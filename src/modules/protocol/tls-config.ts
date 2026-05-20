// Deep TLS / mTLS configuration auditor (altais_audit_tls_config).
//
// Takes a structured TLS configuration and assesses it against RFC 9325
// (TLS recommendations) and RFC 8996 (deprecating TLS 1.0/1.1). This goes
// beyond the crypto module's `altais_audit_tls`: it inspects mutual-TLS
// posture, OCSP stapling, session resumption hygiene, forward secrecy,
// certificate signature algorithms, and certificate transparency.

import type { Finding } from "../../core/types.js";
import { buildProtocolFinding } from "./finding.js";

export type TlsVersion = "SSLv2" | "SSLv3" | "TLSv1.0" | "TLSv1.1" | "TLSv1.2" | "TLSv1.3";

export interface TlsConfigAuditConfig {
  readonly min_version?: TlsVersion;
  readonly enabled_versions?: readonly TlsVersion[];
  readonly cipher_suites?: readonly string[];
  readonly mtls_enabled?: boolean;
  readonly client_cert_required?: boolean;
  readonly ocsp_stapling?: boolean;
  readonly session_resumption?: "none" | "session_id" | "session_ticket" | "tls13_psk";
  readonly forward_secrecy?: boolean;
  readonly cert_signature_algorithm?: string;
  readonly hsts?: boolean;
  readonly certificate_transparency?: boolean;
}

export interface TlsConfigAuditInput {
  readonly config: TlsConfigAuditConfig;
  readonly filename?: string;
}

const REFS = [
  "https://datatracker.ietf.org/doc/html/rfc8996",
  "https://datatracker.ietf.org/doc/html/rfc9325",
  "https://cwe.mitre.org/data/definitions/326.html",
];

const VERSION_RANK: Readonly<Record<TlsVersion, number>> = {
  SSLv2: 0,
  SSLv3: 1,
  "TLSv1.0": 2,
  "TLSv1.1": 3,
  "TLSv1.2": 4,
  "TLSv1.3": 5,
};

const DEPRECATED_VERSIONS: ReadonlySet<TlsVersion> = new Set([
  "SSLv2",
  "SSLv3",
  "TLSv1.0",
  "TLSv1.1",
]);

// Cipher-suite names join tokens with `_` / `-`, so `\b` (which treats `_`
// as a word char) cannot delimit a token. Use explicit non-alphanumeric
// boundaries instead.
const WEAK_CIPHER_RE =
  /(?<![A-Za-z0-9])(?:NULL|EXPORT|anon|ADH|AECDH|RC4|RC2|3DES|DES|MD5|IDEA|SEED)(?![A-Za-z0-9])/i;

// AEAD modes — the only cipher modes RFC 9325 recommends.
const AEAD_CIPHER_RE = /(?<![A-Za-z0-9])(?:GCM|CCM|POLY1305|CHACHA20)(?![A-Za-z0-9])/i;

// Suites whose key exchange provides forward secrecy.
const FORWARD_SECRECY_KX_RE = /(?<![A-Za-z0-9])(?:ECDHE|DHE|TLS_AES|TLS_CHACHA)(?![A-Za-z0-9])/i;

// Static-RSA / static-DH key exchange — no forward secrecy.
const NON_FS_KX_RE = /(?<![A-Za-z0-9])(?:TLS_RSA_WITH|AES\d+-(?:SHA|GCM))(?![A-Za-z0-9])/i;

const WEAK_SIG_RE = /(?:^|[^A-Za-z0-9])(?:sha-?1|md5|md2|md4)(?![0-9])/i;

function mk(
  filename: string | undefined,
  rule: string,
  severity: Finding["severity"],
  title: string,
  description: string,
  remediation: string,
  cwe: readonly string[],
  evidence: string,
  tags: readonly string[],
): Finding {
  return buildProtocolFinding(
    {
      rule,
      severity,
      title,
      description,
      remediation,
      cwe,
      references: REFS,
      evidence,
      tags: ["tls", ...tags],
    },
    filename,
  );
}

export function auditTlsConfig(input: TlsConfigAuditInput): readonly Finding[] {
  const c = input.config;
  const file = input.filename;
  const findings: Finding[] = [];

  // ── Deprecated protocol versions ──────────────────────────────────────
  for (const v of c.enabled_versions ?? []) {
    if (DEPRECATED_VERSIONS.has(v)) {
      findings.push(
        mk(
          file,
          "tls-deprecated-protocol-enabled",
          v === "SSLv2" || v === "SSLv3" ? "critical" : "high",
          `Deprecated TLS protocol enabled: ${v}`,
          `${v} is deprecated by RFC 8996 and carries known weaknesses (POODLE, BEAST, downgrade attacks). Leaving it enabled lets an attacker negotiate it down.`,
          "Disable every protocol below TLS 1.2 and prefer TLS 1.3.",
          ["CWE-326", "CWE-327"],
          `enabled_version=${v}`,
          ["version"],
        ),
      );
    }
  }

  // ── Minimum version floor ─────────────────────────────────────────────
  if (c.min_version !== undefined && VERSION_RANK[c.min_version] < VERSION_RANK["TLSv1.2"]) {
    findings.push(
      mk(
        file,
        "tls-min-version-too-low",
        "high",
        `TLS minimum version too low: ${c.min_version}`,
        "The negotiated floor permits a protocol below TLS 1.2, allowing a downgrade to a deprecated version.",
        "Set the minimum version to TLS 1.2; raise to TLS 1.3 where the client base allows.",
        ["CWE-326"],
        `min_version=${c.min_version}`,
        ["version"],
      ),
    );
  }

  // ── TLS 1.3 not offered ───────────────────────────────────────────────
  const enabled = c.enabled_versions ?? [];
  if (enabled.length > 0 && !enabled.includes("TLSv1.3")) {
    findings.push(
      mk(
        file,
        "tls-no-tls13",
        "medium",
        "TLS 1.3 is not enabled",
        "TLS 1.3 removes legacy ciphers, mandates forward secrecy, encrypts more of the handshake, and resists downgrade attacks. Omitting it leaves only the weaker TLS 1.2 negotiation path.",
        "Enable TLS 1.3 alongside TLS 1.2 so modern clients negotiate the stronger protocol.",
        ["CWE-326"],
        `enabled_versions=[${enabled.join(",")}]`,
        ["version"],
      ),
    );
  }

  // ── Cipher suites ─────────────────────────────────────────────────────
  for (const suite of c.cipher_suites ?? []) {
    if (WEAK_CIPHER_RE.test(suite)) {
      findings.push(
        mk(
          file,
          "tls-weak-cipher-suite",
          "high",
          `Weak TLS cipher suite: ${suite}`,
          "The suite uses an anonymous, NULL, export-grade, or broken (RC4/DES/3DES/MD5) primitive that does not provide meaningful confidentiality or integrity.",
          "Restrict to AEAD suites: TLS_AES_256_GCM_SHA384, TLS_CHACHA20_POLY1305_SHA256, ECDHE-ECDSA-AES256-GCM-SHA384.",
          ["CWE-327"],
          suite,
          ["cipher"],
        ),
      );
    } else if (!AEAD_CIPHER_RE.test(suite)) {
      findings.push(
        mk(
          file,
          "tls-non-aead-cipher-suite",
          "medium",
          `Non-AEAD TLS cipher suite: ${suite}`,
          "RFC 9325 recommends only AEAD cipher modes (GCM, CCM, ChaCha20-Poly1305). CBC-mode suites are vulnerable to padding-oracle and Lucky-13 style attacks.",
          "Replace the suite with an AEAD equivalent such as an `-GCM-` or `CHACHA20-POLY1305` suite.",
          ["CWE-327"],
          suite,
          ["cipher"],
        ),
      );
    }
  }

  // ── Forward secrecy ───────────────────────────────────────────────────
  const suiteList = c.cipher_suites ?? [];
  const anyNonFsSuite = suiteList.some(
    (s) => NON_FS_KX_RE.test(s) && !FORWARD_SECRECY_KX_RE.test(s),
  );
  if (c.forward_secrecy === false || anyNonFsSuite) {
    findings.push(
      mk(
        file,
        "tls-no-forward-secrecy",
        "high",
        "TLS configuration does not guarantee forward secrecy",
        "Without an ephemeral (EC)DHE key exchange, a single compromise of the server's long-term private key decrypts every past recorded session. Static-RSA key transport has no forward secrecy.",
        "Restrict key exchange to ECDHE/DHE suites (TLS 1.3 enforces this), and remove static-RSA suites such as `TLS_RSA_WITH_*`.",
        ["CWE-326"],
        c.forward_secrecy === false
          ? "forward_secrecy=false"
          : "static key exchange in cipher_suites",
        ["cipher"],
      ),
    );
  }

  // ── OCSP stapling ─────────────────────────────────────────────────────
  if (c.ocsp_stapling === false) {
    findings.push(
      mk(
        file,
        "tls-no-ocsp-stapling",
        "medium",
        "OCSP stapling is disabled",
        "Without OCSP stapling, clients either skip revocation checking (fail-open) or contact the CA directly, leaking the visited host and slowing the handshake. A revoked certificate can keep being accepted.",
        "Enable OCSP stapling so the server attaches a fresh, signed revocation status to the handshake; consider OCSP Must-Staple on the certificate.",
        ["CWE-299"],
        "ocsp_stapling=false",
        ["revocation"],
      ),
    );
  }

  // ── Session resumption hygiene ────────────────────────────────────────
  if (c.session_resumption === "session_ticket") {
    findings.push(
      mk(
        file,
        "tls-insecure-session-resumption",
        "medium",
        "TLS session tickets in use without documented key rotation",
        "Session tickets encrypt the full session state under a server-held key (STEK). If the ticket key is long-lived or never rotated, a later key compromise breaks forward secrecy for every resumed session.",
        "Rotate session-ticket keys frequently (hourly to daily), keep them in memory only, or disable stateless tickets in favour of TLS 1.3 PSK with fresh keys.",
        ["CWE-326"],
        "session_resumption=session_ticket",
        ["resumption"],
      ),
    );
  }

  // ── Certificate signature algorithm ───────────────────────────────────
  if (c.cert_signature_algorithm !== undefined && WEAK_SIG_RE.test(c.cert_signature_algorithm)) {
    findings.push(
      mk(
        file,
        "tls-weak-cert-signature-algorithm",
        "high",
        `Certificate signed with a weak algorithm: ${c.cert_signature_algorithm}`,
        "SHA-1, MD5, MD4, and MD2 are collision-broken. An attacker who can mount a chosen-prefix collision can forge a certificate that chains to a trusted CA.",
        "Reissue the certificate with a SHA-256 (or stronger) signature; modern public CAs already require this.",
        ["CWE-327", "CWE-295"],
        `cert_signature_algorithm=${c.cert_signature_algorithm}`,
        ["cert"],
      ),
    );
  }

  // ── mTLS posture ──────────────────────────────────────────────────────
  if (c.mtls_enabled === true && c.client_cert_required !== true) {
    findings.push(
      mk(
        file,
        "tls-mtls-client-cert-optional",
        "high",
        "Mutual TLS is enabled but the client certificate is not required",
        "With mTLS configured but `client_cert_required` off, the server requests a client certificate but still completes the handshake when none is presented. The intended client-authentication control is effectively optional and trivially bypassed.",
        "Set the verification mode to require-and-verify (e.g. `requestCert: true, rejectUnauthorized: true`, Nginx `ssl_verify_client on`) so a missing or invalid client certificate aborts the handshake.",
        ["CWE-295", "CWE-306"],
        "mtls_enabled=true, client_cert_required=false",
        ["mtls"],
      ),
    );
  }

  // ── HSTS ──────────────────────────────────────────────────────────────
  if (c.hsts === false) {
    findings.push(
      mk(
        file,
        "tls-no-hsts",
        "medium",
        "HSTS is not enabled",
        "Without HTTP Strict Transport Security, a first request or a stripped link can be downgraded to plaintext HTTP and intercepted (SSL stripping).",
        "Send `Strict-Transport-Security: max-age=31536000; includeSubDomains` and consider preloading.",
        ["CWE-319"],
        "hsts=false",
        ["downgrade"],
      ),
    );
  }

  // ── Certificate transparency ──────────────────────────────────────────
  if (c.certificate_transparency === false) {
    findings.push(
      mk(
        file,
        "tls-no-certificate-transparency",
        "low",
        "Certificate Transparency is not enforced",
        "Without CT enforcement (Expect-CT / SCT verification), a mis-issued certificate for the domain can go undetected by the operator and may still be accepted by older clients.",
        "Serve SCTs with the certificate and monitor CT logs (e.g. crt.sh, certspotter) for unexpected issuance.",
        ["CWE-295"],
        "certificate_transparency=false",
        ["cert"],
      ),
    );
  }

  return findings;
}
