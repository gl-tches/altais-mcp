// TLS configuration auditor (altais_audit_tls).
//
// Accepts:
// - source: code that configures a TLS client/server — pattern matched for
//   disabled certificate verification and deprecated protocol pinning
// - config: a structured TLS configuration

import type { Finding } from "../../core/types.js";
import { buildCryptoFinding, scanWithPatterns, type SourcePattern } from "./finding.js";

export type TlsVersion = "SSLv2" | "SSLv3" | "TLSv1.0" | "TLSv1.1" | "TLSv1.2" | "TLSv1.3";

export interface TlsAuditConfig {
  readonly min_version?: TlsVersion;
  readonly enabled_versions?: readonly TlsVersion[];
  readonly cipher_suites?: readonly string[];
  readonly verify_certificates?: boolean;
  readonly hsts?: boolean;
  readonly compression?: boolean;
}

export interface TlsAuditInput {
  readonly source?: string;
  readonly config?: TlsAuditConfig;
  readonly filename?: string;
}

const REFS = [
  "https://datatracker.ietf.org/doc/html/rfc8996",
  "https://www.rfc-editor.org/rfc/rfc9325.html",
  "https://wiki.mozilla.org/Security/Server_Side_TLS",
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

const SOURCE_PATTERNS: readonly SourcePattern[] = [
  {
    rule: "tls-verification-disabled",
    regex: /\brejectUnauthorized\s*:\s*false\b/i,
    severity: "critical",
    title: "TLS certificate verification disabled (`rejectUnauthorized: false`)",
    description:
      "Disabling certificate verification accepts any certificate, making the connection trivially man-in-the-middleable.",
    remediation:
      "Remove `rejectUnauthorized: false`. If a private CA is needed, pass it via the `ca` option instead.",
    cwe: ["CWE-295"],
    tags: ["tls", "cert"],
  },
  {
    rule: "tls-verification-disabled",
    regex: /\bverify\s*=\s*False\b|ssl\.CERT_NONE\b/,
    severity: "critical",
    title: "TLS certificate verification disabled (Python `verify=False` / `CERT_NONE`)",
    description:
      "`verify=False` (requests) or `ssl.CERT_NONE` disables certificate validation, exposing the connection to interception.",
    remediation:
      "Leave verification enabled; supply a custom CA bundle via `verify=<path>` if needed.",
    cwe: ["CWE-295"],
    tags: ["tls", "cert"],
  },
  {
    rule: "tls-verification-disabled",
    regex: /\bInsecureSkipVerify\s*:\s*true\b/,
    severity: "critical",
    title: "TLS certificate verification disabled (Go `InsecureSkipVerify: true`)",
    description:
      "`InsecureSkipVerify: true` on `tls.Config` disables certificate and hostname checks.",
    remediation:
      "Set `InsecureSkipVerify: false` (the default). Add a private CA to `RootCAs` if required.",
    cwe: ["CWE-295"],
    tags: ["tls", "cert"],
  },
  {
    rule: "tls-deprecated-protocol-pinned",
    regex:
      /\b(?:SSLv23?_method|TLSv1_method|TLSv1_1_method|PROTOCOL_TLSv1(?:_1)?|PROTOCOL_SSLv\d)\b/,
    severity: "high",
    title: "Deprecated TLS/SSL protocol method pinned",
    description:
      "Pinning an SSLv3 / TLS 1.0 / TLS 1.1 protocol method forces a protocol that RFC 8996 deprecates.",
    remediation:
      "Use the version-flexible method and set a minimum of TLS 1.2 (`minVersion: 'TLSv1.2'` / `PROTOCOL_TLS_CLIENT`).",
    cwe: ["CWE-326", "CWE-327"],
    tags: ["tls"],
  },
];

// Cipher-suite names join tokens with `_` / `-`, so `\b` (which treats `_`
// as a word char) cannot delimit a token. Use explicit non-alphanumeric
// boundaries instead.
const WEAK_CIPHER_RE =
  /(?<![A-Za-z0-9])(?:NULL|EXPORT|anon|ADH|AECDH|RC4|RC2|3DES|DES|MD5|IDEA|SEED|CAMELLIA)(?![A-Za-z0-9])/i;

export function auditTls(input: TlsAuditInput): readonly Finding[] {
  const findings: Finding[] = [];
  if (input.source) {
    findings.push(...scanWithPatterns(input.source, SOURCE_PATTERNS, REFS, input.filename));
  }
  if (input.config) findings.push(...auditConfig(input.config, input.filename));
  return findings;
}

function auditConfig(c: TlsAuditConfig, source: string | undefined): readonly Finding[] {
  const findings: Finding[] = [];

  for (const v of c.enabled_versions ?? []) {
    if (DEPRECATED_VERSIONS.has(v)) {
      findings.push(
        buildCryptoFinding(
          {
            rule: "tls-deprecated-protocol-enabled",
            severity: v === "SSLv2" || v === "SSLv3" ? "critical" : "high",
            title: `Deprecated TLS protocol enabled: ${v}`,
            description: `${v} is deprecated by RFC 8996 and carries known weaknesses (POODLE, BEAST, downgrade attacks).`,
            remediation: "Disable everything below TLS 1.2. Prefer TLS 1.3.",
            cwe: ["CWE-326", "CWE-327"],
            references: REFS,
            evidence: `enabled=${v}`,
            tags: ["tls"],
          },
          source,
        ),
      );
    }
  }

  if (c.min_version !== undefined && VERSION_RANK[c.min_version] < VERSION_RANK["TLSv1.2"]) {
    findings.push(
      buildCryptoFinding(
        {
          rule: "tls-min-version-too-low",
          severity: "high",
          title: `TLS minimum version too low: ${c.min_version}`,
          description:
            "The negotiated floor permits a protocol below TLS 1.2, allowing downgrade to a deprecated version.",
          remediation: "Set the minimum version to TLS 1.2; TLS 1.3 where the client base allows.",
          cwe: ["CWE-326"],
          references: REFS,
          evidence: `min_version=${c.min_version}`,
          tags: ["tls"],
        },
        source,
      ),
    );
  }

  for (const suite of c.cipher_suites ?? []) {
    if (WEAK_CIPHER_RE.test(suite)) {
      findings.push(
        buildCryptoFinding(
          {
            rule: "tls-weak-cipher-suite",
            severity: "high",
            title: `Weak TLS cipher suite: ${suite}`,
            description:
              "The suite uses an anonymous, NULL, export-grade, or broken (RC4/DES/3DES/MD5) primitive.",
            remediation:
              "Restrict to AEAD suites: TLS_AES_256_GCM_SHA384, TLS_CHACHA20_POLY1305_SHA256, ECDHE-RSA-AES256-GCM-SHA384.",
            cwe: ["CWE-327"],
            references: REFS,
            evidence: suite,
            tags: ["tls", "cipher"],
          },
          source,
        ),
      );
    }
  }

  if (c.verify_certificates === false) {
    findings.push(
      buildCryptoFinding(
        {
          rule: "tls-verification-disabled",
          severity: "critical",
          title: "TLS certificate verification is disabled in config",
          description:
            "With certificate verification off, any presented certificate is accepted and the connection can be intercepted.",
          remediation: "Enable certificate verification; pin a private CA bundle if necessary.",
          cwe: ["CWE-295"],
          references: REFS,
          evidence: "verify_certificates=false",
          tags: ["tls", "cert"],
        },
        source,
      ),
    );
  }

  if (c.compression === true) {
    findings.push(
      buildCryptoFinding(
        {
          rule: "tls-compression-enabled",
          severity: "medium",
          title: "TLS compression enabled",
          description: "TLS-level compression enables the CRIME attack against secret data.",
          remediation: "Disable TLS compression.",
          cwe: ["CWE-310"],
          references: REFS,
          evidence: "compression=true",
          tags: ["tls"],
        },
        source,
      ),
    );
  }

  if (c.hsts === false) {
    findings.push(
      buildCryptoFinding(
        {
          rule: "tls-no-hsts",
          severity: "medium",
          title: "HSTS not enabled",
          description:
            "Without HTTP Strict Transport Security, a first request or a stripped link can be downgraded to plaintext HTTP.",
          remediation:
            "Send `Strict-Transport-Security: max-age=31536000; includeSubDomains` and consider preloading.",
          cwe: ["CWE-319"],
          references: REFS,
          evidence: "hsts=false",
          tags: ["tls"],
        },
        source,
      ),
    );
  }

  return findings;
}
