// ACME / Let's Encrypt configuration auditor (altais_audit_acme).
//
// Reviews automated certificate issuance: renewal automation, challenge
// type vs. wildcard needs, CAA records, key strength, and account-key
// handling.

import type { Finding } from "../../core/types.js";
import { buildCryptoFinding } from "./finding.js";

export interface AcmeAuditConfig {
  readonly provider?: string;
  readonly challenge_type?: "http-01" | "dns-01" | "tls-alpn-01";
  readonly auto_renewal?: boolean;
  /** Days before expiry that renewal is attempted. */
  readonly renewal_threshold_days?: number;
  readonly wildcard?: boolean;
  /** Whether a CAA DNS record restricts which CAs may issue. */
  readonly caa_configured?: boolean;
  readonly key_type?: "rsa" | "ecdsa";
  readonly key_size_bits?: number;
  /** Whether the ACME endpoint is the CA's staging (untrusted) environment. */
  readonly staging_endpoint?: boolean;
  readonly account_key_storage?: "hsm" | "kms" | "vault" | "file" | "repo";
}

export interface AcmeAuditInput {
  readonly config: AcmeAuditConfig;
  readonly filename?: string;
}

const REFS = [
  "https://datatracker.ietf.org/doc/html/rfc8555",
  "https://letsencrypt.org/docs/",
  "https://datatracker.ietf.org/doc/html/rfc8659",
];

// Let's Encrypt certificates are valid 90 days; the standard renewal point
// is 30 days remaining. Renewing later leaves no slack for failures.
const SAFE_RENEWAL_THRESHOLD_DAYS = 30;

export function auditAcme(input: AcmeAuditInput): readonly Finding[] {
  const findings: Finding[] = [];
  const c = input.config;
  const file = input.filename;

  if (c.auto_renewal !== true) {
    findings.push(
      buildCryptoFinding(
        {
          rule: "acme-no-auto-renewal",
          severity: "high",
          title: "ACME certificate renewal is not automated",
          description:
            "ACME certificates are short-lived (90 days for Let's Encrypt). Manual renewal reliably leads to expiry-driven outages.",
          remediation:
            "Run a renewal client on a timer (certbot systemd timer, cron, or an operator) and alert on failure.",
          cwe: ["CWE-324"],
          references: REFS,
          evidence: `auto_renewal=${c.auto_renewal ?? "unset"}`,
          tags: ["acme"],
        },
        file,
      ),
    );
  }

  if (
    c.renewal_threshold_days !== undefined &&
    c.renewal_threshold_days < SAFE_RENEWAL_THRESHOLD_DAYS
  ) {
    findings.push(
      buildCryptoFinding(
        {
          rule: "acme-renewal-threshold-too-low",
          severity: "medium",
          title: `Renewal attempted only ${c.renewal_threshold_days}d before expiry`,
          description:
            "Renewing close to expiry leaves no room to recover from a failed challenge, a CA outage, or rate limiting before the certificate lapses.",
          remediation: `Renew at least ${SAFE_RENEWAL_THRESHOLD_DAYS} days before expiry (one-third of the certificate lifetime).`,
          cwe: ["CWE-324"],
          references: REFS,
          evidence: `renewal_threshold_days=${c.renewal_threshold_days}`,
          tags: ["acme"],
        },
        file,
      ),
    );
  }

  if (c.wildcard === true && c.challenge_type !== undefined && c.challenge_type !== "dns-01") {
    findings.push(
      buildCryptoFinding(
        {
          rule: "acme-wildcard-requires-dns-01",
          severity: "high",
          title: `Wildcard certificate requested with ${c.challenge_type} challenge`,
          description:
            "ACME issues wildcard certificates only via the dns-01 challenge. http-01 and tls-alpn-01 cannot satisfy a wildcard request.",
          remediation:
            "Use the dns-01 challenge for wildcard certificates, or issue explicit per-host certificates.",
          cwe: ["CWE-295"],
          references: REFS,
          evidence: `wildcard=true, challenge_type=${c.challenge_type}`,
          tags: ["acme"],
        },
        file,
      ),
    );
  }

  if (c.caa_configured !== true) {
    findings.push(
      buildCryptoFinding(
        {
          rule: "acme-no-caa-record",
          severity: "medium",
          title: "No CAA DNS record restricting certificate issuance",
          description:
            "Without a CAA record, any public CA may issue a certificate for the domain, widening the mis-issuance surface.",
          remediation:
            "Publish a CAA record naming only your intended CA(s), and an `iodef` mailto for unauthorized-issuance reports.",
          cwe: ["CWE-295"],
          references: REFS,
          evidence: `caa_configured=${c.caa_configured ?? "unset"}`,
          tags: ["acme"],
        },
        file,
      ),
    );
  }

  if (c.key_type === "rsa" && c.key_size_bits !== undefined && c.key_size_bits < 2048) {
    findings.push(
      buildCryptoFinding(
        {
          rule: "acme-weak-certificate-key",
          severity: "high",
          title: `ACME certificate uses an RSA key below 2048 bits (${c.key_size_bits})`,
          description: "Certificate keys under 2048-bit RSA do not meet NIST minimum strength.",
          remediation: "Issue certificates with ECDSA P-256 or RSA-2048+.",
          cwe: ["CWE-326"],
          references: REFS,
          evidence: `key_type=rsa, key_size_bits=${c.key_size_bits}`,
          tags: ["acme"],
        },
        file,
      ),
    );
  }

  if (c.staging_endpoint === true) {
    findings.push(
      buildCryptoFinding(
        {
          rule: "acme-staging-endpoint",
          severity: "high",
          title: "ACME configured against the CA staging endpoint",
          description:
            "Staging endpoints issue certificates from an untrusted test root. Browsers and clients will reject them. This is only acceptable for testing.",
          remediation: "Point production at the CA's production ACME directory URL.",
          cwe: ["CWE-295"],
          references: REFS,
          evidence: "staging_endpoint=true",
          tags: ["acme"],
        },
        file,
      ),
    );
  }

  if (c.account_key_storage === "repo" || c.account_key_storage === "file") {
    findings.push(
      buildCryptoFinding(
        {
          rule: "acme-account-key-insecure-storage",
          severity: c.account_key_storage === "repo" ? "high" : "medium",
          title: `ACME account key stored in ${c.account_key_storage}`,
          description:
            "The ACME account key authorizes issuance and revocation for every domain on the account. Exposure lets an attacker obtain or revoke certificates.",
          remediation:
            "Store the account key in a KMS / HSM / secrets manager with restricted access; never commit it.",
          cwe: ["CWE-320", "CWE-522"],
          references: REFS,
          evidence: `account_key_storage=${c.account_key_storage}`,
          tags: ["acme"],
        },
        file,
      ),
    );
  }

  return findings;
}
