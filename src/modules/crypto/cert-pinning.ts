// Certificate pinning auditor (altais_audit_cert_pinning).
//
// Reviews pinning configuration. HPKP (the `Public-Key-Pins` HTTP header)
// is dead — modern pinning lives in the client/app (Android Network
// Security Config, iOS, mobile SDKs). Bad pinning bricks deployments, so
// the checks weigh both "no pinning" and "fragile pinning".

import type { Finding } from "../../core/types.js";
import { buildCryptoFinding, scanWithPatterns, type SourcePattern } from "./finding.js";

export interface CertPinningConfig {
  readonly pinning_enabled?: boolean;
  /** What is pinned: the leaf cert, a public key (SPKI), or a CA. */
  readonly pin_type?: "leaf_certificate" | "public_key" | "ca_certificate";
  /** Number of pins configured. */
  readonly pin_count?: number;
  /** Whether a backup pin (not yet deployed) is included. */
  readonly has_backup_pin?: boolean;
  /** Whether pinning failures hard-fail the connection. */
  readonly enforced?: boolean;
  /** Platform the pinning applies to. */
  readonly platform?: "android" | "ios" | "web" | "backend";
}

export interface CertPinningInput {
  readonly source?: string;
  readonly config?: CertPinningConfig;
  readonly filename?: string;
}

const REFS = [
  "https://owasp.org/www-community/controls/Certificate_and_Public_Key_Pinning",
  "https://developer.android.com/privacy-and-security/security-config",
  "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Public-Key-Pins",
];

const SOURCE_PATTERNS: readonly SourcePattern[] = [
  {
    rule: "cert-pinning-hpkp-header",
    regex: /\bPublic-Key-Pins(?:-Report-Only)?\b/,
    severity: "medium",
    title: "Deprecated HPKP `Public-Key-Pins` header in use",
    description:
      "HTTP Public Key Pinning was removed from browsers because mis-pinning could permanently break a site (hostile pinning / accidental brick). The header is ignored by modern browsers.",
    remediation:
      "Drop the HPKP header. For native apps, pin in the platform layer (Android Network Security Config, iOS pinning, or the HTTP client). For web, rely on CAA + CT monitoring.",
    cwe: ["CWE-1104"],
    tags: ["cert-pinning"],
  },
];

export function auditCertPinning(input: CertPinningInput): readonly Finding[] {
  const findings: Finding[] = [];
  if (input.source) {
    findings.push(...scanWithPatterns(input.source, SOURCE_PATTERNS, REFS, input.filename));
  }
  if (input.config) findings.push(...auditConfig(input.config, input.filename));
  return findings;
}

function auditConfig(c: CertPinningConfig, source: string | undefined): readonly Finding[] {
  const findings: Finding[] = [];

  if (c.pinning_enabled === false) {
    findings.push(
      buildCryptoFinding(
        {
          rule: "cert-pinning-absent",
          severity: c.platform === "android" || c.platform === "ios" ? "medium" : "info",
          title: "Certificate pinning is not enabled",
          description:
            "Without pinning, a connection trusts any certificate from any CA in the system trust store, so a mis-issued or rogue-CA certificate is accepted. For high-assurance mobile apps this widens the MITM surface.",
          remediation:
            "For native apps handling sensitive data, pin the server's SPKI (with a backup pin). For web, pinning is no longer practical — rely on CAA + CT monitoring instead.",
          cwe: ["CWE-295"],
          references: REFS,
          evidence: `pinning_enabled=false${c.platform ? `, platform=${c.platform}` : ""}`,
          tags: ["cert-pinning"],
        },
        source,
      ),
    );
    return findings;
  }

  if (c.pinning_enabled === true) {
    if (c.pin_type === "leaf_certificate") {
      findings.push(
        buildCryptoFinding(
          {
            rule: "cert-pinning-leaf-certificate",
            severity: "medium",
            title: "Pinning the leaf certificate rather than the public key",
            description:
              "A leaf certificate changes on every renewal, so leaf-cert pinning forces an app update on each rotation and risks bricking clients that miss it.",
            remediation:
              "Pin the Subject Public Key Info (SPKI) hash. The key survives certificate renewal as long as the CSR reuses the key pair.",
            cwe: ["CWE-1188"],
            references: REFS,
            evidence: "pin_type=leaf_certificate",
            tags: ["cert-pinning"],
          },
          source,
        ),
      );
    }

    if (c.has_backup_pin === false || (c.pin_count !== undefined && c.pin_count < 2)) {
      findings.push(
        buildCryptoFinding(
          {
            rule: "cert-pinning-no-backup-pin",
            severity: "high",
            title: "Certificate pinning configured without a backup pin",
            description:
              "If the single pinned key is lost or must be rotated for compromise, every client is permanently unable to connect until they receive an update.",
            remediation:
              "Always include at least one backup pin for a key held offline. Rotate to the backup, then issue a new backup.",
            cwe: ["CWE-1188"],
            references: REFS,
            evidence: `has_backup_pin=${c.has_backup_pin ?? "unset"}, pin_count=${c.pin_count ?? "unset"}`,
            tags: ["cert-pinning"],
          },
          source,
        ),
      );
    }

    if (c.enforced === false) {
      findings.push(
        buildCryptoFinding(
          {
            rule: "cert-pinning-not-enforced",
            severity: "low",
            title: "Certificate pinning is in report-only / non-enforcing mode",
            description:
              "Report-only pinning detects mismatches but still completes the connection, so it does not stop a MITM. It is a valid rollout stage, not a final state.",
            remediation:
              "Once pin stability is confirmed in report-only mode, switch to hard-fail enforcement.",
            cwe: ["CWE-295"],
            references: REFS,
            evidence: "enforced=false",
            tags: ["cert-pinning"],
          },
          source,
        ),
      );
    }
  }

  return findings;
}
