// Certificate Transparency monitoring auditor (altais_audit_ct_logs).
//
// Reviews whether a deployment watches CT logs for mis-issued certificates
// covering its domains, and flags reliance on the deprecated Expect-CT
// header.

import type { Finding } from "../../core/types.js";
import { buildCryptoFinding, lineAt } from "./finding.js";

export interface CtLogsConfig {
  /** Whether CT log monitoring is in place for the org's domains. */
  readonly monitoring_enabled?: boolean;
  /** Domains (incl. wildcards) the org owns and expects to monitor. */
  readonly owned_domains?: readonly string[];
  /** Domains actually covered by the CT monitor. */
  readonly monitored_domains?: readonly string[];
  /** Whether mis-issuance alerts are routed to a responder. */
  readonly alerting_enabled?: boolean;
  /** Whether the TLS server requires SCTs (stapled or embedded). */
  readonly requires_sct?: boolean;
}

export interface CtLogsInput {
  readonly source?: string;
  readonly config?: CtLogsConfig;
  readonly filename?: string;
}

const REFS = [
  "https://datatracker.ietf.org/doc/html/rfc6962",
  "https://certificate.transparency.dev/",
  "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Expect-CT",
];

const EXPECT_CT_RE = /\bExpect-CT\b/g;

export function auditCtLogs(input: CtLogsInput): readonly Finding[] {
  const findings: Finding[] = [];

  if (input.source) {
    const src = input.source;
    let m: RegExpExecArray | null;
    const re = new RegExp(EXPECT_CT_RE.source, "g");
    while ((m = re.exec(src)) !== null) {
      findings.push(
        buildCryptoFinding(
          {
            rule: "ct-expect-ct-header-deprecated",
            severity: "low",
            title: "Deprecated `Expect-CT` header in use",
            description:
              "CT enforcement is now mandatory in major browsers, so the `Expect-CT` header is obsolete and ignored. Relying on it gives a false sense of coverage.",
            remediation:
              "Remove the `Expect-CT` header and instead monitor CT logs server-side for certificates covering your domains.",
            cwe: ["CWE-1104"],
            references: REFS,
            evidence: m[0],
            tags: ["ct"],
            line: lineAt(src, m.index),
          },
          input.filename,
        ),
      );
    }
  }

  if (input.config) {
    const c = input.config;

    if (c.monitoring_enabled !== true) {
      findings.push(
        buildCryptoFinding(
          {
            rule: "ct-no-monitoring",
            severity: "medium",
            title: "Certificate Transparency log monitoring is not enabled",
            description:
              "Without CT monitoring, a certificate mis-issued for your domain (by a compromised or coerced CA) can go unnoticed until it is abused.",
            remediation:
              "Subscribe to a CT monitor (crt.sh, Cert Spotter, or a commercial service) for every domain you own and route findings to security.",
            cwe: ["CWE-295"],
            references: REFS,
            evidence: "monitoring_enabled=false",
            tags: ["ct"],
          },
          input.filename,
        ),
      );
    } else {
      const monitored = new Set((c.monitored_domains ?? []).map((d) => d.toLowerCase()));
      const uncovered = (c.owned_domains ?? []).filter((d) => !monitored.has(d.toLowerCase()));
      if (uncovered.length > 0) {
        findings.push(
          buildCryptoFinding(
            {
              rule: "ct-domain-coverage-gap",
              severity: "medium",
              title: `CT monitoring does not cover ${uncovered.length} owned domain(s)`,
              description:
                "Domains you own that are absent from the CT monitor have no detection for mis-issued certificates.",
              remediation: "Add every owned domain (and apex + wildcard) to the CT monitor.",
              cwe: ["CWE-295"],
              references: REFS,
              evidence: `uncovered=${uncovered.slice(0, 10).join(", ")}`,
              tags: ["ct"],
            },
            input.filename,
          ),
        );
      }

      if (c.alerting_enabled !== true) {
        findings.push(
          buildCryptoFinding(
            {
              rule: "ct-no-alerting",
              severity: "medium",
              title: "CT monitoring has no alerting",
              description:
                "Monitoring without alerting only catches mis-issuance if someone happens to review the log — defeating the point of timely detection.",
              remediation:
                "Route CT monitor findings to an on-call channel or ticketing system with a defined response runbook.",
              cwe: ["CWE-778"],
              references: REFS,
              evidence: "alerting_enabled=false",
              tags: ["ct"],
            },
            input.filename,
          ),
        );
      }
    }

    if (c.requires_sct === false) {
      findings.push(
        buildCryptoFinding(
          {
            rule: "ct-sct-not-required",
            severity: "low",
            title: "TLS server does not deliver Signed Certificate Timestamps",
            description:
              "Without embedded or stapled SCTs, CT-enforcing clients may reject the certificate, and there is no on-wire proof the certificate was logged.",
            remediation:
              "Use a CA that embeds SCTs in issued certificates, or staple SCTs via the TLS extension.",
            cwe: ["CWE-295"],
            references: REFS,
            evidence: "requires_sct=false",
            tags: ["ct"],
          },
          input.filename,
        ),
      );
    }
  }

  return findings;
}
