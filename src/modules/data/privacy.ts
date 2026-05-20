// Privacy-by-design auditor (altais_audit_privacy).
//
// Checks an implementation's privacy configuration against the
// GDPR-aligned privacy-by-design principles. Each principle that is
// switched off or omitted produces a Finding; enabling third-party data
// sharing is itself flagged as a risk to review.

import type { Finding, Severity } from "../../core/types.js";
import { buildDataFinding } from "./finding.js";

export interface PrivacyConfig {
  readonly data_minimization?: boolean;
  readonly purpose_limitation?: boolean;
  readonly consent_mechanism?: boolean;
  readonly encryption_at_rest?: boolean;
  readonly encryption_in_transit?: boolean;
  readonly default_private?: boolean;
  readonly dpo_designated?: boolean;
  readonly dpia_conducted?: boolean;
  readonly user_data_export?: boolean;
  readonly user_data_deletion?: boolean;
  readonly breach_notification_process?: boolean;
  readonly third_party_data_sharing?: boolean;
}

export interface AuditPrivacyInput {
  readonly config: PrivacyConfig;
}

const REFS = [
  "https://gdpr.eu/article-25-data-protection-by-design/",
  "https://owasp.org/www-project-top-ten/2021/A04_2021-Insecure_Design",
  "https://cwe.mitre.org/data/definitions/359.html",
  "https://www.nist.gov/privacy-framework",
];

type PrincipleKey = Exclude<keyof PrivacyConfig, "third_party_data_sharing">;

interface PrincipleRule {
  readonly key: PrincipleKey;
  readonly rule: string;
  readonly severity: Severity;
  readonly title: string;
  readonly description: string;
  readonly remediation: string;
  readonly cwe: readonly string[];
}

const PRINCIPLES: readonly PrincipleRule[] = [
  {
    key: "data_minimization",
    rule: "privacy-no-data-minimization",
    severity: "medium",
    title: "Data minimization is not enforced",
    description:
      "GDPR Article 5(1)(c) requires collecting only the personal data that is adequate, relevant, and limited to what is necessary. Collecting more than needed enlarges breach impact and regulatory exposure.",
    remediation:
      "Inventory every collected field, drop the fields no business purpose justifies, and add collection-time validation so excess data is never stored.",
    cwe: ["CWE-359"],
  },
  {
    key: "purpose_limitation",
    rule: "privacy-no-purpose-limitation",
    severity: "medium",
    title: "Purpose limitation is not enforced",
    description:
      "GDPR Article 5(1)(b) requires personal data to be collected for specified, explicit, and legitimate purposes and not further processed in an incompatible way. Reusing data for unrelated purposes is unlawful.",
    remediation:
      "Document the declared purpose for each data category and enforce it in code so data collected for one purpose cannot be silently repurposed.",
    cwe: ["CWE-359"],
  },
  {
    key: "consent_mechanism",
    rule: "privacy-no-consent-mechanism",
    severity: "medium",
    title: "No consent mechanism is implemented",
    description:
      "Where consent is the legal basis for processing, GDPR Article 7 requires it to be freely given, specific, informed, recorded, and as easy to withdraw as to give. Without a consent mechanism the processing may be unlawful.",
    remediation:
      "Implement granular opt-in consent capture, store consent records with timestamp and scope, and provide an equally simple withdrawal path.",
    cwe: ["CWE-359"],
  },
  {
    key: "encryption_at_rest",
    rule: "privacy-no-encryption-at-rest",
    severity: "high",
    title: "Personal data is not encrypted at rest",
    description:
      "Storing personal data in cleartext means a stolen disk, backup, or compromised database directly exposes every record. Encryption at rest is a baseline expectation under GDPR Article 32.",
    remediation:
      "Enable storage- or field-level encryption for all personal data, manage keys in a dedicated KMS, and rotate keys on a defined schedule.",
    cwe: ["CWE-312"],
  },
  {
    key: "encryption_in_transit",
    rule: "privacy-no-encryption-in-transit",
    severity: "high",
    title: "Personal data is not encrypted in transit",
    description:
      "Transmitting personal data over unencrypted channels lets a network attacker intercept or tamper with it. TLS for all data in transit is required by GDPR Article 32.",
    remediation:
      "Enforce TLS 1.2+ on every connection that carries personal data, disable plaintext fallbacks, and use HSTS for browser-facing endpoints.",
    cwe: ["CWE-319"],
  },
  {
    key: "default_private",
    rule: "privacy-not-private-by-default",
    severity: "medium",
    title: "The implementation is not private by default",
    description:
      "GDPR Article 25 requires data-protection by default: the most privacy-friendly settings must apply without the user having to act. Defaulting to public or broadly shared exposes data the user never chose to share.",
    remediation:
      "Make the most restrictive setting the default for every privacy-relevant option, and require an explicit user action to widen visibility or sharing.",
    cwe: ["CWE-1188", "CWE-359"],
  },
  {
    key: "dpo_designated",
    rule: "privacy-no-dpo-designated",
    severity: "low",
    title: "No Data Protection Officer is designated",
    description:
      "GDPR Article 37 requires a Data Protection Officer where processing is large-scale or involves special-category data. Without one there is no accountable owner for privacy compliance.",
    remediation:
      "Assess whether a DPO is mandatory for the processing performed; if so, designate one and publish their contact details.",
    cwe: ["CWE-359"],
  },
  {
    key: "dpia_conducted",
    rule: "privacy-no-dpia-conducted",
    severity: "medium",
    title: "No Data Protection Impact Assessment was conducted",
    description:
      "GDPR Article 35 requires a DPIA for processing likely to result in a high risk to individuals. Skipping it means privacy risks are unassessed and unmitigated.",
    remediation:
      "Conduct a DPIA covering the data flows, risks to data subjects, and mitigations, and revisit it whenever processing materially changes.",
    cwe: ["CWE-359"],
  },
  {
    key: "user_data_export",
    rule: "privacy-no-user-data-export",
    severity: "medium",
    title: "Users cannot export their data (right to access / portability)",
    description:
      "GDPR Articles 15 and 20 give individuals the right to access their personal data and receive it in a portable, machine-readable format. Without an export path the implementation cannot honor those requests.",
    remediation:
      "Provide a self-service or operator-assisted export that returns the data subject's full record in a structured, machine-readable format.",
    cwe: ["CWE-359"],
  },
  {
    key: "user_data_deletion",
    rule: "privacy-no-user-data-deletion",
    severity: "high",
    title: "Users cannot delete their data (right to erasure)",
    description:
      "GDPR Article 17 gives individuals the right to erasure of their personal data. Without a deletion path the implementation retains data it has no lawful basis to keep and cannot honor erasure requests.",
    remediation:
      "Implement an erasure workflow that hard-deletes or irreversibly anonymizes the data subject's records, including backups and downstream copies, within the statutory window.",
    cwe: ["CWE-359"],
  },
  {
    key: "breach_notification_process",
    rule: "privacy-no-breach-notification-process",
    severity: "medium",
    title: "No data-breach notification process is defined",
    description:
      "GDPR Articles 33 and 34 require notifying the supervisory authority within 72 hours of becoming aware of a breach, and affected individuals where the risk is high. Without a defined process those deadlines will be missed.",
    remediation:
      "Define and rehearse a breach-response runbook covering detection, assessment, 72-hour authority notification, and data-subject communication.",
    cwe: ["CWE-359"],
  },
];

export function auditPrivacy(input: AuditPrivacyInput): readonly Finding[] {
  const config = input.config;
  const findings: Finding[] = [];

  for (const principle of PRINCIPLES) {
    const value = config[principle.key];
    if (value === true) continue;
    findings.push(
      buildDataFinding(
        {
          rule: principle.rule,
          severity: principle.severity,
          title: principle.title,
          description: principle.description,
          remediation: principle.remediation,
          cwe: principle.cwe,
          references: REFS,
          evidence: value === false ? `${principle.key}: false` : `${principle.key}: not declared`,
          tags: ["privacy", "gdpr", "privacy-by-design"],
        },
        undefined,
      ),
    );
  }

  if (config.third_party_data_sharing === true) {
    findings.push(
      buildDataFinding(
        {
          rule: "privacy-third-party-data-sharing",
          severity: "medium",
          title: "Personal data is shared with third parties",
          description:
            "Sharing personal data with third parties extends the processing chain beyond the controller's direct control. Each recipient must have a lawful basis, a data-processing agreement, and adequate safeguards — and the data subject must be informed.",
          remediation:
            "Document every third-party recipient and the data shared, sign GDPR Article 28 data-processing agreements, verify cross-border transfer safeguards, and disclose the sharing in the privacy notice.",
          cwe: ["CWE-200", "CWE-359"],
          references: REFS,
          evidence: "third_party_data_sharing: true",
          tags: ["privacy", "gdpr", "third-party"],
        },
        undefined,
      ),
    );
  }

  return findings;
}
