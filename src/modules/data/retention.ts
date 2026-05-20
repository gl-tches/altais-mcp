// Data retention auditor (altais_check_retention).
//
// Reviews declared retention policies against the GDPR storage-
// limitation principle: every data category must have a bounded
// retention period, an actual deletion mechanism, and — for personal
// data — a documented legal basis and an irreversible erasure method.
// Optionally regex-scans source for hardcoded indefinite retention.

import type { Finding, Severity } from "../../core/types.js";
import { buildDataFinding, lineAt } from "./finding.js";

export type DeletionMethod = "hard_delete" | "soft_delete" | "anonymize" | "none";

export interface RetentionPolicy {
  readonly data_category: string;
  readonly retention_period_days?: number;
  readonly deletion_method?: DeletionMethod;
  readonly automated_deletion?: boolean;
  readonly legal_basis?: string;
  readonly contains_pii?: boolean;
}

export interface CheckRetentionInput {
  readonly policies: readonly RetentionPolicy[];
  readonly source?: string;
  readonly filename?: string;
}

const REFS = [
  "https://gdpr.eu/article-5-how-to-process-personal-data/",
  "https://owasp.org/www-project-top-ten/2021/A04_2021-Insecure_Design",
  "https://cwe.mitre.org/data/definitions/359.html",
  "https://www.nist.gov/privacy-framework",
];

/** Retention beyond this many days is treated as excessive without justification. */
const MAX_REASONABLE_RETENTION_DAYS = 3650;

interface SourcePattern {
  readonly rule: string;
  readonly regex: RegExp;
  readonly severity: Severity;
  readonly title: string;
  readonly description: string;
  readonly remediation: string;
}

const SOURCE_PATTERNS: readonly SourcePattern[] = [
  {
    rule: "retention-source-indefinite",
    regex:
      /\b(?:retention|retain|expire[sd]?|ttl|expiry)\b[^\n]{0,40}?(?:[:=]\s*)?(?:indefinite(?:ly)?|forever|never|permanent(?:ly)?|unlimited|-1|null|none)\b/gi,
    severity: "high",
    title: "Hardcoded indefinite data retention in source",
    description:
      "The source declares a retention or expiry setting as indefinite, forever, never, or unlimited. Keeping personal data with no time bound violates the GDPR Article 5(1)(e) storage-limitation principle and steadily grows breach exposure.",
    remediation:
      "Replace the indefinite value with a finite retention period justified by a documented business or legal need, and pair it with automated deletion.",
  },
];

function mk(
  rule: string,
  severity: Severity,
  title: string,
  description: string,
  remediation: string,
  cwe: readonly string[],
  evidence: string,
  filename: string | undefined,
  line: number | undefined,
): Finding {
  return buildDataFinding(
    {
      rule,
      severity,
      title,
      description,
      remediation,
      cwe,
      references: REFS,
      evidence,
      tags: ["retention", "privacy", "gdpr"],
      ...(line !== undefined ? { line } : {}),
    },
    filename,
  );
}

export function checkRetention(input: CheckRetentionInput): readonly Finding[] {
  const findings: Finding[] = [];

  for (const policy of input.policies) {
    const category = policy.data_category;
    const isPii = policy.contains_pii === true;

    // ── Missing or undefined retention period ───────────────────────────
    if (policy.retention_period_days === undefined) {
      findings.push(
        mk(
          "retention-missing-period",
          isPii ? "high" : "medium",
          `No retention period defined for \`${category}\``,
          `The data category \`${category}\` has no \`retention_period_days\`, so the data is kept with no time bound. GDPR Article 5(1)(e) requires personal data to be kept no longer than necessary.`,
          `Set an explicit, justified \`retention_period_days\` for \`${category}\` and enforce it with automated deletion.`,
          ["CWE-359"],
          `data_category: ${category}; retention_period_days: undefined`,
          undefined,
          undefined,
        ),
      );
    } else if (
      policy.retention_period_days <= 0 ||
      policy.retention_period_days > MAX_REASONABLE_RETENTION_DAYS
    ) {
      // ── Indefinite or excessively long retention ──────────────────────
      const indefinite = policy.retention_period_days <= 0;
      findings.push(
        mk(
          indefinite ? "retention-indefinite" : "retention-excessive",
          isPii ? "high" : "medium",
          indefinite
            ? `Indefinite retention configured for \`${category}\``
            : `Excessively long retention for \`${category}\` (${String(policy.retention_period_days)} days)`,
          indefinite
            ? `The data category \`${category}\` is configured with a non-positive retention period, meaning the data is effectively kept forever. Indefinite retention of personal data violates GDPR storage limitation.`
            : `The data category \`${category}\` is retained for ${String(policy.retention_period_days)} days, beyond the ${String(MAX_REASONABLE_RETENTION_DAYS)}-day threshold. Long retention windows must be backed by a specific legal or business justification.`,
          `Reduce the retention window for \`${category}\` to the shortest period a documented legal or business need justifies.`,
          ["CWE-359"],
          `data_category: ${category}; retention_period_days: ${String(policy.retention_period_days)}`,
          undefined,
          undefined,
        ),
      );
    }

    // ── No automated deletion ───────────────────────────────────────────
    if (policy.automated_deletion !== true) {
      findings.push(
        mk(
          "retention-no-automated-deletion",
          "medium",
          `No automated deletion for \`${category}\``,
          `The data category \`${category}\` is not deleted automatically. Manual deletion is routinely forgotten, so data outlives its retention period and accumulates indefinitely.`,
          `Schedule automated deletion (a cron job, TTL index, or lifecycle policy) that purges \`${category}\` once its retention period elapses.`,
          ["CWE-359"],
          `data_category: ${category}; automated_deletion: ${
            policy.automated_deletion === false ? "false" : "undefined"
          }`,
          undefined,
          undefined,
        ),
      );
    }

    // ── Deletion method is "none" ───────────────────────────────────────
    if (policy.deletion_method === "none") {
      findings.push(
        mk(
          "retention-no-deletion-method",
          isPii ? "high" : "medium",
          `No deletion method for \`${category}\``,
          `The data category \`${category}\` declares \`deletion_method: none\`, so data is never removed. This cannot satisfy the GDPR right to erasure or the storage-limitation principle.`,
          `Choose a real deletion method for \`${category}\` — \`hard_delete\` or \`anonymize\` for personal data — and apply it when retention expires or on an erasure request.`,
          ["CWE-359"],
          `data_category: ${category}; deletion_method: none`,
          undefined,
          undefined,
        ),
      );
    }

    // ── PII using only soft delete ──────────────────────────────────────
    if (isPii && policy.deletion_method === "soft_delete") {
      findings.push(
        mk(
          "retention-pii-soft-delete-only",
          "high",
          `PII category \`${category}\` uses soft delete only`,
          `The personal-data category \`${category}\` is removed only by \`soft_delete\`, which flags rows as deleted but leaves the underlying personal data fully recoverable. This does not satisfy the GDPR right to erasure.`,
          `For personal data use \`hard_delete\` or irreversible \`anonymize\` so an erasure request actually destroys the data, including in backups and replicas.`,
          ["CWE-359", "CWE-312"],
          `data_category: ${category}; deletion_method: soft_delete; contains_pii: true`,
          undefined,
          undefined,
        ),
      );
    }

    // ── Missing legal basis for PII ─────────────────────────────────────
    if (isPii && (policy.legal_basis === undefined || policy.legal_basis.trim() === "")) {
      findings.push(
        mk(
          "retention-pii-no-legal-basis",
          "medium",
          `PII category \`${category}\` has no documented legal basis`,
          `The personal-data category \`${category}\` does not declare a \`legal_basis\`. GDPR Article 6 requires every processing of personal data to rest on a documented lawful basis.`,
          `Document the GDPR Article 6 lawful basis for retaining \`${category}\` (e.g. consent, contract, legal obligation, legitimate interest).`,
          ["CWE-359"],
          `data_category: ${category}; legal_basis: missing`,
          undefined,
          undefined,
        ),
      );
    }
  }

  // ── Source scan for hardcoded indefinite retention ────────────────────
  if (input.source !== undefined && input.source.length > 0) {
    const source = input.source;
    for (const pat of SOURCE_PATTERNS) {
      const regex = new RegExp(pat.regex.source, pat.regex.flags);
      let m: RegExpExecArray | null;
      while ((m = regex.exec(source)) !== null) {
        if (m[0].length === 0) {
          regex.lastIndex += 1;
          continue;
        }
        findings.push(
          mk(
            pat.rule,
            pat.severity,
            pat.title,
            pat.description,
            pat.remediation,
            ["CWE-359"],
            m[0].trim().slice(0, 200),
            input.filename ?? "source",
            lineAt(source, m.index),
          ),
        );
      }
    }
  }

  return findings;
}
