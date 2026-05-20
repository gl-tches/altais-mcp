// Data module: 4 auditors for data-privacy security — PII detection,
// data-sensitivity classification, privacy-by-design auditing, and
// data-retention / deletion review.

import { z } from "zod";
import type { CallToolResult } from "@modelcontextprotocol/sdk/types.js";

import type { FindingStore } from "../../core/report.js";
import type { Finding, ModuleDefinition, ToolDefinition } from "../../core/types.js";
import { classifyDataFindings } from "./classification.js";
import { detectPii } from "./pii.js";
import { auditPrivacy } from "./privacy.js";
import { checkRetention } from "./retention.js";

const MODULE_VERSION = "0.3.0";

const COMMON_ANNOTATIONS = {
  readOnlyHint: true,
  destructiveHint: false,
  idempotentHint: true,
  openWorldHint: false,
} as const;

export interface DataModuleDeps {
  readonly findingStore: FindingStore;
}

function textResult(text: string): CallToolResult {
  return { content: [{ type: "text", text }] };
}

function errorResult(text: string): CallToolResult {
  return { isError: true, content: [{ type: "text", text }] };
}

function jsonText(value: unknown): string {
  return JSON.stringify(value, null, 2);
}

function summarize(findings: readonly Finding[]): {
  total: number;
  by_severity: Record<string, number>;
} {
  const bySeverity: Record<string, number> = {};
  for (const f of findings) bySeverity[f.severity] = (bySeverity[f.severity] ?? 0) + 1;
  return { total: findings.length, by_severity: bySeverity };
}

function withSummary(findings: readonly Finding[]): unknown {
  return { summary: summarize(findings), findings };
}

function zodParser<T>(
  schema: z.ZodType<T>,
): (args: unknown) => { success: true; data: T } | { success: false; message: string } {
  return (args) => {
    const r = schema.safeParse(args);
    if (r.success) return { success: true, data: r.data };
    return {
      success: false,
      message: r.error.issues
        .map((i) => `${i.path.join(".") || "<root>"}: ${i.message}`)
        .join("; "),
    };
  };
}

function makeRunner<TInput>(
  deps: DataModuleDeps,
  parser: (args: unknown) => { success: true; data: TInput } | { success: false; message: string },
  run: (data: TInput) => readonly Finding[],
): (args: unknown) => CallToolResult {
  return (args: unknown) => {
    const parsed = parser(args);
    if (!parsed.success) return errorResult(`Invalid input: ${parsed.message}`);
    const findings = run(parsed.data);
    deps.findingStore.addMany(findings);
    return textResult(jsonText(withSummary(findings)));
  };
}

const filenameField = z
  .string()
  .min(1)
  .max(512)
  .optional()
  .describe("Optional filename used for the finding location.");

const sourceField = z
  .string()
  .min(1)
  .max(512 * 1024)
  .describe("Source code or sample data to scan.");

// ─── altais_detect_pii ─────────────────────────────────────────────────────

const detectPiiSchema = z.object({
  source: sourceField,
  filename: filenameField,
});

function buildDetectPiiTool(deps: DataModuleDeps): ToolDefinition {
  return {
    name: "altais_detect_pii",
    title: "Detect personally identifiable information",
    description:
      "Scan source code or sample data for personally identifiable information: email addresses, phone numbers, US Social Security Numbers, credit-card-like numbers (Luhn-checked), IPv4 addresses, IBANs, and dates of birth, plus PII-revealing identifiers in code (variable / column names like `ssn`, `first_name`, `date_of_birth`, `passport`, `home_address`). Raw values are masked in findings — never echoed back.",
    inputSchema: detectPiiSchema.shape,
    annotations: COMMON_ANNOTATIONS,
    handler: makeRunner(deps, zodParser(detectPiiSchema), (d) => detectPii(d)),
  };
}

// ─── altais_classify_data ──────────────────────────────────────────────────

const dataFieldSchema = z.object({
  name: z.string().min(1).max(256).describe("Field, column, or property name."),
  type: z.string().min(1).max(128).optional().describe("Optional declared data type."),
  description: z
    .string()
    .min(1)
    .max(1024)
    .optional()
    .describe("Optional human description of the field."),
});

const classifyDataSchema = z.object({
  fields: z
    .array(dataFieldSchema)
    .min(1)
    .max(500)
    .describe("Data fields to classify by sensitivity tier."),
});

function buildClassifyDataTool(deps: DataModuleDeps): ToolDefinition {
  return {
    name: "altais_classify_data",
    title: "Classify data fields by sensitivity",
    description:
      "Classify data fields into sensitivity tiers — `restricted` (passwords, secrets, SSN, credit card, health, biometric), `confidential` (email, phone, name, address, date of birth, IP, precise location), `internal` (user_id, timestamps, internal flags), or `public` (slug, public title). Returns a per-field classification, a tier summary, and a tracked finding for every restricted or confidential field.",
    inputSchema: classifyDataSchema.shape,
    annotations: COMMON_ANNOTATIONS,
    handler: makeRunner(deps, zodParser(classifyDataSchema), (d) => classifyDataFindings(d)),
  };
}

// ─── altais_audit_privacy ──────────────────────────────────────────────────

const privacyConfigSchema = z.object({
  data_minimization: z.boolean().optional(),
  purpose_limitation: z.boolean().optional(),
  consent_mechanism: z.boolean().optional(),
  encryption_at_rest: z.boolean().optional(),
  encryption_in_transit: z.boolean().optional(),
  default_private: z.boolean().optional(),
  dpo_designated: z.boolean().optional(),
  dpia_conducted: z.boolean().optional(),
  user_data_export: z.boolean().optional(),
  user_data_deletion: z.boolean().optional(),
  breach_notification_process: z.boolean().optional(),
  third_party_data_sharing: z.boolean().optional(),
});

const auditPrivacySchema = z.object({
  config: privacyConfigSchema.describe(
    "Privacy-by-design configuration flags for the implementation.",
  ),
});

function buildAuditPrivacyTool(deps: DataModuleDeps): ToolDefinition {
  return {
    name: "altais_audit_privacy",
    title: "Audit privacy-by-design compliance",
    description:
      "Check an implementation against the GDPR-aligned privacy-by-design principles: data minimization, purpose limitation, consent mechanism, encryption at rest / in transit, private-by-default, DPO designation, DPIA, user data export (right to access / portability), user data deletion (right to erasure), and a breach-notification process. Emits a finding for every principle that is false or missing, and flags enabled third-party data sharing as a risk.",
    inputSchema: auditPrivacySchema.shape,
    annotations: COMMON_ANNOTATIONS,
    handler: makeRunner(deps, zodParser(auditPrivacySchema), (d) => auditPrivacy(d)),
  };
}

// ─── altais_check_retention ────────────────────────────────────────────────

const retentionPolicySchema = z.object({
  data_category: z.string().min(1).max(256).describe("Name of the data category."),
  retention_period_days: z
    .number()
    .int()
    .min(-1)
    .max(1_000_000)
    .optional()
    .describe("Retention period in days; <= 0 means indefinite."),
  deletion_method: z
    .enum(["hard_delete", "soft_delete", "anonymize", "none"])
    .optional()
    .describe("How the data is removed at end of life."),
  automated_deletion: z
    .boolean()
    .optional()
    .describe("Whether deletion runs automatically at end of retention."),
  legal_basis: z
    .string()
    .min(1)
    .max(512)
    .optional()
    .describe("Documented GDPR Article 6 lawful basis for retention."),
  contains_pii: z.boolean().optional().describe("Whether the category contains personal data."),
});

const checkRetentionSchema = z.object({
  policies: z
    .array(retentionPolicySchema)
    .min(1)
    .max(500)
    .describe("Data-retention policies to review."),
  source: z
    .string()
    .min(1)
    .max(512 * 1024)
    .optional()
    .describe("Optional source to scan for hardcoded indefinite retention."),
  filename: filenameField,
});

function buildCheckRetentionTool(deps: DataModuleDeps): ToolDefinition {
  return {
    name: "altais_check_retention",
    title: "Check data retention and deletion",
    description:
      "Analyze data-retention policies against the GDPR storage-limitation principle. Flags missing or undefined retention periods, indefinite or excessively long retention (> 3650 days), missing automated deletion, a `none` deletion method, personal-data categories deleted only by `soft_delete`, and personal data with no documented legal basis. Optionally regex-scans source for hardcoded indefinite retention.",
    inputSchema: checkRetentionSchema.shape,
    annotations: COMMON_ANNOTATIONS,
    handler: makeRunner(deps, zodParser(checkRetentionSchema), (d) => checkRetention(d)),
  };
}

export function createDataModule(deps: DataModuleDeps): ModuleDefinition {
  const tools: readonly ToolDefinition[] = [
    buildDetectPiiTool(deps),
    buildClassifyDataTool(deps),
    buildAuditPrivacyTool(deps),
    buildCheckRetentionTool(deps),
  ];
  return {
    name: "data",
    description:
      "Data-privacy audits: PII detection in code and sample data, data-sensitivity classification, privacy-by-design (GDPR) compliance auditing, and data-retention / deletion review.",
    version: MODULE_VERSION,
    tools,
    init() {
      // No async resources to load.
    },
  };
}
