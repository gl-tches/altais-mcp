// Incident module: 7 tools for incident readiness and response —
// two auditors (audit logging completeness, canary / honeypot coverage)
// and five generators (incident-response playbook, RFC 9116 security.txt,
// GHSA-style security advisory, SIEM integration guidance, and a
// vulnerability-disclosure / bug-bounty program template).
//
// Auditors push Finding objects into the shared FindingStore. Generators
// produce a self-contained artifact and return it as JSON text without
// pushing findings — they advise rather than scan.

import { z } from "zod";
import type { CallToolResult } from "@modelcontextprotocol/sdk/types.js";

import type { FindingStore } from "../../core/report.js";
import type { Finding, ModuleDefinition, ToolDefinition } from "../../core/types.js";
import { draftAdvisory } from "./advisory.js";
import { checkCanary } from "./canary.js";
import { generateDisclosureProgram } from "./disclosure.js";
import { auditLogging } from "./logging.js";
import { generatePlaybook } from "./playbook.js";
import { generateSecurityTxt } from "./security-txt.js";
import { recommendSiem } from "./siem.js";

const MODULE_VERSION = "0.5.0";

const COMMON_ANNOTATIONS = {
  readOnlyHint: true,
  destructiveHint: false,
  idempotentHint: true,
  openWorldHint: false,
} as const;

export interface IncidentModuleDeps {
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
  deps: IncidentModuleDeps,
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

function makeGenerator<TInput>(
  parser: (args: unknown) => { success: true; data: TInput } | { success: false; message: string },
  run: (data: TInput) => unknown,
): (args: unknown) => CallToolResult {
  return (args: unknown) => {
    const parsed = parser(args);
    if (!parsed.success) return errorResult(`Invalid input: ${parsed.message}`);
    return textResult(jsonText(run(parsed.data)));
  };
}

const filenameField = z
  .string()
  .min(1)
  .max(512)
  .optional()
  .describe("Optional filename used for the finding location.");

// ─── altais_audit_logging ──────────────────────────────────────────────────

const loggingConfigSchema = z
  .object({
    has_audit_log: z.boolean().optional().describe("Whether a dedicated audit log exists."),
    logs_authentication: z
      .boolean()
      .optional()
      .describe("Whether authentication events (success and failure) are logged."),
    logs_authorization: z
      .boolean()
      .optional()
      .describe("Whether authorization decisions are logged."),
    logs_admin_actions: z
      .boolean()
      .optional()
      .describe("Whether administrative and privileged actions are logged."),
    log_injection_protection: z
      .boolean()
      .optional()
      .describe("Whether untrusted input is neutralized before logging."),
    centralized: z
      .boolean()
      .optional()
      .describe("Whether logs are shipped to a centralized store."),
    tamper_protection: z
      .boolean()
      .optional()
      .describe("Whether the audit log is append-only / integrity-protected."),
    retention_days: z
      .number()
      .int()
      .min(0)
      .max(36500)
      .optional()
      .describe("How many days audit logs are retained."),
    logs_sensitive_data: z
      .boolean()
      .optional()
      .describe("Whether logs contain sensitive data or PII."),
    pii_redaction: z
      .boolean()
      .optional()
      .describe("Whether PII / secret redaction is applied to log output."),
    includes_timestamp: z
      .boolean()
      .optional()
      .describe("Whether every log entry includes a timestamp."),
    includes_actor: z
      .boolean()
      .optional()
      .describe("Whether every log entry identifies the acting principal."),
  })
  .strict();

const loggingSchema = z
  .object({
    source: z
      .string()
      .min(1)
      .max(512 * 1024)
      .optional()
      .describe("Optional source code to scan for log-injection and sensitive-data logging."),
    config: loggingConfigSchema
      .optional()
      .describe("Optional declarative logging-configuration object."),
    filename: filenameField,
  })
  .refine((v) => v.source !== undefined || v.config !== undefined, {
    message: "provide at least one of `source` or `config`",
  });

function buildLoggingTool(deps: IncidentModuleDeps): ToolDefinition {
  return {
    name: "altais_audit_logging",
    title: "Audit logging completeness and log-injection prevention",
    description:
      "Assess audit-trail completeness and log-injection prevention. Scans optional source code for user-controlled input concatenated into log calls (CWE-117) and sensitive values written to logs (CWE-532), and reviews an optional logging-configuration object for a missing audit log, missing security-event logging (CWE-778), absent log-injection neutralization, unredacted PII in logs, no tamper protection, no centralization, and too-short retention.",
    inputSchema: loggingSchema.shape,
    annotations: COMMON_ANNOTATIONS,
    handler: makeRunner(deps, zodParser(loggingSchema), (d) =>
      auditLogging({
        ...(d.source !== undefined ? { source: d.source } : {}),
        ...(d.config !== undefined ? { config: d.config } : {}),
        ...(d.filename !== undefined ? { filename: d.filename } : {}),
      }),
    ),
  };
}

// ─── altais_generate_playbook ──────────────────────────────────────────────

const playbookSchema = z
  .object({
    scenario: z
      .enum([
        "ransomware",
        "data-breach",
        "account-takeover",
        "ddos",
        "supply-chain-compromise",
        "insider-threat",
        "credential-leak",
        "malware",
        "phishing",
      ])
      .describe("The incident scenario to generate a playbook for."),
    context: z
      .string()
      .min(1)
      .max(4096)
      .optional()
      .describe("Optional free-text context about the environment or the specific incident."),
  })
  .strict();

function buildPlaybookTool(): ToolDefinition {
  return {
    name: "altais_generate_playbook",
    title: "Generate an incident-response playbook",
    description:
      "Generate a structured, scenario-specific incident-response playbook organized along the NIST SP 800-61 lifecycle phases (preparation; detection & analysis; containment; eradication; recovery; post-incident activity). Covers ransomware, data breach, account takeover, DDoS, supply-chain compromise, insider threat, credential leak, malware, and phishing — with concrete steps, response roles, and communication guidance for the chosen scenario.",
    inputSchema: playbookSchema.shape,
    annotations: COMMON_ANNOTATIONS,
    handler: makeGenerator(zodParser(playbookSchema), (d) =>
      generatePlaybook({
        scenario: d.scenario,
        ...(d.context !== undefined ? { context: d.context } : {}),
      }),
    ),
  };
}

// ─── altais_generate_security_txt ──────────────────────────────────────────

const securityTxtConfigSchema = z
  .object({
    contact: z
      .string()
      .min(1)
      .max(512)
      .describe("Required contact — an email address or a mailto/https URL."),
    encryption: z
      .string()
      .min(1)
      .max(512)
      .optional()
      .describe("URL of a public key for encrypted reports."),
    policy: z
      .string()
      .min(1)
      .max(512)
      .optional()
      .describe("URL of the security / disclosure policy."),
    acknowledgments: z
      .string()
      .min(1)
      .max(512)
      .optional()
      .describe("URL of a security acknowledgments / hall-of-fame page."),
    preferred_languages: z
      .string()
      .min(1)
      .max(256)
      .optional()
      .describe("Comma-separated language tags, e.g. `en, fr`."),
    canonical: z
      .string()
      .min(1)
      .max(512)
      .optional()
      .describe("The canonical URL where this security.txt is located."),
    hiring: z.string().min(1).max(512).optional().describe("URL of security-related job openings."),
    expires_days: z
      .number()
      .int()
      .min(1)
      .max(3650)
      .optional()
      .describe("Days until the file expires (defaults to 365)."),
  })
  .strict();

const securityTxtSchema = z.object({ config: securityTxtConfigSchema }).strict();

function buildSecurityTxtTool(): ToolDefinition {
  return {
    name: "altais_generate_security_txt",
    title: "Generate an RFC 9116 security.txt",
    description:
      "Generate a `security.txt` file body conforming to RFC 9116. Emits valid field syntax with a required `Contact` field and a future-dated `Expires` field, plus optional `Encryption`, `Policy`, `Acknowledgments`, `Preferred-Languages`, `Canonical`, and `Hiring` fields, and a placement note for `/.well-known/security.txt`.",
    inputSchema: securityTxtSchema.shape,
    annotations: COMMON_ANNOTATIONS,
    handler: makeGenerator(zodParser(securityTxtSchema), (d) => generateSecurityTxt(d.config)),
  };
}

// ─── altais_draft_advisory ─────────────────────────────────────────────────

const advisoryConfigSchema = z
  .object({
    title: z.string().min(1).max(256).describe("Advisory title / vulnerability name."),
    severity: z
      .enum(["critical", "high", "moderate", "low"])
      .describe("GHSA-style severity rating."),
    cve: z
      .string()
      .min(1)
      .max(32)
      .regex(/^CVE-\d{4}-\d{4,}$/i, "must be a CVE identifier, e.g. CVE-2024-12345")
      .optional()
      .describe("Optional CVE identifier."),
    cwe: z
      .array(z.string().min(1).max(32))
      .max(20)
      .optional()
      .describe("Optional list of CWE identifiers."),
    affected_versions: z
      .string()
      .min(1)
      .max(256)
      .optional()
      .describe("Affected version range, e.g. `>= 2.0.0, < 2.4.1`."),
    patched_version: z.string().min(1).max(128).optional().describe("First fixed version."),
    description: z
      .string()
      .min(1)
      .max(8192)
      .optional()
      .describe("Plain-language description of the vulnerability."),
    impact: z
      .string()
      .min(1)
      .max(4096)
      .optional()
      .describe("Who is affected and what an attacker can achieve."),
    cvss_vector: z.string().min(1).max(512).optional().describe("Optional CVSS vector string."),
    credits: z.string().min(1).max(512).optional().describe("Credit for the reporter(s)."),
  })
  .strict();

const advisorySchema = z.object({ config: advisoryConfigSchema }).strict();

function buildAdvisoryTool(): ToolDefinition {
  return {
    name: "altais_draft_advisory",
    title: "Draft a GHSA-style security advisory",
    description:
      "Draft a security advisory in the GitHub Security Advisory (GHSA) format as markdown: a summary, severity rating with optional CVSS vector and CVE, affected and patched versions, impact, remediation guidance, references (NVD and CWE links), a disclosure timeline, and credits.",
    inputSchema: advisorySchema.shape,
    annotations: COMMON_ANNOTATIONS,
    handler: makeGenerator(zodParser(advisorySchema), (d) =>
      draftAdvisory({
        title: d.config.title,
        severity: d.config.severity,
        ...(d.config.cve !== undefined ? { cve: d.config.cve } : {}),
        ...(d.config.cwe !== undefined ? { cwe: d.config.cwe } : {}),
        ...(d.config.affected_versions !== undefined
          ? { affected_versions: d.config.affected_versions }
          : {}),
        ...(d.config.patched_version !== undefined
          ? { patched_version: d.config.patched_version }
          : {}),
        ...(d.config.description !== undefined ? { description: d.config.description } : {}),
        ...(d.config.impact !== undefined ? { impact: d.config.impact } : {}),
        ...(d.config.cvss_vector !== undefined ? { cvss_vector: d.config.cvss_vector } : {}),
        ...(d.config.credits !== undefined ? { credits: d.config.credits } : {}),
      }),
    ),
  };
}

// ─── altais_check_canary ───────────────────────────────────────────────────

const canaryConfigSchema = z
  .object({
    canary_tokens_deployed: z.boolean().optional().describe("Whether canary tokens are deployed."),
    honeypots_deployed: z.boolean().optional().describe("Whether honeypots are deployed."),
    coverage_areas: z
      .array(z.string().min(1).max(128))
      .max(50)
      .optional()
      .describe(
        "Areas covered by deception controls, e.g. `database`, `credentials`, `cloud`, `filesystem`, `endpoints`.",
      ),
    alerting_enabled: z
      .boolean()
      .optional()
      .describe("Whether a canary / honeypot trigger raises an alert."),
    alert_routing: z
      .string()
      .min(1)
      .max(256)
      .optional()
      .describe("Where trigger alerts are routed, e.g. an on-call channel."),
    monitored_assets: z
      .array(z.string().min(1).max(256))
      .max(200)
      .optional()
      .describe("Assets the deception controls are protecting."),
  })
  .strict();

const canarySchema = z.object({ config: canaryConfigSchema, filename: filenameField }).strict();

function buildCanaryTool(deps: IncidentModuleDeps): ToolDefinition {
  return {
    name: "altais_check_canary",
    title: "Assess canary-token and honeypot coverage",
    description:
      "Assess deception-control coverage from a declarative configuration: flags no canary tokens deployed (CWE-778), no honeypots deployed, triggers that raise no alert, alerts with no routing destination, coverage gaps for sensitive areas (databases, credential stores, file shares, cloud accounts, internal endpoints), and a missing monitored-asset inventory.",
    inputSchema: canarySchema.shape,
    annotations: COMMON_ANNOTATIONS,
    handler: makeRunner(deps, zodParser(canarySchema), (d) =>
      checkCanary({
        config: d.config,
        ...(d.filename !== undefined ? { filename: d.filename } : {}),
      }),
    ),
  };
}

// ─── altais_recommend_siem ─────────────────────────────────────────────────

const siemConfigSchema = z
  .object({
    platform: z
      .enum(["splunk", "elastic", "cloudwatch", "sentinel", "datadog", "chronicle", "other"])
      .describe("The SIEM platform to tailor guidance for."),
    log_sources: z
      .array(z.string().min(1).max(256))
      .max(100)
      .optional()
      .describe("Log sources already onboarded into the SIEM."),
    existing_detections: z
      .array(z.string().min(1).max(256))
      .max(200)
      .optional()
      .describe("Detection rules / use-cases already in place."),
  })
  .strict();

const siemSchema = z.object({ config: siemConfigSchema }).strict();

function buildSiemTool(): ToolDefinition {
  return {
    name: "altais_recommend_siem",
    title: "Recommend SIEM integration steps",
    description:
      "Generate platform-aware SIEM integration guidance for Splunk, Elastic, CloudWatch, Microsoft Sentinel, Datadog, Chronicle / Google SecOps, or another platform. Returns recommended log sources to onboard (excluding those already configured), priority detection use-cases (excluding existing detections), recommended dashboards, and alerting guidance.",
    inputSchema: siemSchema.shape,
    annotations: COMMON_ANNOTATIONS,
    handler: makeGenerator(zodParser(siemSchema), (d) =>
      recommendSiem({
        platform: d.config.platform,
        ...(d.config.log_sources !== undefined ? { log_sources: d.config.log_sources } : {}),
        ...(d.config.existing_detections !== undefined
          ? { existing_detections: d.config.existing_detections }
          : {}),
      }),
    ),
  };
}

// ─── altais_generate_disclosure_program ────────────────────────────────────

const disclosureConfigSchema = z
  .object({
    organization: z.string().min(1).max(256).describe("The organization the policy is for."),
    scope_in: z
      .array(z.string().min(1).max(256))
      .max(100)
      .optional()
      .describe("In-scope systems, domains, and applications."),
    scope_out: z
      .array(z.string().min(1).max(256))
      .max(100)
      .optional()
      .describe("Out-of-scope systems and services."),
    safe_harbor: z
      .boolean()
      .optional()
      .describe("Whether to include a safe-harbor clause (defaults to true)."),
    bounty: z
      .boolean()
      .optional()
      .describe("Whether this is a paid bug-bounty program (defaults to a no-reward VDP)."),
    response_sla_days: z
      .number()
      .int()
      .min(1)
      .max(90)
      .optional()
      .describe("Acknowledgment SLA in business days (defaults to 5)."),
    contact: z
      .string()
      .min(1)
      .max(512)
      .describe("Required reporting contact — an email address or URL."),
  })
  .strict();

const disclosureSchema = z.object({ config: disclosureConfigSchema }).strict();

function buildDisclosureTool(): ToolDefinition {
  return {
    name: "altais_generate_disclosure_program",
    title: "Generate a vulnerability-disclosure / bug-bounty program",
    description:
      "Generate a complete coordinated-vulnerability-disclosure (VDP) or bug-bounty policy document in markdown: introduction, in-scope and out-of-scope definitions, reporting instructions, the organization's commitments and acknowledgment SLA, researcher expectations, a safe-harbor clause, a rewards section, and references.",
    inputSchema: disclosureSchema.shape,
    annotations: COMMON_ANNOTATIONS,
    handler: makeGenerator(zodParser(disclosureSchema), (d) =>
      generateDisclosureProgram({
        organization: d.config.organization,
        contact: d.config.contact,
        ...(d.config.scope_in !== undefined ? { scope_in: d.config.scope_in } : {}),
        ...(d.config.scope_out !== undefined ? { scope_out: d.config.scope_out } : {}),
        ...(d.config.safe_harbor !== undefined ? { safe_harbor: d.config.safe_harbor } : {}),
        ...(d.config.bounty !== undefined ? { bounty: d.config.bounty } : {}),
        ...(d.config.response_sla_days !== undefined
          ? { response_sla_days: d.config.response_sla_days }
          : {}),
      }),
    ),
  };
}

export function createIncidentModule(deps: IncidentModuleDeps): ModuleDefinition {
  const tools: readonly ToolDefinition[] = [
    buildLoggingTool(deps),
    buildPlaybookTool(),
    buildSecurityTxtTool(),
    buildAdvisoryTool(),
    buildCanaryTool(deps),
    buildSiemTool(),
    buildDisclosureTool(),
  ];
  return {
    name: "incident",
    description:
      "Incident readiness and response: audit-logging completeness and log-injection checks, canary / honeypot coverage assessment, and generators for NIST SP 800-61 response playbooks, RFC 9116 security.txt, GHSA security advisories, SIEM integration guidance, and vulnerability-disclosure / bug-bounty programs.",
    version: MODULE_VERSION,
    tools,
    init() {
      // No async resources to load.
    },
  };
}
