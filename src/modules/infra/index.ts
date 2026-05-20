// Infrastructure module: 4 auditors for infrastructure security —
// network segmentation and firewall rules, DNS configuration, zero-trust
// architecture maturity (NIST SP 800-207), and CIS-Benchmark-style
// platform hardening.

import { z } from "zod";
import type { CallToolResult } from "@modelcontextprotocol/sdk/types.js";

import type { FindingStore } from "../../core/report.js";
import type { Finding, ModuleDefinition, ToolDefinition } from "../../core/types.js";
import { auditDns } from "./dns.js";
import { checkHardening } from "./hardening.js";
import { auditNetwork } from "./network.js";
import { checkZeroTrust } from "./zero-trust.js";

const MODULE_VERSION = "0.4.0";

const COMMON_ANNOTATIONS = {
  readOnlyHint: true,
  destructiveHint: false,
  idempotentHint: true,
  openWorldHint: false,
} as const;

export interface InfraModuleDeps {
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
  deps: InfraModuleDeps,
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

// ─── altais_audit_network ──────────────────────────────────────────────────

const firewallRuleSchema = z.object({
  direction: z.enum(["ingress", "egress"]).describe("Traffic direction the rule governs."),
  source: z
    .string()
    .min(1)
    .max(256)
    .describe("Source CIDR / address / label (e.g. `0.0.0.0/0`, `10.0.0.0/8`, `any`)."),
  destination: z
    .string()
    .min(1)
    .max(256)
    .optional()
    .describe("Optional destination CIDR / address / label."),
  port: z
    .union([z.number().int().min(0).max(65535), z.string().min(1).max(64)])
    .optional()
    .describe("Port or port range (number, `*`, `any`, or a range string)."),
  protocol: z
    .string()
    .min(1)
    .max(32)
    .optional()
    .describe("Transport protocol (e.g. `tcp`, `udp`, `icmp`, `any`)."),
  action: z.enum(["allow", "deny"]).describe("Whether the rule permits or blocks the traffic."),
});

const networkConfigSchema = z.object({
  firewall_rules: z
    .array(firewallRuleSchema)
    .max(2000)
    .optional()
    .describe("The firewall / security-group rule set to review."),
  zones: z
    .array(z.string().min(1).max(128))
    .max(256)
    .optional()
    .describe("Named network zones / trust tiers."),
  segments: z
    .array(z.string().min(1).max(128))
    .max(256)
    .optional()
    .describe("Named network segments / subnets."),
  egress_filtering: z
    .boolean()
    .optional()
    .describe("Whether outbound traffic is filtered against an allow-list."),
});

const networkSchema = z.object({
  config: networkConfigSchema.describe("The network configuration to audit."),
  filename: filenameField,
});

function buildNetworkTool(deps: InfraModuleDeps): ToolDefinition {
  return {
    name: "altais_audit_network",
    title: "Audit network segmentation and firewall rules",
    description:
      "Review a network configuration for segmentation and firewall weaknesses: ingress `allow` rules from any source (`0.0.0.0/0` / `::/0`), especially to admin and database ports (SSH, RDP, PostgreSQL, MySQL, Redis, MongoDB, Elasticsearch); unconstrained `allow any any` rules; a flat topology with no zones or segments; unrestricted egress; and rule sets with no default-deny.",
    inputSchema: networkSchema.shape,
    annotations: COMMON_ANNOTATIONS,
    handler: makeRunner(deps, zodParser(networkSchema), (d) => auditNetwork(d)),
  };
}

// ─── altais_audit_dns ──────────────────────────────────────────────────────

const dnsRecordSchema = z.object({
  name: z.string().min(1).max(256).describe("Record name / FQDN."),
  type: z.string().min(1).max(16).describe("Record type (e.g. `A`, `CNAME`, `MX`, `NS`)."),
  value: z.string().min(1).max(512).describe("Record value / target."),
  points_to_external: z
    .boolean()
    .optional()
    .describe("Whether the record's target is an external (third-party) resource."),
});

const dnsConfigSchema = z.object({
  dnssec_enabled: z.boolean().optional().describe("Whether DNSSEC is enabled for the zone."),
  zone_transfer_allowed: z
    .boolean()
    .optional()
    .describe("Whether AXFR zone transfers are allowed."),
  allowed_to: z
    .array(z.string().min(1).max(128))
    .max(256)
    .optional()
    .describe("Hosts permitted to perform zone transfers."),
  caa_records: z
    .array(z.string().min(1).max(256))
    .max(256)
    .optional()
    .describe("CAA records published for the zone."),
  wildcard_records: z
    .union([z.boolean(), z.array(z.string().min(1).max(256)).max(256)])
    .optional()
    .describe("Whether wildcard records exist, or the list of wildcard record names."),
  records: z
    .array(dnsRecordSchema)
    .max(5000)
    .optional()
    .describe("DNS records to inspect for dangling external targets."),
});

const dnsSchema = z.object({
  config: dnsConfigSchema.describe("The DNS configuration to audit."),
  filename: filenameField,
});

function buildDnsTool(deps: InfraModuleDeps): ToolDefinition {
  return {
    name: "altais_audit_dns",
    title: "Audit DNS configuration security",
    description:
      "Check a DNS zone configuration for security weaknesses: DNSSEC disabled (responses cannot be verified), open zone transfers / AXFR (full zone enumeration), missing CAA records (any CA may issue certificates), wildcard records (broadened attack surface), and dangling records pointing to unclaimed external resources (subdomain-takeover risk).",
    inputSchema: dnsSchema.shape,
    annotations: COMMON_ANNOTATIONS,
    handler: makeRunner(deps, zodParser(dnsSchema), (d) => auditDns(d)),
  };
}

// ─── altais_check_zero_trust ───────────────────────────────────────────────

const zeroTrustConfigSchema = z.object({
  verify_explicitly: z.boolean().optional().describe("Every request is verified explicitly."),
  least_privilege_access: z.boolean().optional().describe("Access is scoped to least privilege."),
  assume_breach: z.boolean().optional().describe("The architecture assumes breach."),
  mfa_enforced: z.boolean().optional().describe("Multi-factor authentication is enforced."),
  microsegmentation: z.boolean().optional().describe("The network is microsegmented."),
  device_trust_verification: z
    .boolean()
    .optional()
    .describe("Device trust / posture is verified before access."),
  continuous_verification: z
    .boolean()
    .optional()
    .describe("Sessions are continuously re-verified."),
  no_implicit_network_trust: z
    .boolean()
    .optional()
    .describe("Network location confers no implicit trust."),
  encrypted_internal_traffic: z
    .boolean()
    .optional()
    .describe("Internal (east-west) traffic is encrypted."),
  per_request_authorization: z
    .boolean()
    .optional()
    .describe("Authorization is evaluated per request."),
  centralized_policy_engine: z
    .boolean()
    .optional()
    .describe("A centralized policy engine governs access decisions."),
});

const zeroTrustSchema = z.object({
  config: zeroTrustConfigSchema.describe("The zero-trust architecture description to assess."),
  filename: filenameField,
});

function buildZeroTrustTool(deps: InfraModuleDeps): ToolDefinition {
  return {
    name: "altais_check_zero_trust",
    title: "Assess an architecture against zero-trust principles",
    description:
      "Assess an architecture against the tenets of NIST SP 800-207 (Zero Trust Architecture): verify explicitly, least-privilege access, assume breach, enforced MFA, microsegmentation, device-trust verification, continuous verification, no implicit network trust, encrypted east-west traffic, per-request authorization, and a centralized policy engine. Emits a finding for each missing tenet plus a maturity summary.",
    inputSchema: zeroTrustSchema.shape,
    annotations: COMMON_ANNOTATIONS,
    handler: makeRunner(deps, zodParser(zeroTrustSchema), (d) => checkZeroTrust(d)),
  };
}

// ─── altais_check_hardening ────────────────────────────────────────────────

const hardeningSettingSchema = z.union([z.boolean(), z.number(), z.string().max(512)]);

const hardeningSchema = z.object({
  platform: z
    .enum(["linux", "windows", "docker", "kubernetes", "aws", "gcp", "azure"])
    .describe("The platform whose CIS-style hardening controls should be checked."),
  settings: z
    .record(z.string().min(1).max(128), hardeningSettingSchema)
    .describe("Map of hardening-relevant setting keys to their observed values."),
});

function buildHardeningTool(deps: InfraModuleDeps): ToolDefinition {
  return {
    name: "altais_check_hardening",
    title: "Check a system against a CIS Benchmark",
    description:
      "Check a system's settings against a curated set of high-value CIS-Benchmark-style controls for the chosen platform (linux, windows, docker, kubernetes, aws, gcp, azure) — for example SSH root login disabled, host firewall enabled, no privileged containers, RBAC and audit logging on Kubernetes, root MFA and multi-region CloudTrail on AWS. Flags every control the settings show non-compliant or do not report.",
    inputSchema: hardeningSchema.shape,
    annotations: COMMON_ANNOTATIONS,
    handler: makeRunner(deps, zodParser(hardeningSchema), (d) => checkHardening(d)),
  };
}

export function createInfraModule(deps: InfraModuleDeps): ModuleDefinition {
  const tools: readonly ToolDefinition[] = [
    buildNetworkTool(deps),
    buildDnsTool(deps),
    buildZeroTrustTool(deps),
    buildHardeningTool(deps),
  ];
  return {
    name: "infra",
    description:
      "Infrastructure audits: network segmentation and firewall rules, DNS configuration security, zero-trust architecture maturity (NIST SP 800-207), and CIS-Benchmark-style platform hardening.",
    version: MODULE_VERSION,
    tools,
    init() {
      // No async resources to load.
    },
  };
}
