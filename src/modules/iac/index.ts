// IaC module: 4 auditors for infrastructure-as-code security —
// Terraform HCL misconfigurations, Kubernetes manifest Pod Security
// Standards compliance, Helm chart insecure defaults, and OPA / Rego
// and Kyverno policy-as-code validation.

import { z } from "zod";
import type { CallToolResult } from "@modelcontextprotocol/sdk/types.js";

import type { FindingStore } from "../../core/report.js";
import type { Finding, ModuleDefinition, ToolDefinition } from "../../core/types.js";
import { auditHelmChart } from "./helm.js";
import { auditK8sManifest } from "./kubernetes.js";
import { auditPolicy } from "./policy.js";
import { auditTerraform } from "./terraform.js";

const MODULE_VERSION = "0.3.0";

const COMMON_ANNOTATIONS = {
  readOnlyHint: true,
  destructiveHint: false,
  idempotentHint: true,
  openWorldHint: false,
} as const;

export interface IacModuleDeps {
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
  deps: IacModuleDeps,
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

const fileContentField = z
  .string()
  .min(1)
  .max(512 * 1024)
  .describe("Full text of the file to audit.");

// ─── altais_audit_terraform ────────────────────────────────────────────────

const terraformSchema = z.object({
  content: fileContentField,
  filename: filenameField,
});

function buildTerraformTool(deps: IacModuleDeps): ToolDefinition {
  return {
    name: "altais_audit_terraform",
    title: "Audit Terraform HCL",
    description:
      "Scan Terraform HCL for security misconfigurations: security-group / firewall ingress open to `0.0.0.0/0` (especially SSH 22 / RDP 3389), public object storage (`public-read` ACLs, disabled public-access blocking), unencrypted resources, hardcoded secrets and plaintext provider credentials, IAM `*` action / resource wildcards, publicly accessible databases, and disabled audit logging.",
    inputSchema: terraformSchema.shape,
    annotations: COMMON_ANNOTATIONS,
    handler: makeRunner(deps, zodParser(terraformSchema), (d) => auditTerraform(d)),
  };
}

// ─── altais_audit_k8s_manifest ─────────────────────────────────────────────

const k8sSchema = z.object({
  content: fileContentField,
  filename: filenameField,
});

function buildK8sTool(deps: IacModuleDeps): ToolDefinition {
  return {
    name: "altais_audit_k8s_manifest",
    title: "Audit a Kubernetes manifest",
    description:
      "Check a Kubernetes manifest against the Pod Security Standards: privileged containers, privilege escalation, running as root, shared host network / PID / IPC namespaces, dangerous added Linux capabilities, a missing security context, missing CPU / memory resource limits, automatically mounted service-account tokens, hostPath volumes, a writable root filesystem, mutable `:latest` image tags, and wildcard RBAC rules.",
    inputSchema: k8sSchema.shape,
    annotations: COMMON_ANNOTATIONS,
    handler: makeRunner(deps, zodParser(k8sSchema), (d) => auditK8sManifest(d)),
  };
}

// ─── altais_audit_helm_chart ───────────────────────────────────────────────

const helmSchema = z.object({
  content: fileContentField,
  filename: filenameField,
});

function buildHelmTool(deps: IacModuleDeps): ToolDefinition {
  return {
    name: "altais_audit_helm_chart",
    title: "Audit a Helm chart",
    description:
      "Review a Helm chart's `values.yaml` (optionally with concatenated templates) for insecure defaults: privileged pods, empty / `latest` image tags, publicly exposing `LoadBalancer` / `NodePort` service types, disabled RBAC creation, a disabled security context, default / hardcoded passwords, secrets passed via `--set`, and templates that render secrets into a ConfigMap.",
    inputSchema: helmSchema.shape,
    annotations: COMMON_ANNOTATIONS,
    handler: makeRunner(deps, zodParser(helmSchema), (d) => auditHelmChart(d)),
  };
}

// ─── altais_check_policy_as_code ───────────────────────────────────────────

const policySchema = z.object({
  content: fileContentField,
  policy_type: z
    .enum(["rego", "kyverno"])
    .describe("The policy language: `rego` for OPA / Rego, `kyverno` for Kyverno YAML policies."),
  filename: filenameField,
});

function buildPolicyTool(deps: IacModuleDeps): ToolDefinition {
  return {
    name: "altais_check_policy_as_code",
    title: "Check a policy-as-code file",
    description:
      "Validate an OPA / Rego or Kyverno policy. For Rego: flag an insecure `default allow = true`, a policy with no `deny` / `violation` rules, and `http.send` network calls in the decision path. For Kyverno: flag `validationFailureAction: Audit` (should be `Enforce`), disabled background scanning, a policy with no `validate` / `deny` rules, and a rule with no `match` selector.",
    inputSchema: policySchema.shape,
    annotations: COMMON_ANNOTATIONS,
    handler: makeRunner(deps, zodParser(policySchema), (d) => auditPolicy(d)),
  };
}

export function createIacModule(deps: IacModuleDeps): ModuleDefinition {
  const tools: readonly ToolDefinition[] = [
    buildTerraformTool(deps),
    buildK8sTool(deps),
    buildHelmTool(deps),
    buildPolicyTool(deps),
  ];
  return {
    name: "iac",
    description:
      "Infrastructure-as-code audits: Terraform HCL misconfigurations, Kubernetes manifest Pod Security Standards compliance, Helm chart insecure defaults, and OPA / Rego and Kyverno policy-as-code validation.",
    version: MODULE_VERSION,
    tools,
    init() {
      // No async resources to load.
    },
  };
}
