// Container module: 3 auditors for container image security —
// Dockerfile best practices, Docker Compose misconfigurations, and base
// image hygiene (pinning, end-of-life, bloat).

import { z } from "zod";
import type { CallToolResult } from "@modelcontextprotocol/sdk/types.js";

import type { FindingStore } from "../../core/report.js";
import type { Finding, ModuleDefinition, ToolDefinition } from "../../core/types.js";
import { checkBaseImage } from "./base-image.js";
import { auditCompose } from "./compose.js";
import { auditDockerfile } from "./dockerfile.js";

const MODULE_VERSION = "0.3.0";

const COMMON_ANNOTATIONS = {
  readOnlyHint: true,
  destructiveHint: false,
  idempotentHint: true,
  openWorldHint: false,
} as const;

export interface ContainerModuleDeps {
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
  deps: ContainerModuleDeps,
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

// ─── altais_audit_dockerfile ───────────────────────────────────────────────

const dockerfileSchema = z.object({
  content: fileContentField,
  filename: filenameField,
});

function buildDockerfileTool(deps: ContainerModuleDeps): ToolDefinition {
  return {
    name: "altais_audit_dockerfile",
    title: "Audit a Dockerfile",
    description:
      "Analyze a Dockerfile for security best-practice violations: running as root, mutable / `latest` base image tags, `ADD` of remote URLs, remote scripts piped into a shell, credentials baked into ENV / ARG, world-writable `chmod 777`, `sudo` in `RUN`, whole-context `COPY .`, and a missing `HEALTHCHECK`.",
    inputSchema: dockerfileSchema.shape,
    annotations: COMMON_ANNOTATIONS,
    handler: makeRunner(deps, zodParser(dockerfileSchema), (d) => auditDockerfile(d)),
  };
}

// ─── altais_audit_compose ──────────────────────────────────────────────────

const composeSchema = z.object({
  content: fileContentField,
  filename: filenameField,
});

function buildComposeTool(deps: ContainerModuleDeps): ToolDefinition {
  return {
    name: "altais_audit_compose",
    title: "Audit a Docker Compose file",
    description:
      "Review a Docker Compose file for security misconfigurations: privileged mode, shared host network / PID / IPC namespaces, a mounted Docker socket, dangerous added Linux capabilities, a disabled seccomp / AppArmor sandbox, hardcoded credentials, and unpinned image tags.",
    inputSchema: composeSchema.shape,
    annotations: COMMON_ANNOTATIONS,
    handler: makeRunner(deps, zodParser(composeSchema), (d) => auditCompose(d)),
  };
}

// ─── altais_check_base_image ───────────────────────────────────────────────

const baseImageSchema = z.object({
  image: z
    .string()
    .min(1)
    .max(512)
    .describe("An image reference, e.g. `node:20-alpine` or `ubuntu:24.04@sha256:...`."),
  filename: filenameField,
});

function buildBaseImageTool(deps: ContainerModuleDeps): ToolDefinition {
  return {
    name: "altais_check_base_image",
    title: "Check a container base image",
    description:
      "Assess a base image reference for known issues and bloat: missing version pinning (`latest` / untagged), missing digest pinning, end-of-life base images that no longer receive patches, and full-OS / non-minimal images where a `-slim`, `-alpine`, or distroless variant would cut attack surface.",
    inputSchema: baseImageSchema.shape,
    annotations: COMMON_ANNOTATIONS,
    handler: makeRunner(deps, zodParser(baseImageSchema), (d) => checkBaseImage(d)),
  };
}

export function createContainerModule(deps: ContainerModuleDeps): ModuleDefinition {
  const tools: readonly ToolDefinition[] = [
    buildDockerfileTool(deps),
    buildComposeTool(deps),
    buildBaseImageTool(deps),
  ];
  return {
    name: "container",
    description:
      "Container audits: Dockerfile best practices, Docker Compose misconfigurations, and base image hygiene (version / digest pinning, end-of-life images, image bloat).",
    version: MODULE_VERSION,
    tools,
    init() {
      // No async resources to load.
    },
  };
}
