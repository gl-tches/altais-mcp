// Headers module: HTTP response header audit, CSP generation, CORS check.

import { z } from "zod";
import type { CallToolResult } from "@modelcontextprotocol/sdk/types.js";

import type { FindingStore } from "../../core/report.js";
import { scanToken } from "../../core/scan-patterns.js";
import type { Finding, ModuleDefinition, ToolDefinition } from "../../core/types.js";
import { auditHeaders } from "./audit.js";
import { checkCors } from "./cors.js";
import { generateCsp } from "./csp.js";

const MODULE_VERSION = "0.1.0";

// CSP dynamic-code source keyword, assembled from data/scan-patterns.json.
const UNSAFE_EVAL = `'unsafe-${scanToken("js-dynamic-code")}'`;

const COMMON_ANNOTATIONS = {
  readOnlyHint: true,
  destructiveHint: false,
  idempotentHint: true,
  openWorldHint: false,
} as const;

export interface HeadersModuleDeps {
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

const headerMapSchema = z
  .record(z.string().min(1).max(256), z.string().max(8192))
  .describe("HTTP response headers as a key/value map (case-insensitive).");

function buildAuditTool(deps: HeadersModuleDeps): ToolDefinition {
  const inputSchema = {
    headers: headerMapSchema,
    context: z
      .enum(["html-app", "api", "static-asset"])
      .default("html-app")
      .describe("Hint that adjusts which headers are required."),
    source: z
      .string()
      .min(1)
      .max(512)
      .optional()
      .describe("Optional label (URL or filename) used for finding location."),
  };
  return {
    name: "altais_audit_headers",
    title: "Audit HTTP response headers",
    description:
      "Check a response header map against current best practice. Validates CSP, HSTS, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy, basic CORS, Set-Cookie attributes, and server-identity leaks. Returns one Finding per problem.",
    inputSchema,
    annotations: COMMON_ANNOTATIONS,
    handler: (args) => {
      const parsed = z.object(inputSchema).safeParse(args);
      if (!parsed.success) {
        return errorResult(
          `Invalid input: ${parsed.error.issues
            .map((i) => `${i.path.join(".") || "<root>"}: ${i.message}`)
            .join("; ")}`,
        );
      }
      const findings = auditHeaders({
        headers: parsed.data.headers,
        context: parsed.data.context,
        ...(parsed.data.source !== undefined ? { source: parsed.data.source } : {}),
      });
      deps.findingStore.addMany(findings);
      return textResult(jsonText({ summary: summarize(findings), findings }));
    },
  };
}

function buildGenerateCspTool(): ToolDefinition {
  const sourceList = z.array(z.string().min(1).max(512)).max(128).optional();
  const inputSchema = {
    mode: z
      .enum(["strict", "compatible"])
      .default("strict")
      .describe("'strict' uses default-src 'none'; 'compatible' uses default-src 'self'."),
    requires_inline_scripts: z.boolean().default(false),
    requires_inline_styles: z.boolean().default(false),
    external_scripts: sourceList,
    external_styles: sourceList,
    external_images: sourceList,
    external_fonts: sourceList,
    external_connections: sourceList,
    external_frames: sourceList,
    use_workers: z.boolean().default(false),
    allow_form_actions: sourceList,
    report_uri: z.string().min(1).max(512).optional(),
    report_to: z.string().min(1).max(128).optional(),
  };
  return {
    name: "altais_generate_csp",
    title: "Generate a Content-Security-Policy header",
    description: `Build a CSP header from a high-level description of what the app loads. The generator never emits \`'unsafe-inline'\` or \`${UNSAFE_EVAL}\`; when those would be needed, it returns a \`recommendations\` array suggesting a nonce/hash-based alternative.`,
    inputSchema,
    annotations: COMMON_ANNOTATIONS,
    handler: (args) => {
      const parsed = z.object(inputSchema).safeParse(args);
      if (!parsed.success) {
        return errorResult(
          `Invalid input: ${parsed.error.issues
            .map((i) => `${i.path.join(".") || "<root>"}: ${i.message}`)
            .join("; ")}`,
        );
      }
      const result = generateCsp(parsed.data);
      return textResult(jsonText(result));
    },
  };
}

function buildCheckCorsTool(deps: HeadersModuleDeps): ToolDefinition {
  const inputSchema = {
    headers: headerMapSchema.optional(),
    config: z
      .object({
        allowed_origins: z.array(z.string().min(1).max(256)).max(128).optional(),
        reflect_origin: z.boolean().optional(),
        allow_credentials: z.boolean().optional(),
        allowed_methods: z.array(z.string().min(1).max(16)).max(16).optional(),
        allowed_headers: z.array(z.string().min(1).max(128)).max(64).optional(),
        expose_headers: z.array(z.string().min(1).max(128)).max(64).optional(),
        max_age_seconds: z.number().int().min(0).max(31_536_000).optional(),
        vary_origin: z.boolean().optional(),
      })
      .optional()
      .describe("Structured CORS policy. Provide this or `headers`."),
    source: z
      .string()
      .min(1)
      .max(512)
      .optional()
      .describe("Optional label used for finding location."),
  };
  return {
    name: "altais_check_cors",
    title: "Validate CORS configuration",
    description:
      "Validate a CORS policy expressed as either an HTTP header map or a structured config object. Flags wildcard origins combined with credentials, unsafe origin reflection, the literal `null` origin, wildcard methods/headers, excessive max-age, and missing `Vary: Origin`.",
    inputSchema,
    annotations: COMMON_ANNOTATIONS,
    handler: (args) => {
      const parsed = z.object(inputSchema).safeParse(args);
      if (!parsed.success) {
        return errorResult(
          `Invalid input: ${parsed.error.issues
            .map((i) => `${i.path.join(".") || "<root>"}: ${i.message}`)
            .join("; ")}`,
        );
      }
      if (!parsed.data.headers && !parsed.data.config) {
        return errorResult("Provide at least one of `headers` or `config`.");
      }
      const findings = checkCors({
        ...(parsed.data.headers !== undefined ? { headers: parsed.data.headers } : {}),
        ...(parsed.data.config !== undefined ? { config: parsed.data.config } : {}),
        ...(parsed.data.source !== undefined ? { source: parsed.data.source } : {}),
      });
      deps.findingStore.addMany(findings);
      return textResult(jsonText({ summary: summarize(findings), findings }));
    },
  };
}

export function createHeadersModule(deps: HeadersModuleDeps): ModuleDefinition {
  const tools: readonly ToolDefinition[] = [
    buildAuditTool(deps),
    buildGenerateCspTool(),
    buildCheckCorsTool(deps),
  ];
  return {
    name: "headers",
    description: "HTTP response header audit, CSP generation, and CORS validation.",
    version: MODULE_VERSION,
    tools,
    init() {
      // No async resources to load.
    },
  };
}
