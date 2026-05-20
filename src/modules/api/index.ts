// API module: 3 auditors for API-layer security — OpenAPI specification
// review, rate-limiting configuration review, and API gateway hardening
// review.

import { z } from "zod";
import type { CallToolResult } from "@modelcontextprotocol/sdk/types.js";

import type { FindingStore } from "../../core/report.js";
import type { Finding, ModuleDefinition, ToolDefinition } from "../../core/types.js";
import { auditApiGateway } from "./gateway.js";
import { auditOpenApi } from "./openapi.js";
import { auditRateLimiting } from "./rate-limiting.js";

const MODULE_VERSION = "0.3.0";

const COMMON_ANNOTATIONS = {
  readOnlyHint: true,
  destructiveHint: false,
  idempotentHint: true,
  openWorldHint: false,
} as const;

export interface ApiModuleDeps {
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
  deps: ApiModuleDeps,
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

// ─── altais_audit_openapi_spec ─────────────────────────────────────────────

const openApiSchema = z.object({
  spec: z
    .string()
    .min(1)
    .max(1024 * 1024)
    .describe("A JSON OpenAPI 3.x document (the contract text). YAML is not supported."),
  filename: filenameField,
});

function buildOpenApiTool(deps: ApiModuleDeps): ToolDefinition {
  const parser = zodParser(openApiSchema);
  return {
    name: "altais_audit_openapi_spec",
    title: "Audit an OpenAPI specification",
    description:
      "Validate a JSON OpenAPI 3.x specification for security gaps: no security scheme defined, weak schemes (HTTP Basic auth, an API key carried in the query string), operations with no security requirement, cleartext `http://` server URLs, operations missing 4xx/5xx error responses, request schemas that allow arbitrary extra properties (mass assignment), request bodies with no schema, and no documented rate limiting (`429`).",
    inputSchema: openApiSchema.shape,
    annotations: COMMON_ANNOTATIONS,
    handler: (args: unknown): CallToolResult => {
      const parsed = parser(args);
      if (!parsed.success) return errorResult(`Invalid input: ${parsed.message}`);
      const result = auditOpenApi(parsed.data);
      if (!result.ok) return errorResult(result.error);
      deps.findingStore.addMany(result.findings);
      return textResult(jsonText(withSummary(result.findings)));
    },
  };
}

// ─── altais_audit_rate_limiting ────────────────────────────────────────────

const rateLimitConfigSchema = z
  .object({
    enabled: z.boolean().optional().describe("Whether rate limiting is enabled."),
    strategy: z
      .enum(["fixed_window", "sliding_window", "token_bucket", "leaky_bucket", "none"])
      .optional()
      .describe("The rate-limiting algorithm in use."),
    scope: z
      .enum(["global", "per_ip", "per_user", "per_api_key"])
      .optional()
      .describe("The dimension the limit is keyed on."),
    limit: z
      .number()
      .int()
      .min(0)
      .max(1_000_000_000)
      .optional()
      .describe("Maximum number of requests allowed per window."),
    window_seconds: z
      .number()
      .int()
      .min(0)
      .max(86_400)
      .optional()
      .describe("Length of the rate-limit window in seconds."),
    applies_to_auth_endpoints: z
      .boolean()
      .optional()
      .describe("Whether authentication endpoints are rate-limited."),
    burst: z
      .number()
      .int()
      .min(0)
      .max(1_000_000)
      .optional()
      .describe("Burst allowance above the steady-state limit."),
    returns_429: z.boolean().optional().describe("Whether throttled requests return HTTP 429."),
    has_retry_after_header: z
      .boolean()
      .optional()
      .describe("Whether throttled responses include a `Retry-After` header."),
  })
  .describe("The rate-limiting configuration to audit.");

const rateLimitSchema = z.object({
  config: rateLimitConfigSchema,
  source: z
    .string()
    .min(1)
    .max(1024 * 1024)
    .optional()
    .describe("Optional source code to scan for known rate-limiting libraries."),
  filename: filenameField,
});

function buildRateLimitTool(deps: ApiModuleDeps): ToolDefinition {
  return {
    name: "altais_audit_rate_limiting",
    title: "Audit rate-limiting configuration",
    description:
      "Check a rate-limiting configuration for gaps: rate limiting disabled or absent, a global-only scope a single client can exhaust, authentication endpoints left unthrottled (credential-stuffing / brute-force risk), a budget too large to constrain abuse, a missing `429` response, and a missing `Retry-After` header. Optionally scans source for known limiter libraries.",
    inputSchema: rateLimitSchema.shape,
    annotations: COMMON_ANNOTATIONS,
    handler: makeRunner(deps, zodParser(rateLimitSchema), (d) => auditRateLimiting(d)),
  };
}

// ─── altais_audit_api_gateway ──────────────────────────────────────────────

const gatewayCorsSchema = z
  .object({
    allow_all_origins: z
      .boolean()
      .optional()
      .describe("Whether the gateway allows any origin (wildcard CORS)."),
    allow_credentials: z
      .boolean()
      .optional()
      .describe("Whether credentialed cross-origin requests are allowed."),
  })
  .describe("The gateway's CORS policy.");

const gatewayConfigSchema = z
  .object({
    authentication_enabled: z
      .boolean()
      .optional()
      .describe("Whether the gateway enforces authentication."),
    authorization_enabled: z
      .boolean()
      .optional()
      .describe("Whether the gateway enforces authorization."),
    tls_enabled: z.boolean().optional().describe("Whether the gateway terminates TLS."),
    min_tls_version: z
      .string()
      .min(1)
      .max(32)
      .optional()
      .describe("Minimum accepted TLS version, e.g. `1.2` or `TLSv1.3`."),
    waf_enabled: z.boolean().optional().describe("Whether a web application firewall is enabled."),
    request_validation: z
      .boolean()
      .optional()
      .describe("Whether the gateway validates requests against a schema."),
    request_size_limit_bytes: z
      .number()
      .int()
      .min(0)
      .max(1_000_000_000_000)
      .optional()
      .describe("Maximum allowed request body size in bytes."),
    timeout_seconds: z
      .number()
      .int()
      .min(0)
      .max(86_400)
      .optional()
      .describe("Request timeout in seconds."),
    rate_limiting_enabled: z
      .boolean()
      .optional()
      .describe("Whether the gateway enforces rate limiting."),
    logging_enabled: z.boolean().optional().describe("Whether the gateway logs access requests."),
    cors: gatewayCorsSchema.optional(),
    ip_allowlist_enabled: z.boolean().optional().describe("Whether an IP allowlist is enforced."),
    mtls_enabled: z.boolean().optional().describe("Whether mutual TLS is enabled for clients."),
    api_keys_rotated: z
      .boolean()
      .optional()
      .describe("Whether API keys are rotated on a schedule."),
    backend_tls: z
      .boolean()
      .optional()
      .describe("Whether gateway-to-backend traffic is encrypted."),
  })
  .describe("The API gateway configuration to audit.");

const gatewaySchema = z.object({
  config: gatewayConfigSchema,
  filename: filenameField,
});

function buildGatewayTool(deps: ApiModuleDeps): ToolDefinition {
  return {
    name: "altais_audit_api_gateway",
    title: "Audit API gateway configuration",
    description:
      "Review an API gateway's security configuration: authentication or authorization disabled, TLS disabled or pinned below 1.2, no WAF, no edge request validation, no request size limit, no or an over-long timeout, rate limiting disabled, access logging disabled, a wildcard CORS origin combined with credentials, and cleartext gateway-to-backend traffic.",
    inputSchema: gatewaySchema.shape,
    annotations: COMMON_ANNOTATIONS,
    handler: makeRunner(deps, zodParser(gatewaySchema), (d) => auditApiGateway(d)),
  };
}

export function createApiModule(deps: ApiModuleDeps): ModuleDefinition {
  const tools: readonly ToolDefinition[] = [
    buildOpenApiTool(deps),
    buildRateLimitTool(deps),
    buildGatewayTool(deps),
  ];
  return {
    name: "api",
    description:
      "API security audits: OpenAPI 3.x specification review (auth schemes, error responses, mass assignment), rate-limiting configuration review, and API gateway hardening review (TLS, WAF, CORS, request validation, backend encryption).",
    version: MODULE_VERSION,
    tools,
    init() {
      // No async resources to load.
    },
  };
}
