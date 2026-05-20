// Protocol module: 7 auditors for application- and transport-protocol
// security — deep TLS / mTLS configuration, webhook signature
// verification, email authentication (SPF / DKIM / DMARC), WebSocket
// security, GraphQL security, gRPC security, and Server-Sent Events.

import { z } from "zod";
import type { CallToolResult } from "@modelcontextprotocol/sdk/types.js";

import type { FindingStore } from "../../core/report.js";
import type { Finding, ModuleDefinition, ToolDefinition } from "../../core/types.js";
import { auditEmailSecurity } from "./email.js";
import { auditGraphQl } from "./graphql.js";
import { auditGrpc } from "./grpc.js";
import { auditSse } from "./sse.js";
import { auditTlsConfig } from "./tls-config.js";
import { auditWebSocket } from "./websocket.js";
import { checkWebhook } from "./webhook.js";

const MODULE_VERSION = "0.4.0";

const COMMON_ANNOTATIONS = {
  readOnlyHint: true,
  destructiveHint: false,
  idempotentHint: true,
  openWorldHint: false,
} as const;

export interface ProtocolModuleDeps {
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
  deps: ProtocolModuleDeps,
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
  .optional()
  .describe("Source code that configures the protocol, scanned with pattern matching.");

// ─── altais_audit_tls_config ───────────────────────────────────────────────

const tlsVersionEnum = z.enum(["SSLv2", "SSLv3", "TLSv1.0", "TLSv1.1", "TLSv1.2", "TLSv1.3"]);

const tlsConfigSchema = z.object({
  config: z
    .object({
      min_version: tlsVersionEnum
        .optional()
        .describe("Lowest TLS/SSL version the endpoint accepts."),
      enabled_versions: z
        .array(tlsVersionEnum)
        .max(6)
        .optional()
        .describe("All TLS/SSL versions the endpoint will negotiate."),
      cipher_suites: z
        .array(z.string().min(1).max(128))
        .max(128)
        .optional()
        .describe("Configured cipher suite names (IANA or OpenSSL form)."),
      mtls_enabled: z.boolean().optional().describe("Whether mutual TLS is configured."),
      client_cert_required: z
        .boolean()
        .optional()
        .describe("Whether a valid client certificate is mandatory to complete the handshake."),
      ocsp_stapling: z
        .boolean()
        .optional()
        .describe("Whether the server staples an OCSP response."),
      session_resumption: z
        .enum(["none", "session_id", "session_ticket", "tls13_psk"])
        .optional()
        .describe("Session resumption mechanism in use."),
      forward_secrecy: z
        .boolean()
        .optional()
        .describe("Whether the negotiated key exchange provides forward secrecy."),
      cert_signature_algorithm: z
        .string()
        .min(1)
        .max(64)
        .optional()
        .describe("Signature algorithm of the server certificate (e.g. `sha256WithRSA`)."),
      hsts: z.boolean().optional().describe("Whether HSTS is sent for the endpoint."),
      certificate_transparency: z
        .boolean()
        .optional()
        .describe("Whether Certificate Transparency (SCTs) is enforced."),
    })
    .describe("Structured TLS / mTLS configuration to audit."),
  filename: filenameField,
});

function buildTlsConfigTool(deps: ProtocolModuleDeps): ToolDefinition {
  return {
    name: "altais_audit_tls_config",
    title: "Deep TLS / mTLS configuration audit",
    description:
      "Audit a structured TLS / mutual-TLS configuration against RFC 9325 and RFC 8996: deprecated SSLv3 / TLS 1.0 / 1.1, no TLS 1.3, weak or non-AEAD cipher suites, missing forward secrecy, OCSP stapling disabled, insecure session resumption, weak certificate signature algorithms (SHA-1 / MD5), mutual TLS enabled but the client certificate not required, missing HSTS, and missing Certificate Transparency.",
    inputSchema: tlsConfigSchema.shape,
    annotations: COMMON_ANNOTATIONS,
    handler: makeRunner(deps, zodParser(tlsConfigSchema), (d) => auditTlsConfig(d)),
  };
}

// ─── altais_check_webhook ──────────────────────────────────────────────────

const webhookSchema = z
  .object({
    source: sourceField,
    config: z
      .object({
        signature_verified: z
          .boolean()
          .optional()
          .describe("Whether the inbound signature is verified before processing."),
        hash_algorithm: z
          .string()
          .min(1)
          .max(32)
          .optional()
          .describe("Hash algorithm backing the HMAC signature."),
        constant_time_comparison: z
          .boolean()
          .optional()
          .describe("Whether the signature is compared in constant time."),
        timestamp_validation: z
          .boolean()
          .optional()
          .describe("Whether a signed timestamp is checked against a tolerance window."),
        replay_protection: z
          .boolean()
          .optional()
          .describe("Whether delivery IDs / nonces are de-duplicated to block replays."),
        secret_source: z
          .enum(["env", "secrets_manager", "config_file", "hardcoded"])
          .optional()
          .describe("Where the webhook signing secret is loaded from."),
      })
      .optional()
      .describe("Structured description of the webhook verification posture."),
    filename: filenameField,
  })
  .refine((v) => v.source !== undefined || v.config !== undefined, {
    message: "Provide `source`, `config`, or both.",
  });

function buildWebhookTool(deps: ProtocolModuleDeps): ToolDefinition {
  return {
    name: "altais_check_webhook",
    title: "Verify webhook signature handling",
    description:
      "Verify a webhook receiver's HMAC signature implementation. Provide handler `source` and/or a structured `config`. Flags: no signature verification, a signature compared with `==` / `===` instead of a constant-time compare, weak hash algorithms (MD5 / SHA-1), missing timestamp validation, missing replay protection, and a hardcoded signing secret.",
    inputSchema: webhookSchema.shape,
    annotations: COMMON_ANNOTATIONS,
    handler: makeRunner(deps, zodParser(webhookSchema), (d) => checkWebhook(d)),
  };
}

// ─── altais_audit_email_security ───────────────────────────────────────────

const emailSchema = z.object({
  config: z
    .object({
      spf_record: z
        .string()
        .min(1)
        .max(2048)
        .optional()
        .describe("The domain's published SPF TXT record."),
      dkim_enabled: z.boolean().optional().describe("Whether DKIM signing is configured."),
      dkim_selectors: z
        .array(z.string().min(1).max(128))
        .max(32)
        .optional()
        .describe("Published DKIM selectors."),
      dmarc_record: z
        .string()
        .min(1)
        .max(2048)
        .optional()
        .describe("The domain's published DMARC TXT record."),
      dmarc_policy: z
        .enum(["none", "quarantine", "reject"])
        .optional()
        .describe("The DMARC `p=` policy."),
      mta_sts: z.boolean().optional().describe("Whether SMTP MTA-STS is enabled."),
      dnssec: z.boolean().optional().describe("Whether the zone is signed with DNSSEC."),
    })
    .describe("Structured email-authentication posture for a domain."),
  filename: filenameField,
});

function buildEmailTool(deps: ProtocolModuleDeps): ToolDefinition {
  return {
    name: "altais_audit_email_security",
    title: "Audit SPF / DKIM / DMARC email authentication",
    description:
      "Audit a domain's email-authentication posture. Parses the SPF and DMARC record strings and flags: missing SPF, an SPF record ending in `+all` / `?all` or with no terminating `all`, missing DKIM, missing DMARC, a `p=none` DMARC policy, no `rua` aggregate reporting, missing MTA-STS, and a domain without DNSSEC.",
    inputSchema: emailSchema.shape,
    annotations: COMMON_ANNOTATIONS,
    handler: makeRunner(deps, zodParser(emailSchema), (d) => auditEmailSecurity(d)),
  };
}

// ─── altais_audit_websocket ────────────────────────────────────────────────

const websocketSchema = z
  .object({
    source: sourceField,
    config: z
      .object({
        tls: z.boolean().optional().describe("Whether the endpoint uses `wss://` (TLS)."),
        origin_validation: z
          .boolean()
          .optional()
          .describe("Whether the upgrade handshake validates the Origin header."),
        authentication: z.boolean().optional().describe("Whether the connection is authenticated."),
        message_size_limit: z
          .boolean()
          .optional()
          .describe("Whether a maximum message / frame size is enforced."),
        rate_limiting: z
          .boolean()
          .optional()
          .describe("Whether per-connection rate limiting is applied."),
        csrf_protection: z
          .boolean()
          .optional()
          .describe("Whether a per-session CSRF token is required on the handshake."),
      })
      .optional()
      .describe("Structured description of the WebSocket posture."),
    filename: filenameField,
  })
  .refine((v) => v.source !== undefined || v.config !== undefined, {
    message: "Provide `source`, `config`, or both.",
  });

function buildWebSocketTool(deps: ProtocolModuleDeps): ToolDefinition {
  return {
    name: "altais_audit_websocket",
    title: "Review WebSocket security",
    description:
      "Review a WebSocket server or client. Provide `source` and/or a structured `config`. Flags: plaintext `ws://` instead of `wss://`, no Origin validation on the upgrade handshake (Cross-Site WebSocket Hijacking), no authentication, unbounded message size, and no rate limiting.",
    inputSchema: websocketSchema.shape,
    annotations: COMMON_ANNOTATIONS,
    handler: makeRunner(deps, zodParser(websocketSchema), (d) => auditWebSocket(d)),
  };
}

// ─── altais_audit_graphql ──────────────────────────────────────────────────

const graphqlSchema = z
  .object({
    source: sourceField,
    config: z
      .object({
        introspection_enabled: z
          .boolean()
          .optional()
          .describe("Whether schema introspection is enabled."),
        query_depth_limit: z
          .boolean()
          .optional()
          .describe("Whether a maximum query depth is enforced."),
        query_complexity_limit: z
          .boolean()
          .optional()
          .describe("Whether a query complexity / cost limit is enforced."),
        batching_enabled: z
          .boolean()
          .optional()
          .describe("Whether array-form query batching is enabled."),
        field_suggestions: z
          .boolean()
          .optional()
          .describe("Whether 'did you mean' field suggestions are returned."),
        rate_limiting: z
          .boolean()
          .optional()
          .describe("Whether the GraphQL endpoint is rate limited."),
        production: z
          .boolean()
          .optional()
          .describe("Whether this configuration is a production deployment."),
      })
      .optional()
      .describe("Structured description of the GraphQL posture."),
    filename: filenameField,
  })
  .refine((v) => v.source !== undefined || v.config !== undefined, {
    message: "Provide `source`, `config`, or both.",
  });

function buildGraphQlTool(deps: ProtocolModuleDeps): ToolDefinition {
  return {
    name: "altais_audit_graphql",
    title: "Audit GraphQL API security",
    description:
      "Audit a GraphQL API. Provide `source` and/or a structured `config`. Flags: introspection enabled in production, no query-depth limit, no complexity / cost limit, query batching enabled (batching attacks), field suggestions enabled (schema leak), and no rate limiting.",
    inputSchema: graphqlSchema.shape,
    annotations: COMMON_ANNOTATIONS,
    handler: makeRunner(deps, zodParser(graphqlSchema), (d) => auditGraphQl(d)),
  };
}

// ─── altais_audit_grpc ─────────────────────────────────────────────────────

const grpcSchema = z
  .object({
    source: sourceField,
    config: z
      .object({
        tls_enabled: z.boolean().optional().describe("Whether the channel uses TLS credentials."),
        insecure_channel: z
          .boolean()
          .optional()
          .describe("Whether an explicitly insecure channel is used."),
        auth_interceptor: z
          .boolean()
          .optional()
          .describe("Whether a server authentication interceptor is installed."),
        deadline_propagation: z
          .boolean()
          .optional()
          .describe("Whether calls set and propagate a deadline."),
        reflection_enabled: z
          .boolean()
          .optional()
          .describe("Whether gRPC server reflection is registered."),
        max_message_size: z
          .boolean()
          .optional()
          .describe("Whether a bounded maximum message size is enforced."),
        production: z
          .boolean()
          .optional()
          .describe("Whether this configuration is a production deployment."),
      })
      .optional()
      .describe("Structured description of the gRPC posture."),
    filename: filenameField,
  })
  .refine((v) => v.source !== undefined || v.config !== undefined, {
    message: "Provide `source`, `config`, or both.",
  });

function buildGrpcTool(deps: ProtocolModuleDeps): ToolDefinition {
  return {
    name: "altais_audit_grpc",
    title: "Audit gRPC service security",
    description:
      "Audit a gRPC service or client. Provide `source` and/or a structured `config`. Flags: an insecure (plaintext) channel with no TLS, no authentication interceptor, no deadline / timeout propagation, server reflection enabled in production, and unbounded message size.",
    inputSchema: grpcSchema.shape,
    annotations: COMMON_ANNOTATIONS,
    handler: makeRunner(deps, zodParser(grpcSchema), (d) => auditGrpc(d)),
  };
}

// ─── altais_audit_sse ──────────────────────────────────────────────────────

const sseSchema = z
  .object({
    source: sourceField,
    config: z
      .object({
        origin_validation: z
          .boolean()
          .optional()
          .describe("Whether the SSE endpoint validates the Origin header."),
        authentication: z
          .boolean()
          .optional()
          .describe("Whether the SSE endpoint is authenticated."),
        tls: z.boolean().optional().describe("Whether the SSE endpoint is served over HTTPS."),
        reconnection_backoff: z
          .boolean()
          .optional()
          .describe("Whether a reconnection backoff / `retry:` interval is used."),
        cors_restricted: z
          .boolean()
          .optional()
          .describe("Whether CORS on the endpoint is restricted to an allowlist."),
        per_connection_limit: z
          .boolean()
          .optional()
          .describe("Whether a per-client concurrent connection cap is enforced."),
      })
      .optional()
      .describe("Structured description of the Server-Sent Events posture."),
    filename: filenameField,
  })
  .refine((v) => v.source !== undefined || v.config !== undefined, {
    message: "Provide `source`, `config`, or both.",
  });

function buildSseTool(deps: ProtocolModuleDeps): ToolDefinition {
  return {
    name: "altais_audit_sse",
    title: "Audit Server-Sent Events security",
    description:
      "Audit a Server-Sent Events (`text/event-stream`) endpoint. Provide `source` and/or a structured `config`. Flags: no Origin validation, missing authentication, plaintext `http://` instead of `https://`, no reconnection backoff (reconnection storms), unrestricted CORS on the event-stream endpoint, and no per-client connection cap.",
    inputSchema: sseSchema.shape,
    annotations: COMMON_ANNOTATIONS,
    handler: makeRunner(deps, zodParser(sseSchema), (d) => auditSse(d)),
  };
}

export function createProtocolModule(deps: ProtocolModuleDeps): ModuleDefinition {
  const tools: readonly ToolDefinition[] = [
    buildTlsConfigTool(deps),
    buildWebhookTool(deps),
    buildEmailTool(deps),
    buildWebSocketTool(deps),
    buildGraphQlTool(deps),
    buildGrpcTool(deps),
    buildSseTool(deps),
  ];
  return {
    name: "protocol",
    description:
      "Protocol audits: deep TLS / mTLS configuration, webhook signature verification, email authentication (SPF / DKIM / DMARC), WebSocket security, GraphQL security, gRPC security, and Server-Sent Events.",
    version: MODULE_VERSION,
    tools,
    init() {
      // No async resources to load.
    },
  };
}
