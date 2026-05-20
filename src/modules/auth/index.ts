// Auth module: 10 auditors for OAuth, JWT, session, CSRF, password
// hashing, RBAC, passkeys, NHI, secret lifecycle, NHI isolation.

import { z } from "zod";
import type { CallToolResult } from "@modelcontextprotocol/sdk/types.js";

import type { FindingStore } from "../../core/report.js";
import type { Finding, ModuleDefinition, ToolDefinition } from "../../core/types.js";
import { auditCsrf } from "./csrf.js";
import { auditJwt } from "./jwt.js";
import { auditNhi } from "./nhi.js";
import { checkNhiIsolation } from "./nhi-isolation.js";
import { auditOAuth } from "./oauth.js";
import { auditPasskey } from "./passkey.js";
import { auditPasswordHashing } from "./password.js";
import { auditRbac } from "./rbac.js";
import { auditSecretLifecycle } from "./secret-lifecycle.js";
import { auditSession } from "./session.js";

const MODULE_VERSION = "0.2.0";

const COMMON_ANNOTATIONS = {
  readOnlyHint: true,
  destructiveHint: false,
  idempotentHint: true,
  openWorldHint: false,
} as const;

export interface AuthModuleDeps {
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

const sourceField = z
  .string()
  .min(1)
  .max(2 * 1024 * 1024)
  .optional()
  .describe("Optional source code to scan with pattern checks.");

const filenameField = z
  .string()
  .min(1)
  .max(512)
  .optional()
  .describe("Optional filename for finding location.");

function makeRunner<TInput>(
  deps: AuthModuleDeps,
  parser: (args: unknown) => { success: true; data: TInput } | { success: false; message: string },
  run: (data: TInput) => readonly Finding[],
  shape: (findings: readonly Finding[], data: TInput) => unknown,
): (args: unknown) => CallToolResult {
  return (args: unknown) => {
    const parsed = parser(args);
    if (!parsed.success) return errorResult(`Invalid input: ${parsed.message}`);
    const findings = run(parsed.data);
    deps.findingStore.addMany(findings);
    return textResult(jsonText(shape(findings, parsed.data)));
  };
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

// ─── altais_audit_oauth ────────────────────────────────────────────────────

const oauthConfigSchema = z
  .object({
    flow: z
      .enum(["authorization_code", "client_credentials", "device_code", "implicit", "password"])
      .optional(),
    pkce: z
      .object({
        used: z.boolean(),
        method: z.enum(["S256", "plain"]).optional(),
      })
      .optional(),
    redirect_uris: z.array(z.string().min(1).max(2048)).max(32).optional(),
    uses_state: z.boolean().optional(),
    uses_nonce_for_oidc: z.boolean().optional(),
    token_endpoint_auth: z
      .enum(["client_secret_post", "client_secret_basic", "private_key_jwt", "none"])
      .optional(),
    token_storage: z
      .enum(["httponly_cookie", "memory", "localStorage", "sessionStorage"])
      .optional(),
    refresh_token_rotation: z.boolean().optional(),
    scope: z.array(z.string().min(1).max(64)).max(64).optional(),
  })
  .optional();

const oauthSchema = z.object({
  source: sourceField,
  filename: filenameField,
  config: oauthConfigSchema,
});

function buildOauthTool(deps: AuthModuleDeps): ToolDefinition {
  return {
    name: "altais_audit_oauth",
    title: "Audit an OAuth 2.1 / OIDC implementation",
    description:
      "Run OAuth 2.1 / OIDC checks against either source code (pattern-based) or a structured config. Flags implicit / password grants, missing PKCE / PKCE=plain, wildcard redirect URIs, missing state / nonce, tokens in localStorage, and refresh-token rotation gaps.",
    inputSchema: oauthSchema.shape,
    annotations: COMMON_ANNOTATIONS,
    handler: makeRunner(
      deps,
      zodParser(oauthSchema),
      (d) => auditOAuth(d),
      (findings) => ({ summary: summarize(findings), findings }),
    ),
  };
}

// ─── altais_audit_jwt ──────────────────────────────────────────────────────

const jwtSchema = z.object({
  source: sourceField,
  filename: filenameField,
  token: z.string().min(1).max(16384).optional().describe("Optional JWT to decode + check."),
  config: z
    .object({
      accepted_algorithms: z.array(z.string().min(1).max(16)).max(32).optional(),
      required_iss: z.array(z.string().min(1).max(256)).max(16).optional(),
      required_aud: z.array(z.string().min(1).max(256)).max(16).optional(),
      clock_skew_seconds: z.number().int().min(0).max(3600).optional(),
      verify_exp: z.boolean().optional(),
      verify_nbf: z.boolean().optional(),
      jwks_uri: z.string().min(1).max(1024).optional(),
    })
    .optional(),
});

function buildJwtTool(deps: AuthModuleDeps): ToolDefinition {
  return {
    name: "altais_audit_jwt",
    title: "Audit JWT usage",
    description:
      "Scan code for JWT library misuse, decode an actual token to inspect its claims, and / or audit the verifier config. Flags alg:none, missing algorithms allowlist, HS-with-RS confusion, missing exp / aud / iss, and long-lived tokens.",
    inputSchema: jwtSchema.shape,
    annotations: COMMON_ANNOTATIONS,
    handler: makeRunner(
      deps,
      zodParser(jwtSchema),
      (d) => auditJwt(d),
      (findings) => ({ summary: summarize(findings), findings }),
    ),
  };
}

// ─── altais_audit_session ──────────────────────────────────────────────────

const sessionSchema = z.object({
  source: sourceField,
  filename: filenameField,
  config: z
    .object({
      cookie: z
        .object({
          secure: z.boolean().optional(),
          httpOnly: z.boolean().optional(),
          sameSite: z.union([z.enum(["Strict", "Lax", "None"]), z.literal(false)]).optional(),
          maxAgeSeconds: z.number().int().min(0).max(31_536_000).optional(),
          domain: z.string().min(1).max(256).optional(),
        })
        .optional(),
      regenerate_on_login: z.boolean().optional(),
      invalidate_on_logout: z.boolean().optional(),
      absolute_timeout_seconds: z.number().int().min(0).max(31_536_000).optional(),
      idle_timeout_seconds: z.number().int().min(0).max(31_536_000).optional(),
      id_entropy_bits: z.number().int().min(0).max(1024).optional(),
    })
    .optional(),
});

function buildSessionTool(deps: AuthModuleDeps): ToolDefinition {
  return {
    name: "altais_audit_session",
    title: "Audit session management",
    description:
      "Check session flags (Secure / HttpOnly / SameSite), regeneration on login, invalidation on logout, absolute / idle timeouts, and session-ID entropy. Accepts source code patterns or a structured config.",
    inputSchema: sessionSchema.shape,
    annotations: COMMON_ANNOTATIONS,
    handler: makeRunner(
      deps,
      zodParser(sessionSchema),
      (d) => auditSession(d),
      (findings) => ({ summary: summarize(findings), findings }),
    ),
  };
}

// ─── altais_audit_csrf ─────────────────────────────────────────────────────

const csrfSchema = z.object({
  source: sourceField,
  filename: filenameField,
  config: z
    .object({
      auth_via: z.enum(["cookie", "bearer", "mixed"]).optional(),
      samesite: z.union([z.enum(["Strict", "Lax", "None"]), z.literal(false)]).optional(),
      csrf_token: z.enum(["synchronizer", "double_submit", "none"]).optional(),
      checks_origin_header: z.boolean().optional(),
      state_changing_methods: z
        .array(z.enum(["POST", "PUT", "PATCH", "DELETE"]))
        .max(8)
        .optional(),
    })
    .optional(),
});

function buildCsrfTool(deps: AuthModuleDeps): ToolDefinition {
  return {
    name: "altais_audit_csrf",
    title: "Audit CSRF protections",
    description:
      "Verify that state-changing endpoints are defended: SameSite cookies, CSRF tokens (synchronizer or double-submit), or Origin/Referer checks.",
    inputSchema: csrfSchema.shape,
    annotations: COMMON_ANNOTATIONS,
    handler: makeRunner(
      deps,
      zodParser(csrfSchema),
      (d) => auditCsrf(d),
      (findings) => ({ summary: summarize(findings), findings }),
    ),
  };
}

// ─── altais_audit_password_hashing ─────────────────────────────────────────

const passwordSchema = z.object({
  source: z
    .string()
    .min(1)
    .max(2 * 1024 * 1024),
  filename: filenameField,
});

function buildPasswordTool(deps: AuthModuleDeps): ToolDefinition {
  return {
    name: "altais_audit_password_hashing",
    title: "Audit password hashing",
    description:
      "Scan source for password-hashing patterns. Flags fast hashes (MD5/SHA-*) used in a password context. Notes the presence (or absence) of Argon2 / bcrypt / scrypt.",
    inputSchema: passwordSchema.shape,
    annotations: COMMON_ANNOTATIONS,
    handler: makeRunner(
      deps,
      zodParser(passwordSchema),
      (d) => auditPasswordHashing(d),
      (findings) => ({ summary: summarize(findings), findings }),
    ),
  };
}

// ─── altais_audit_rbac ─────────────────────────────────────────────────────

const rbacSchema = z.object({
  filename: filenameField,
  policy: z.object({
    model: z.enum(["rbac", "abac", "rebac"]).optional(),
    default: z.enum(["allow", "deny"]).optional(),
    roles: z
      .array(
        z.object({
          name: z.string().min(1).max(128),
          description: z.string().max(1024).optional(),
          inherits: z.array(z.string().min(1).max(128)).max(32).optional(),
          permissions: z
            .array(
              z.union([
                z.string().min(1).max(128),
                z.object({
                  resource: z.string().min(1).max(128),
                  action: z.string().min(1).max(64),
                }),
              ]),
            )
            .max(256),
        }),
      )
      .max(256),
    assignments: z
      .array(z.object({ user: z.string().min(1).max(256), role: z.string().min(1).max(128) }))
      .max(2000)
      .optional(),
  }),
});

function buildRbacTool(deps: AuthModuleDeps): ToolDefinition {
  return {
    name: "altais_audit_rbac",
    title: "Audit an RBAC / ABAC policy",
    description:
      "Inspect a structured policy for default-allow, superuser roles (`*:*`), wildcards on dangerous resources, self-elevation paths (a role that can grant roles), inheritance cycles, and dangling parents.",
    inputSchema: rbacSchema.shape,
    annotations: COMMON_ANNOTATIONS,
    handler: makeRunner(
      deps,
      zodParser(rbacSchema),
      (d) => auditRbac(d),
      (findings) => ({ summary: summarize(findings), findings }),
    ),
  };
}

// ─── altais_audit_passkey_impl ─────────────────────────────────────────────

const passkeySchema = z.object({
  source: sourceField,
  filename: filenameField,
  config: z
    .object({
      rp_id: z.string().min(1).max(256).optional(),
      user_verification: z.enum(["required", "preferred", "discouraged"]).optional(),
      resident_key: z.enum(["required", "preferred", "discouraged"]).optional(),
      attestation: z.enum(["none", "indirect", "direct", "enterprise"]).optional(),
      origins: z.array(z.string().min(1).max(512)).max(32).optional(),
      challenge_entropy_bits: z.number().int().min(0).max(4096).optional(),
      stores_credential_id: z.boolean().optional(),
      stores_aaguid: z.boolean().optional(),
      stores_sign_count: z.boolean().optional(),
    })
    .optional(),
});

function buildPasskeyTool(deps: AuthModuleDeps): ToolDefinition {
  return {
    name: "altais_audit_passkey_impl",
    title: "Audit a FIDO2 / passkey implementation",
    description:
      "Check WebAuthn / passkey configuration and source for: rp_id-origin alignment, userVerification, challenge entropy, attestation policy, sign-count tracking, and missing server-issued challenges.",
    inputSchema: passkeySchema.shape,
    annotations: COMMON_ANNOTATIONS,
    handler: makeRunner(
      deps,
      zodParser(passkeySchema),
      (d) => auditPasskey(d),
      (findings) => ({ summary: summarize(findings), findings }),
    ),
  };
}

// ─── altais_audit_nhi ──────────────────────────────────────────────────────

const nhiSchema = z.object({
  filename: filenameField,
  identities: z
    .array(
      z.object({
        name: z.string().min(1).max(256),
        kind: z.enum([
          "service_account",
          "api_key",
          "machine_user",
          "ci_runner",
          "workload_identity",
          "bot_account",
          "other",
        ]),
        environment: z.string().min(1).max(64).optional(),
        owner: z.string().min(1).max(256).optional(),
        credential_type: z
          .enum(["static_key", "oidc", "workload_identity", "mTLS", "password"])
          .optional(),
        credential_age_days: z.number().int().min(0).max(10_000).optional(),
        rotation_period_days: z.number().int().min(0).max(10_000).optional(),
        scopes: z.array(z.string().min(1).max(256)).max(256).optional(),
        scoped_to_resources: z.array(z.string().min(1).max(256)).max(256).optional(),
        expires_at: z.string().min(1).max(64).optional(),
        mfa_enabled: z.boolean().optional(),
        stored_in_repo: z.boolean().optional(),
        stored_in_env_vars: z.boolean().optional(),
      }),
    )
    .min(1)
    .max(1000),
});

function buildNhiTool(deps: AuthModuleDeps): ToolDefinition {
  return {
    name: "altais_audit_nhi",
    title: "Audit non-human identities (OWASP NHI Top 10)",
    description:
      "For each non-human identity (service account, API key, CI runner, ...), check against the OWASP NHI Top 10: missing owner, static keys, overdue rotation, wildcard scope, credentials in repo, no expiry, password credentials.",
    inputSchema: nhiSchema.shape,
    annotations: COMMON_ANNOTATIONS,
    handler: makeRunner(
      deps,
      zodParser(nhiSchema),
      (d) => auditNhi(d),
      (findings) => ({ summary: summarize(findings), findings }),
    ),
  };
}

// ─── altais_check_secret_lifecycle ─────────────────────────────────────────

const secretLifecycleSchema = z.object({
  filename: filenameField,
  secrets: z
    .array(
      z.object({
        name: z.string().min(1).max(256),
        kind: z.enum([
          "api_key",
          "oauth_client_secret",
          "signing_key",
          "encryption_key",
          "password",
          "webhook",
        ]),
        owner: z.string().min(1).max(256).optional(),
        created_at: z.string().min(1).max(64).optional(),
        last_rotated_at: z.string().min(1).max(64).optional(),
        expires_at: z.string().min(1).max(64).optional(),
        rotation_period_days: z.number().int().min(0).max(10_000).optional(),
        revocation_procedure_documented: z.boolean().optional(),
        audit_logged: z.boolean().optional(),
        stored_in: z
          .enum(["vault", "secrets_manager", "env_var", "repo", "file_on_disk"])
          .optional(),
      }),
    )
    .min(1)
    .max(2000),
});

function buildSecretLifecycleTool(deps: AuthModuleDeps): ToolDefinition {
  return {
    name: "altais_check_secret_lifecycle",
    title: "Check secret rotation / expiry / revocation",
    description:
      "Audit a structured list of secrets for: rotation past the kind-specific threshold, never-rotated long-lived secrets, missing expiry, expired-but-still-listed secrets, undocumented revocation procedures, and missing audit logging.",
    inputSchema: secretLifecycleSchema.shape,
    annotations: COMMON_ANNOTATIONS,
    handler: makeRunner(
      deps,
      zodParser(secretLifecycleSchema),
      (d) => auditSecretLifecycle(d),
      (findings) => ({ summary: summarize(findings), findings }),
    ),
  };
}

// ─── altais_check_nhi_isolation ────────────────────────────────────────────

const nhiIsolationSchema = z.object({
  filename: filenameField,
  identities: z
    .array(
      z.object({
        name: z.string().min(1).max(256),
        environment: z.string().min(1).max(64).optional(),
        namespace: z.string().min(1).max(128).optional(),
        project: z.string().min(1).max(128).optional(),
        scopes: z.array(z.string().min(1).max(256)).max(256).optional(),
        cross_environment_access: z.array(z.string().min(1).max(64)).max(16).optional(),
      }),
    )
    .min(1)
    .max(1000),
});

function buildNhiIsolationTool(deps: AuthModuleDeps): ToolDefinition {
  return {
    name: "altais_check_nhi_isolation",
    title: "Check NHI environment isolation",
    description:
      "Verify that non-human identities are scoped to a single environment / namespace / project, and flag any pre-prod identity that can reach prod (or vice-versa).",
    inputSchema: nhiIsolationSchema.shape,
    annotations: COMMON_ANNOTATIONS,
    handler: makeRunner(
      deps,
      zodParser(nhiIsolationSchema),
      (d) => checkNhiIsolation(d),
      (findings) => ({ summary: summarize(findings), findings }),
    ),
  };
}

export function createAuthModule(deps: AuthModuleDeps): ModuleDefinition {
  const tools: readonly ToolDefinition[] = [
    buildOauthTool(deps),
    buildJwtTool(deps),
    buildSessionTool(deps),
    buildCsrfTool(deps),
    buildPasswordTool(deps),
    buildRbacTool(deps),
    buildPasskeyTool(deps),
    buildNhiTool(deps),
    buildSecretLifecycleTool(deps),
    buildNhiIsolationTool(deps),
  ];
  return {
    name: "auth",
    description:
      "Auth audits: OAuth 2.1 / OIDC, JWT, session, CSRF, password hashing, RBAC/ABAC, FIDO2 passkeys, NHI, secret lifecycle, NHI isolation.",
    version: MODULE_VERSION,
    tools,
    init() {
      // No async resources to load.
    },
  };
}
