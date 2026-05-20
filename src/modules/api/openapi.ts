// OpenAPI specification auditor (altais_audit_openapi_spec).
//
// Parses a JSON OpenAPI 3.x document and walks it defensively for the
// security gaps that most often slip into a published API contract: no
// security scheme at all, weak schemes (Basic auth, an API key carried in
// the query string), operations with no security requirement, cleartext
// (`http://`) server URLs, operations missing error responses, request
// bodies that allow arbitrary extra properties (mass assignment), request
// bodies with no schema, and the absence of any documented rate limiting.

import type { Finding } from "../../core/types.js";
import { buildApiFinding } from "./finding.js";

export interface OpenApiAuditInput {
  readonly spec: string;
  readonly filename?: string;
}

export type OpenApiAuditResult =
  | { readonly ok: true; readonly findings: readonly Finding[] }
  | { readonly ok: false; readonly error: string };

const REFS = [
  "https://owasp.org/API-Security/editions/2023/en/0x11-t10/",
  "https://spec.openapis.org/oas/v3.1.0",
  "https://cwe.mitre.org/",
];

// ─── Defensive type guards over the parsed `unknown` document ───────────────

function isObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function getObject(value: unknown, key: string): Record<string, unknown> | undefined {
  if (!isObject(value)) return undefined;
  const child = value[key];
  return isObject(child) ? child : undefined;
}

function getString(value: unknown, key: string): string | undefined {
  if (!isObject(value)) return undefined;
  const child = value[key];
  return typeof child === "string" ? child : undefined;
}

const HTTP_METHODS = new Set(["get", "put", "post", "delete", "patch", "options", "head", "trace"]);

interface OperationRef {
  readonly path: string;
  readonly method: string;
  readonly operation: Record<string, unknown>;
}

/** Collect every HTTP operation across all path items. */
function collectOperations(spec: Record<string, unknown>): readonly OperationRef[] {
  const paths = getObject(spec, "paths");
  if (paths === undefined) return [];
  const out: OperationRef[] = [];
  for (const [path, pathItemRaw] of Object.entries(paths)) {
    if (!isObject(pathItemRaw)) continue;
    for (const [method, opRaw] of Object.entries(pathItemRaw)) {
      if (!HTTP_METHODS.has(method.toLowerCase())) continue;
      if (!isObject(opRaw)) continue;
      out.push({ path, method: method.toLowerCase(), operation: opRaw });
    }
  }
  return out;
}

/** True when an object has a non-empty `security` array. */
function hasSecurityRequirement(value: Record<string, unknown>): boolean {
  const sec = value.security;
  return Array.isArray(sec) && sec.length > 0;
}

/**
 * Recursively look for a schema (or nested schema) that allows arbitrary
 * extra properties — i.e. an `object` whose `additionalProperties` is not
 * explicitly `false`. Bounded by `depth` to avoid pathological nesting.
 */
function schemaAllowsExtraProps(schema: unknown, depth: number): boolean {
  if (depth > 8 || !isObject(schema)) return false;
  const type = schema.type;
  const props = schema.properties;
  const looksLikeObject = type === "object" || isObject(props);
  if (looksLikeObject) {
    const additional = schema.additionalProperties;
    if (additional !== false) return true;
  }
  // Walk nested property schemas and array item schemas.
  if (isObject(props)) {
    for (const child of Object.values(props)) {
      if (schemaAllowsExtraProps(child, depth + 1)) return true;
    }
  }
  const items = schema.items;
  if (items !== undefined && schemaAllowsExtraProps(items, depth + 1)) return true;
  for (const composite of ["allOf", "anyOf", "oneOf"]) {
    const branch = schema[composite];
    if (Array.isArray(branch)) {
      for (const child of branch) {
        if (schemaAllowsExtraProps(child, depth + 1)) return true;
      }
    }
  }
  return false;
}

export function auditOpenApi(input: OpenApiAuditInput): OpenApiAuditResult {
  let parsed: unknown;
  try {
    parsed = JSON.parse(input.spec);
  } catch (err) {
    const detail = err instanceof Error ? err.message : "unknown parse error";
    return {
      ok: false,
      error: `Could not parse the OpenAPI document as JSON: ${detail}. This tool only accepts a JSON OpenAPI 3.x document — convert a YAML spec to JSON first (for example with \`npx js-yaml spec.yaml\`).`,
    };
  }

  if (!isObject(parsed)) {
    return {
      ok: false,
      error:
        "The OpenAPI document parsed as JSON but its top level is not an object. Provide a JSON OpenAPI 3.x document whose root is an object with `openapi`, `info`, and `paths` keys.",
    };
  }

  return { ok: true, findings: analyze(parsed, input.filename) };
}

function analyze(spec: Record<string, unknown>, file: string | undefined): readonly Finding[] {
  const findings: Finding[] = [];

  const components = getObject(spec, "components");
  const securitySchemes =
    components !== undefined ? getObject(components, "securitySchemes") : undefined;
  const hasGlobalSecurity = hasSecurityRequirement(spec);
  const hasAnyScheme = securitySchemes !== undefined && Object.keys(securitySchemes).length > 0;

  // ── No security defined anywhere ──────────────────────────────────────
  if (!hasGlobalSecurity && !hasAnyScheme) {
    findings.push(
      mk(
        file,
        "openapi-no-security",
        "high",
        "OpenAPI document defines no authentication",
        "The document declares neither a top-level `security` requirement nor any `components.securitySchemes`. As written, every operation in the API is anonymous and unauthenticated.",
        "Define at least one security scheme under `components.securitySchemes` (OAuth2, OpenID Connect, or a bearer JWT) and apply it with a top-level `security` requirement or per-operation `security`.",
        ["CWE-306", "CWE-1059"],
        "no security / securitySchemes",
        ["openapi", "authentication", "API2:2023"],
      ),
    );
  }

  // ── Weak security schemes ─────────────────────────────────────────────
  if (securitySchemes !== undefined) {
    for (const [name, schemeRaw] of Object.entries(securitySchemes)) {
      if (!isObject(schemeRaw)) continue;
      const type = getString(schemeRaw, "type");
      const scheme = getString(schemeRaw, "scheme");
      if (type === "http" && scheme?.toLowerCase() === "basic") {
        findings.push(
          mk(
            file,
            "openapi-basic-auth-scheme",
            "high",
            `Security scheme \`${name}\` uses HTTP Basic authentication`,
            "HTTP Basic auth transmits a base64-encoded username and password on every request. It has no built-in expiry, is trivially decoded if TLS is stripped, and encourages long-lived shared credentials.",
            "Replace Basic auth with a token-based scheme: OAuth2, OpenID Connect, or short-lived bearer JWTs issued by an identity provider.",
            ["CWE-522", "CWE-319"],
            `securitySchemes.${name}: http/basic`,
            ["openapi", "authentication", "API2:2023"],
          ),
        );
      }
      if (type === "apiKey" && getString(schemeRaw, "in")?.toLowerCase() === "query") {
        findings.push(
          mk(
            file,
            "openapi-apikey-in-query",
            "medium",
            `Security scheme \`${name}\` carries an API key in the query string`,
            "An API key passed as a query parameter is written into server access logs, browser history, proxy logs, and the `Referer` header of any outbound link. The credential leaks far beyond the request.",
            "Carry the API key in a request header (`in: header`) instead of the query string, and rotate any key that may already have been logged.",
            ["CWE-598", "CWE-522"],
            `securitySchemes.${name}: apiKey in query`,
            ["openapi", "authentication", "API2:2023"],
          ),
        );
      }
    }
  }

  // ── Server URLs over cleartext HTTP ───────────────────────────────────
  const servers = spec.servers;
  if (Array.isArray(servers)) {
    for (const serverRaw of servers) {
      const url = getString(serverRaw, "url");
      if (url?.toLowerCase().startsWith("http://") === true) {
        findings.push(
          mk(
            file,
            "openapi-cleartext-server-url",
            "high",
            `Server URL \`${url}\` uses cleartext HTTP`,
            "A server declared with an `http://` URL serves traffic — including credentials and tokens — without transport encryption, exposing it to interception and tampering on the network path.",
            "Serve the API only over `https://` and update every `servers[].url` to use the `https` scheme.",
            ["CWE-319"],
            url,
            ["openapi", "transport", "API8:2023"],
          ),
        );
      }
    }
  }

  // ── Per-operation checks ──────────────────────────────────────────────
  const operations = collectOperations(spec);
  let anyRateLimitResponse = false;

  for (const op of operations) {
    const where = `${op.method.toUpperCase()} ${op.path}`;

    // Operation has no security requirement and there is no global default.
    const opHasSecurityKey = "security" in op.operation;
    const opSecuredExplicitly = opHasSecurityKey && hasSecurityRequirement(op.operation);
    if (!opSecuredExplicitly && !hasGlobalSecurity) {
      findings.push(
        mk(
          file,
          "openapi-operation-no-security",
          "high",
          `Operation \`${where}\` has no security requirement`,
          "Neither this operation nor the document defines a `security` requirement that applies to it, so the operation is reachable without authentication.",
          "Add a `security` requirement to the operation, or define a top-level `security` default that covers it. Use an empty `security: []` only for genuinely public operations.",
          ["CWE-306"],
          where,
          ["openapi", "authentication", "API2:2023"],
        ),
      );
    }

    // Operation responses.
    const responses = getObject(op.operation, "responses");
    const responseCodes = responses !== undefined ? Object.keys(responses) : [];
    const hasErrorResponse = responseCodes.some((c) => /^[45]/.test(c) || c === "default");
    if (!hasErrorResponse) {
      findings.push(
        mk(
          file,
          "openapi-operation-no-error-response",
          "low",
          `Operation \`${where}\` documents no error responses`,
          "The operation declares no 4xx/5xx (or `default`) response. Undocumented error contracts let inconsistent, sometimes verbose, error bodies reach clients and hide error-handling gaps from reviewers.",
          "Document the expected error responses (`400`, `401`, `403`, `404`, `429`, `500`) with a consistent error schema.",
          ["CWE-1059"],
          where,
          ["openapi", "error-handling", "API8:2023"],
        ),
      );
    }
    if (responseCodes.includes("429")) anyRateLimitResponse = true;

    // Request body schema checks.
    const requestBody = getObject(op.operation, "requestBody");
    if (requestBody !== undefined) {
      const content = getObject(requestBody, "content");
      if (content === undefined || Object.keys(content).length === 0) {
        findings.push(
          mk(
            file,
            "openapi-request-body-no-schema",
            "medium",
            `Operation \`${where}\` accepts a request body with no schema`,
            "The `requestBody` declares no `content` media type or schema. Without a schema the input is unvalidated at the contract level and gateways cannot enforce request validation.",
            "Declare a `content` media type (for example `application/json`) with an explicit JSON Schema for the request body.",
            ["CWE-20", "CWE-1059"],
            where,
            ["openapi", "input-validation", "API6:2023"],
          ),
        );
      } else {
        for (const [media, mediaObjRaw] of Object.entries(content)) {
          const schema = getObject(mediaObjRaw, "schema");
          if (schema === undefined) {
            findings.push(
              mk(
                file,
                "openapi-request-body-no-schema",
                "medium",
                `Operation \`${where}\` has a \`${media}\` body with no schema`,
                "The request body media type declares no `schema`, so the payload shape is undefined and cannot be validated at the edge.",
                "Add an explicit JSON Schema to the request body media type.",
                ["CWE-20", "CWE-1059"],
                `${where} (${media})`,
                ["openapi", "input-validation", "API6:2023"],
              ),
            );
          } else if (schemaAllowsExtraProps(schema, 0)) {
            findings.push(
              mk(
                file,
                "openapi-additional-properties-open",
                "medium",
                `Operation \`${where}\` request schema allows arbitrary extra properties`,
                "An object schema that does not set `additionalProperties: false` accepts unexpected fields. A client can then set internal-only attributes (roles, ownership, balances) the API never meant to expose — a mass-assignment vulnerability.",
                "Set `additionalProperties: false` on object schemas and list every accepted property explicitly. Bind input to a strict allowlist of fields.",
                ["CWE-915", "CWE-20"],
                `${where} (${media})`,
                ["openapi", "mass-assignment", "API6:2023"],
              ),
            );
          }
        }
      }
    }
  }

  // ── No documented rate limiting anywhere ──────────────────────────────
  if (operations.length > 0 && !anyRateLimitResponse) {
    findings.push(
      mk(
        file,
        "openapi-no-rate-limit-documented",
        "medium",
        "No operation documents a rate-limiting (`429`) response",
        "Not a single operation declares a `429 Too Many Requests` response. Either the API enforces no rate limiting — leaving it open to resource exhaustion and brute-force abuse — or the contract hides the limit from clients.",
        "Apply rate limiting to the API and document the `429` response (with a `Retry-After` header) on rate-limited operations.",
        ["CWE-770"],
        "no 429 response across all operations",
        ["openapi", "rate-limiting", "API4:2023"],
      ),
    );
  }

  return findings;
}

function mk(
  file: string | undefined,
  rule: string,
  severity: Finding["severity"],
  title: string,
  description: string,
  remediation: string,
  cwe: readonly string[],
  evidence: string,
  tags: readonly string[],
): Finding {
  return buildApiFinding(
    {
      rule,
      severity,
      title,
      description,
      remediation,
      cwe,
      references: REFS,
      evidence,
      tags,
    },
    file,
  );
}
