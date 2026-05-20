// CORS validator.
//
// Accepts either an HTTP header map (the common Access-Control-* set) or
// a structured config object describing the same policy. Returns a list
// of Finding objects flagging permissive configurations.

import type { Finding, FindingLocation, Severity } from "../../core/types.js";
import { findingId } from "../../core/utils.js";

export interface CorsConfig {
  readonly allowed_origins?: readonly string[];
  readonly reflect_origin?: boolean;
  readonly allow_credentials?: boolean;
  readonly allowed_methods?: readonly string[];
  readonly allowed_headers?: readonly string[];
  readonly expose_headers?: readonly string[];
  readonly max_age_seconds?: number;
  readonly vary_origin?: boolean;
}

export interface CorsCheckInput {
  readonly config?: CorsConfig;
  readonly headers?: Readonly<Record<string, string>>;
  readonly source?: string;
}

interface Check {
  readonly rule: string;
  readonly severity: Severity;
  readonly title: string;
  readonly description: string;
  readonly remediation: string;
  readonly cwe: readonly string[];
  readonly references: readonly string[];
  readonly evidence?: string;
}

const REFS = [
  "https://owasp.org/www-project-secure-headers/#cross-origin-resource-sharing",
  "https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS",
];

const SAFE_METHODS = new Set(["GET", "HEAD", "OPTIONS"]);
const DANGEROUS_METHODS = new Set(["PUT", "DELETE", "PATCH", "TRACE", "CONNECT"]);
const MAX_REASONABLE_AGE = 86_400;

/**
 * Run CORS checks. At least one of `config` or `headers` must be set.
 */
export function checkCors(input: CorsCheckInput): readonly Finding[] {
  const config = input.config ?? configFromHeaders(input.headers ?? {});
  const checks: Check[] = [];
  checks.push(...checkOrigins(config));
  checks.push(...checkMethods(config));
  checks.push(...checkHeadersConfig(config));
  checks.push(...checkMaxAge(config));
  checks.push(...checkVary(config, input.headers));
  return checks.map((c) => toFinding(c, input.source));
}

function configFromHeaders(headers: Readonly<Record<string, string>>): CorsConfig {
  const map = new Map<string, string>();
  for (const [k, v] of Object.entries(headers)) map.set(k.toLowerCase(), v);

  const origin = map.get("access-control-allow-origin");
  const allowedOrigins = origin === undefined ? undefined : [origin];
  const allowedMethods = map
    .get("access-control-allow-methods")
    ?.split(",")
    .map((s) => s.trim().toUpperCase())
    .filter((s) => s.length > 0);
  const allowedHeaders = map
    .get("access-control-allow-headers")
    ?.split(",")
    .map((s) => s.trim())
    .filter((s) => s.length > 0);
  const exposeHeaders = map
    .get("access-control-expose-headers")
    ?.split(",")
    .map((s) => s.trim())
    .filter((s) => s.length > 0);
  const maxAge = map.get("access-control-max-age");
  return {
    ...(allowedOrigins ? { allowed_origins: allowedOrigins } : {}),
    allow_credentials: map.get("access-control-allow-credentials")?.toLowerCase() === "true",
    ...(allowedMethods ? { allowed_methods: allowedMethods } : {}),
    ...(allowedHeaders ? { allowed_headers: allowedHeaders } : {}),
    ...(exposeHeaders ? { expose_headers: exposeHeaders } : {}),
    ...(maxAge !== undefined ? { max_age_seconds: Number.parseInt(maxAge, 10) } : {}),
    vary_origin: /(^|,\s*)origin(\s*,|$)/i.test(map.get("vary") ?? ""),
  };
}

function checkOrigins(c: CorsConfig): Check[] {
  const origins = c.allowed_origins ?? [];
  const out: Check[] = [];
  if (origins.includes("*") && c.allow_credentials === true) {
    out.push({
      rule: "cors-wildcard-with-credentials",
      severity: "critical",
      title: "CORS: wildcard origin combined with credentials",
      description:
        "Browsers reject `Access-Control-Allow-Origin: *` together with `Access-Control-Allow-Credentials: true`, but the intent is dangerous. With credentials, every origin is implicitly trusted.",
      remediation:
        "Drop credentials, or reflect an origin from an explicit allowlist and add `Vary: Origin`.",
      cwe: ["CWE-942", "CWE-346"],
      references: REFS,
      evidence: `allowed_origins=${JSON.stringify(origins)}, allow_credentials=true`,
    });
  } else if (origins.includes("*")) {
    out.push({
      rule: "cors-wildcard-origin",
      severity: "medium",
      title: "CORS: wildcard origin",
      description:
        "`Access-Control-Allow-Origin: *` allows any web origin to read non-credentialed responses. Acceptable for truly public data; not acceptable for anything authenticated by IP/headers/etc.",
      remediation:
        "If responses must remain public, document it. Otherwise switch to an explicit allowlist and reflect the matched origin.",
      cwe: ["CWE-942"],
      references: REFS,
      evidence: `allowed_origins=${JSON.stringify(origins)}`,
    });
  }
  if (c.reflect_origin === true && origins.length === 0) {
    out.push({
      rule: "cors-origin-reflection",
      severity: "high",
      title: "CORS: origin is reflected without an allowlist",
      description:
        "Echoing the request's `Origin` back into `Access-Control-Allow-Origin` (without a server-side allowlist) trusts any caller, including attacker.example.com. Combined with credentials this is a full bypass.",
      remediation:
        "Compare the incoming Origin against a configured allowlist. Only reflect when it matches.",
      cwe: ["CWE-942"],
      references: REFS,
    });
  }
  if (origins.includes("null")) {
    out.push({
      rule: "cors-null-origin",
      severity: "high",
      title: "CORS: `null` origin is allowed",
      description:
        "Sandboxed documents, `data:` URLs, and certain redirects produce the literal `null` origin. Trusting it lets attacker-controlled sandboxed pages reach the API.",
      remediation: "Remove `null` from the origin allowlist.",
      cwe: ["CWE-942"],
      references: REFS,
      evidence: "allowed_origins includes 'null'",
    });
  }
  return out;
}

function checkMethods(c: CorsConfig): Check[] {
  const methods = c.allowed_methods ?? [];
  const out: Check[] = [];
  if (methods.includes("*")) {
    out.push({
      rule: "cors-wildcard-methods",
      severity: "medium",
      title: "CORS: wildcard methods allowed",
      description:
        "`Access-Control-Allow-Methods: *` is interpreted literally by browsers — it's not a true wildcard for non-CORS-safelisted methods. Either way, prefer an explicit list.",
      remediation: "Replace with an explicit list, e.g. `GET, POST, PUT, DELETE, OPTIONS`.",
      cwe: ["CWE-942"],
      references: REFS,
      evidence: `allowed_methods=${JSON.stringify(methods)}`,
    });
  }
  const dangerous = methods.filter((m) => DANGEROUS_METHODS.has(m.toUpperCase()));
  if (dangerous.length > 0 && c.allow_credentials === true) {
    out.push({
      rule: "cors-state-changing-with-credentials",
      severity: "medium",
      title: "CORS allows state-changing methods with credentials",
      description: `Cross-origin ${dangerous.join("/")} with credentials enables CSRF-like attacks if the origin allowlist is loose.`,
      remediation:
        "Keep the origin allowlist tight and consider requiring an additional same-origin token for state-changing requests.",
      cwe: ["CWE-942", "CWE-352"],
      references: REFS,
      evidence: `methods=${dangerous.join(",")} credentials=true`,
    });
  }
  if (methods.length === 0 && (c.allowed_origins ?? []).length > 0) {
    out.push({
      rule: "cors-default-methods",
      severity: "info",
      title: "CORS: no explicit methods set",
      description:
        "Without an `Access-Control-Allow-Methods` response, browsers default to the CORS-safelisted methods (GET, HEAD, POST). Make the policy explicit so server changes do not silently broaden it.",
      remediation: "Add an explicit method list to the preflight response.",
      cwe: ["CWE-693"],
      references: REFS,
    });
  }
  void SAFE_METHODS;
  return out;
}

function checkHeadersConfig(c: CorsConfig): Check[] {
  const allowed = c.allowed_headers ?? [];
  const out: Check[] = [];
  if (allowed.includes("*")) {
    out.push({
      rule: "cors-wildcard-headers",
      severity: "low",
      title: "CORS: wildcard request headers allowed",
      description:
        "`Access-Control-Allow-Headers: *` is interpreted literally with credentials and as a wildcard otherwise. Either way, explicit allowlists make the policy auditable.",
      remediation:
        "List required headers explicitly, e.g. `Content-Type, Authorization, X-CSRF-Token`.",
      cwe: ["CWE-942"],
      references: REFS,
      evidence: `allowed_headers=${JSON.stringify(allowed)}`,
    });
  }
  const expose = c.expose_headers ?? [];
  if (expose.includes("*") && c.allow_credentials === true) {
    out.push({
      rule: "cors-expose-wildcard-with-credentials",
      severity: "medium",
      title: "CORS exposes wildcard headers with credentials",
      description:
        "`Access-Control-Expose-Headers: *` is treated as literal when credentials are present. With credentials, exposing every header leaks `Set-Cookie` envelopes and other sensitive metadata.",
      remediation: "Enumerate exposed headers explicitly.",
      cwe: ["CWE-942", "CWE-200"],
      references: REFS,
      evidence: `expose_headers=${JSON.stringify(expose)} credentials=true`,
    });
  }
  return out;
}

function checkMaxAge(c: CorsConfig): Check[] {
  if (c.max_age_seconds === undefined) return [];
  if (c.max_age_seconds > MAX_REASONABLE_AGE * 30) {
    return [
      {
        rule: "cors-max-age-excessive",
        severity: "low",
        title: `CORS preflight cache is very long (${c.max_age_seconds}s)`,
        description:
          "Long preflight cache values mean policy changes (e.g. removing an origin) propagate slowly to existing browser sessions.",
        remediation:
          "Cap `Access-Control-Max-Age` at 86400 (1 day) unless you have a specific reason.",
        cwe: ["CWE-693"],
        references: REFS,
        evidence: `max_age_seconds=${c.max_age_seconds}`,
      },
    ];
  }
  return [];
}

function checkVary(c: CorsConfig, headers: Readonly<Record<string, string>> | undefined): Check[] {
  if (!headers) return [];
  const origins = c.allowed_origins ?? [];
  const isDynamic = origins.length > 1 || c.reflect_origin === true;
  if (!isDynamic) return [];
  if (c.vary_origin === true) return [];
  return [
    {
      rule: "cors-missing-vary-origin",
      severity: "medium",
      title: "CORS reflects origin without `Vary: Origin`",
      description:
        "When the CORS response depends on the request's Origin, caches must be told via `Vary: Origin` — otherwise one client's allowed response can be served to a different origin.",
      remediation: "Add `Vary: Origin` to every CORS response that depends on the Origin header.",
      cwe: ["CWE-693", "CWE-942"],
      references: REFS,
    },
  ];
}

function toFinding(c: Check, source: string | undefined): Finding {
  const location: FindingLocation | undefined =
    source !== undefined ? { file: source, line_start: 1 } : undefined;
  return {
    id: findingId("headers", c.rule, location, c.evidence ?? ""),
    module: "headers",
    rule: c.rule,
    severity: c.severity,
    cwe: c.cwe,
    title: c.title,
    description: c.description,
    ...(location !== undefined ? { location } : {}),
    ...(c.evidence !== undefined ? { evidence: c.evidence } : {}),
    remediation: c.remediation,
    references: c.references,
    tags: ["headers", "cors"],
    status: "open",
  };
}
