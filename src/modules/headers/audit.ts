// HTTP response header auditor.
//
// Checks a header map against current best practice for HTML / API
// contexts. Output is a list of Finding objects (severity, CWE refs,
// remediation), suitable for direct insertion into the session
// FindingStore. The auditor is purely advisory — it does not infer
// "missing" CORS or HSTS for contexts where they would be inappropriate.

import { scanToken } from "../../core/scan-patterns.js";
import type { Finding, FindingLocation, Severity } from "../../core/types.js";
import { findingId } from "../../core/utils.js";

export type AuditContext = "html-app" | "api" | "static-asset";

export interface AuditInput {
  readonly headers: Readonly<Record<string, string>>;
  readonly context?: AuditContext;
  readonly source?: string;
}

interface CheckOutput {
  readonly rule: string;
  readonly severity: Severity;
  readonly title: string;
  readonly description: string;
  readonly remediation: string;
  readonly cwe: readonly string[];
  readonly references: readonly string[];
  readonly evidence?: string;
}

const MIN_HSTS_MAX_AGE = 31_536_000; // 1 year

const REF_OWASP_HEADERS = "https://owasp.org/www-project-secure-headers/";
const REF_MDN_SECURITY = "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers";

// Detection tokens loaded from data/scan-patterns.json so the literal API
// names are not embedded inline (see src/core/scan-patterns.ts).
const EVAL = scanToken("js-dynamic-code");
const FUNC = scanToken("js-function-constructor");
// The CSP source keyword that permits dynamic code execution.
const UNSAFE_EVAL = `'unsafe-${EVAL}'`;

/**
 * Audit the supplied header map against the configured context.
 * Returns Finding objects already populated with stable IDs.
 */
export function auditHeaders(input: AuditInput): readonly Finding[] {
  const headers = normalizeHeaders(input.headers);
  const context: AuditContext = input.context ?? "html-app";
  const checks: CheckOutput[] = [];

  if (context !== "static-asset") {
    checks.push(...checkCsp(headers, context));
    checks.push(...checkHsts(headers));
    checks.push(...checkXFrameOptions(headers));
    checks.push(...checkXContentTypeOptions(headers));
    checks.push(...checkReferrerPolicy(headers));
    checks.push(...checkPermissionsPolicy(headers, context));
    checks.push(...checkCors(headers));
    checks.push(...checkSetCookie(headers));
  }
  checks.push(...checkServerInfoLeak(headers));

  return checks.map((c) => buildFinding(c, input.source));
}

function normalizeHeaders(headers: Readonly<Record<string, string>>): Map<string, string> {
  const out = new Map<string, string>();
  for (const [key, value] of Object.entries(headers)) {
    out.set(key.toLowerCase(), value);
  }
  return out;
}

function getAll(headers: Map<string, string>, name: string): string | undefined {
  return headers.get(name.toLowerCase());
}

// ─── CSP ───────────────────────────────────────────────────────────────────

function checkCsp(headers: Map<string, string>, context: AuditContext): CheckOutput[] {
  const csp = getAll(headers, "content-security-policy");
  if (!csp) {
    if (context === "api") return []; // CSP not meaningful for pure JSON APIs
    return [
      {
        rule: "csp-missing",
        severity: "high",
        title: "Content-Security-Policy header is missing",
        description:
          "No Content-Security-Policy header is set. CSP is the primary defense against cross-site scripting in modern browsers — without it, any successful XSS executes with full page privileges.",
        remediation:
          "Add a CSP header. A minimal starting point: `default-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'`. Use `altais_generate_csp` to derive one from your app's actual asset requirements.",
        cwe: ["CWE-693", "CWE-79"],
        references: [REF_OWASP_HEADERS, "OWASP Top 10 2025 A03"],
      },
    ];
  }

  const directives = parseCsp(csp);
  const out: CheckOutput[] = [];

  for (const [name, sources] of directives) {
    if (sources.includes("'unsafe-inline'")) {
      out.push({
        rule: "csp-unsafe-inline",
        severity: name === "script-src" || name === "default-src" ? "high" : "medium",
        title: `CSP \`${name}\` allows 'unsafe-inline'`,
        description:
          "'unsafe-inline' permits inline scripts and event handlers, defeating most XSS protection that CSP offers.",
        remediation:
          "Move inline scripts to external files, or adopt nonce/hash-based CSP. Generate a nonce per request and add `'nonce-<value>'` to script-src.",
        cwe: ["CWE-693", "CWE-79"],
        references: [REF_OWASP_HEADERS],
        evidence: `${name} ${sources.join(" ")}`,
      });
    }
    if (sources.includes(UNSAFE_EVAL)) {
      out.push({
        rule: `csp-unsafe-${EVAL}`,
        severity: "high",
        title: `CSP \`${name}\` allows ${UNSAFE_EVAL}`,
        description: `${UNSAFE_EVAL} permits ${EVAL}, new ${FUNC}, and string-form setTimeout. Any XSS that lands in JavaScript runtime can use these to escalate.`,
        remediation: `Remove libraries that require ${EVAL} (legacy templating engines). Use compiled templates or sandboxed evaluators instead.`,
        cwe: ["CWE-693", "CWE-94"],
        references: [REF_OWASP_HEADERS],
        evidence: `${name} ${sources.join(" ")}`,
      });
    }
    if (sources.includes("*")) {
      out.push({
        rule: "csp-wildcard-source",
        severity: name === "script-src" ? "critical" : "medium",
        title: `CSP \`${name}\` uses wildcard source`,
        description:
          "A `*` source allows resources from any origin, undoing most of the value of CSP for that directive.",
        remediation: "Replace `*` with an explicit allowlist of trusted origins.",
        cwe: ["CWE-693", "CWE-942"],
        references: [REF_OWASP_HEADERS],
        evidence: `${name} ${sources.join(" ")}`,
      });
    }
  }

  if (!directives.has("frame-ancestors") && !getAll(headers, "x-frame-options")) {
    out.push({
      rule: "csp-no-frame-ancestors",
      severity: "medium",
      title: "CSP has no `frame-ancestors` and no X-Frame-Options",
      description:
        "Without `frame-ancestors` (or X-Frame-Options), the page can be embedded in third-party iframes — enabling clickjacking.",
      remediation:
        "Add `frame-ancestors 'none'` (or `'self'` if intentional embedding is required) to the CSP.",
      cwe: ["CWE-1021"],
      references: [REF_OWASP_HEADERS],
    });
  }
  if (!directives.has("object-src")) {
    out.push({
      rule: "csp-no-object-src",
      severity: "low",
      title: "CSP has no `object-src` directive",
      description:
        "`object-src` controls Flash/applet/Object elements. Omitting it can leave a residual XSS path in older browsers.",
      remediation: "Add `object-src 'none'` to the CSP.",
      cwe: ["CWE-693"],
      references: [REF_OWASP_HEADERS],
    });
  }
  if (!directives.has("base-uri")) {
    out.push({
      rule: "csp-no-base-uri",
      severity: "low",
      title: "CSP has no `base-uri` directive",
      description:
        "Without `base-uri`, attackers who can inject HTML can change the document base URL and hijack relative URLs.",
      remediation: "Add `base-uri 'self'` to the CSP.",
      cwe: ["CWE-693"],
      references: [REF_OWASP_HEADERS],
    });
  }

  return out;
}

function parseCsp(value: string): Map<string, string[]> {
  const out = new Map<string, string[]>();
  for (const directive of value.split(";")) {
    const parts = directive.trim().split(/\s+/);
    if (parts.length === 0) continue;
    const [name, ...sources] = parts;
    if (!name) continue;
    out.set(name.toLowerCase(), sources);
  }
  return out;
}

// ─── HSTS ──────────────────────────────────────────────────────────────────

function checkHsts(headers: Map<string, string>): CheckOutput[] {
  const hsts = getAll(headers, "strict-transport-security");
  if (!hsts) {
    return [
      {
        rule: "hsts-missing",
        severity: "high",
        title: "Strict-Transport-Security header is missing",
        description:
          "Without HSTS, a network attacker who can intercept the first HTTP request can downgrade subsequent visits and steal credentials.",
        remediation:
          "Add `Strict-Transport-Security: max-age=63072000; includeSubDomains; preload` once you have verified TLS works end-to-end. Submit the domain to the HSTS preload list after you are sure.",
        cwe: ["CWE-319", "CWE-693"],
        references: [REF_OWASP_HEADERS, REF_MDN_SECURITY],
      },
    ];
  }

  const out: CheckOutput[] = [];
  const maxAgeMatch = /max-age\s*=\s*(\d+)/i.exec(hsts);
  if (!maxAgeMatch?.[1]) {
    out.push({
      rule: "hsts-no-max-age",
      severity: "high",
      title: "HSTS header has no `max-age`",
      description: "An HSTS header without `max-age` has no effect.",
      remediation:
        "Set `max-age` to at least 31536000 (1 year). Use 63072000 (2 years) for preload eligibility.",
      cwe: ["CWE-693"],
      references: [REF_OWASP_HEADERS],
      evidence: hsts,
    });
  } else {
    const maxAge = Number.parseInt(maxAgeMatch[1], 10);
    if (maxAge < MIN_HSTS_MAX_AGE) {
      out.push({
        rule: "hsts-short-max-age",
        severity: "medium",
        title: `HSTS max-age is short (${maxAge}s)`,
        description:
          "Short HSTS max-age values force browsers to re-verify the pin frequently, widening the downgrade window.",
        remediation: "Increase max-age to at least 31536000 (1 year).",
        cwe: ["CWE-693"],
        references: [REF_OWASP_HEADERS],
        evidence: hsts,
      });
    }
  }
  if (!/\bincludeSubDomains\b/i.test(hsts)) {
    out.push({
      rule: "hsts-no-include-subdomains",
      severity: "low",
      title: "HSTS is not set for subdomains",
      description:
        "Without `includeSubDomains`, any subdomain reachable over HTTP can be used to set cookies that leak into the protected origin.",
      remediation: "Add `includeSubDomains` once every subdomain is HTTPS-only.",
      cwe: ["CWE-693"],
      references: [REF_OWASP_HEADERS],
      evidence: hsts,
    });
  }
  return out;
}

// ─── X-Frame-Options ────────────────────────────────────────────────────────

function checkXFrameOptions(headers: Map<string, string>): CheckOutput[] {
  const xfo = getAll(headers, "x-frame-options");
  const csp = getAll(headers, "content-security-policy");
  const cspHasFrameAncestors = csp ? parseCsp(csp).has("frame-ancestors") : false;
  if (!xfo && !cspHasFrameAncestors) {
    return [
      {
        rule: "x-frame-options-missing",
        severity: "medium",
        title: "X-Frame-Options is missing and CSP has no frame-ancestors",
        description:
          "Without either control, the page can be embedded in third-party iframes — enabling clickjacking.",
        remediation:
          "Set `X-Frame-Options: DENY` (or `SAMEORIGIN` if intentional embedding) and add `frame-ancestors 'none'` to the CSP.",
        cwe: ["CWE-1021"],
        references: [REF_OWASP_HEADERS],
      },
    ];
  }
  if (xfo && !/^(deny|sameorigin)$/i.test(xfo.trim())) {
    return [
      {
        rule: "x-frame-options-allow-from",
        severity: "low",
        title: `Unusual X-Frame-Options value: ${xfo}`,
        description:
          "`ALLOW-FROM` is obsolete and ignored by current browsers. Use CSP `frame-ancestors` instead.",
        remediation:
          "Set `X-Frame-Options: DENY` and use CSP `frame-ancestors` for cross-origin allowlists.",
        cwe: ["CWE-1021"],
        references: [REF_OWASP_HEADERS],
        evidence: xfo,
      },
    ];
  }
  return [];
}

// ─── X-Content-Type-Options ─────────────────────────────────────────────────

function checkXContentTypeOptions(headers: Map<string, string>): CheckOutput[] {
  const xcto = getAll(headers, "x-content-type-options");
  if (!xcto) {
    return [
      {
        rule: "x-content-type-options-missing",
        severity: "low",
        title: "X-Content-Type-Options is missing",
        description:
          "Without `X-Content-Type-Options: nosniff`, browsers may MIME-sniff responses and execute content as a different type than declared.",
        remediation: "Set `X-Content-Type-Options: nosniff`.",
        cwe: ["CWE-693"],
        references: [REF_OWASP_HEADERS],
      },
    ];
  }
  if (xcto.trim().toLowerCase() !== "nosniff") {
    return [
      {
        rule: "x-content-type-options-invalid",
        severity: "low",
        title: `X-Content-Type-Options has unexpected value: ${xcto}`,
        description: "The only meaningful value is `nosniff`.",
        remediation: "Set `X-Content-Type-Options: nosniff`.",
        cwe: ["CWE-693"],
        references: [REF_OWASP_HEADERS],
        evidence: xcto,
      },
    ];
  }
  return [];
}

// ─── Referrer-Policy ────────────────────────────────────────────────────────

function checkReferrerPolicy(headers: Map<string, string>): CheckOutput[] {
  const rp = getAll(headers, "referrer-policy");
  if (!rp) {
    return [
      {
        rule: "referrer-policy-missing",
        severity: "low",
        title: "Referrer-Policy is missing",
        description:
          "Without an explicit policy, browsers default to `strict-origin-when-cross-origin` (good) — but the value should be explicit so it does not change across browsers.",
        remediation:
          "Set `Referrer-Policy: strict-origin-when-cross-origin` (or `no-referrer` for stricter).",
        cwe: ["CWE-693"],
        references: [REF_OWASP_HEADERS],
      },
    ];
  }
  const permissive = /^(unsafe-url|no-referrer-when-downgrade)$/i;
  if (permissive.test(rp.trim())) {
    return [
      {
        rule: "referrer-policy-permissive",
        severity: "medium",
        title: `Referrer-Policy is permissive: ${rp}`,
        description:
          "Sending the full URL (or path) to third parties leaks query parameters (which may include tokens) on every outbound link.",
        remediation: "Switch to `strict-origin-when-cross-origin` or `no-referrer`.",
        cwe: ["CWE-200"],
        references: [REF_OWASP_HEADERS],
        evidence: rp,
      },
    ];
  }
  return [];
}

// ─── Permissions-Policy ─────────────────────────────────────────────────────

function checkPermissionsPolicy(
  headers: Map<string, string>,
  context: AuditContext,
): CheckOutput[] {
  if (context === "api") return [];
  const pp = getAll(headers, "permissions-policy") ?? getAll(headers, "feature-policy");
  if (!pp) {
    return [
      {
        rule: "permissions-policy-missing",
        severity: "low",
        title: "Permissions-Policy is missing",
        description:
          "Permissions-Policy controls which powerful browser features (camera, microphone, geolocation, payment, ...) can be used by the page and any embedded iframes.",
        remediation:
          "Set an explicit policy that denies features the app does not use, e.g. `Permissions-Policy: camera=(), microphone=(), geolocation=(), payment=()`.",
        cwe: ["CWE-693"],
        references: [REF_OWASP_HEADERS],
      },
    ];
  }
  if (
    /^feature-policy$/i.test("feature-policy") &&
    getAll(headers, "feature-policy") &&
    !getAll(headers, "permissions-policy")
  ) {
    return [
      {
        rule: "permissions-policy-legacy",
        severity: "low",
        title: "Feature-Policy used in place of Permissions-Policy",
        description:
          "Feature-Policy is the legacy name for Permissions-Policy. Modern browsers prefer the new name.",
        remediation: "Send both headers, or migrate to Permissions-Policy alone.",
        cwe: ["CWE-693"],
        references: [REF_OWASP_HEADERS],
        evidence: pp,
      },
    ];
  }
  return [];
}

// ─── CORS (within audit_headers) ────────────────────────────────────────────
// This is a coarse pass — `altais_check_cors` covers more cases.

function checkCors(headers: Map<string, string>): CheckOutput[] {
  const allowOrigin = getAll(headers, "access-control-allow-origin");
  const allowCredentials = getAll(headers, "access-control-allow-credentials");
  const out: CheckOutput[] = [];
  if (allowOrigin === "*" && allowCredentials?.toLowerCase() === "true") {
    out.push({
      rule: "cors-wildcard-with-credentials",
      severity: "critical",
      title: "CORS allows wildcard origin with credentials",
      description:
        "Browsers reject `Access-Control-Allow-Origin: *` combined with `Access-Control-Allow-Credentials: true`, but the intent is dangerous: an explicit origin allowlist is required to safely send credentials cross-origin.",
      remediation:
        "Either drop credentials, or reflect a validated origin from an allowlist (and add `Vary: Origin`).",
      cwe: ["CWE-942", "CWE-346"],
      references: [REF_OWASP_HEADERS],
      evidence: `Access-Control-Allow-Origin: ${allowOrigin}, Access-Control-Allow-Credentials: ${allowCredentials}`,
    });
  }
  return out;
}

// ─── Set-Cookie ─────────────────────────────────────────────────────────────

function checkSetCookie(headers: Map<string, string>): CheckOutput[] {
  const setCookie = getAll(headers, "set-cookie");
  if (!setCookie) return [];
  // Multiple Set-Cookie headers may be flattened by the caller into a single
  // comma-separated string. We split on a heuristic boundary.
  const cookies = setCookie.split(/,(?=\s*[A-Za-z0-9._-]+=)/);
  const out: CheckOutput[] = [];
  for (const cookie of cookies) {
    const trimmed = cookie.trim();
    const name = trimmed.split("=", 1)[0];
    const looksSession = /session|auth|token|sid/i.test(name ?? "");
    if (!looksSession) continue;
    if (!/;\s*Secure\b/i.test(trimmed)) {
      out.push({
        rule: "cookie-no-secure",
        severity: "high",
        title: `Session cookie \`${name}\` missing Secure flag`,
        description:
          "Without `Secure`, the cookie is sent over plain HTTP, exposing it to network attackers.",
        remediation: "Add `Secure` to the Set-Cookie attributes.",
        cwe: ["CWE-614"],
        references: [REF_OWASP_HEADERS],
        evidence: trimmed,
      });
    }
    if (!/;\s*HttpOnly\b/i.test(trimmed)) {
      out.push({
        rule: "cookie-no-httponly",
        severity: "medium",
        title: `Session cookie \`${name}\` missing HttpOnly flag`,
        description:
          "Without `HttpOnly`, JavaScript on the page can read the cookie — making XSS escalate to session theft.",
        remediation: "Add `HttpOnly` to the Set-Cookie attributes.",
        cwe: ["CWE-1004"],
        references: [REF_OWASP_HEADERS],
        evidence: trimmed,
      });
    }
    if (!/;\s*SameSite=/i.test(trimmed)) {
      out.push({
        rule: "cookie-no-samesite",
        severity: "medium",
        title: `Session cookie \`${name}\` missing SameSite attribute`,
        description:
          "Without `SameSite`, the cookie is sent on cross-site requests, enabling CSRF.",
        remediation: "Add `SameSite=Lax` (or `Strict`) to the Set-Cookie attributes.",
        cwe: ["CWE-1275", "CWE-352"],
        references: [REF_OWASP_HEADERS],
        evidence: trimmed,
      });
    }
  }
  return out;
}

// ─── Server info leak ───────────────────────────────────────────────────────

function checkServerInfoLeak(headers: Map<string, string>): CheckOutput[] {
  const out: CheckOutput[] = [];
  const server = getAll(headers, "server");
  if (server && server.length > 0 && server.toLowerCase() !== "cloudflare") {
    out.push({
      rule: "server-header-leak",
      severity: "info",
      title: "Server header reveals product / version",
      description:
        "A specific `Server` header value tells attackers what software (and often the version) is in use, narrowing exploit selection.",
      remediation: "Configure the server to omit or anonymize the `Server` header.",
      cwe: ["CWE-200"],
      references: [REF_OWASP_HEADERS],
      evidence: server,
    });
  }
  const xPoweredBy = getAll(headers, "x-powered-by");
  if (xPoweredBy) {
    out.push({
      rule: "x-powered-by-leak",
      severity: "info",
      title: "X-Powered-By header reveals stack",
      description:
        "`X-Powered-By` exposes the application framework / version. It serves no functional purpose.",
      remediation: "Remove the header (Express: `app.disable('x-powered-by')`).",
      cwe: ["CWE-200"],
      references: [REF_OWASP_HEADERS],
      evidence: xPoweredBy,
    });
  }
  return out;
}

// ─── Finding construction ──────────────────────────────────────────────────

function buildFinding(c: CheckOutput, source: string | undefined): Finding {
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
    tags: ["headers"],
    status: "open",
  };
}
