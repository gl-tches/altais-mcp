// Rate-limiting auditor (altais_audit_rate_limiting).
//
// Reviews a declared rate-limiting configuration for the gaps that let an
// API be exhausted or brute-forced: rate limiting disabled or absent, a
// global-only scope that a single client can consume entirely, auth /
// login endpoints left unthrottled, a budget so large it is no real
// limit, and a missing `429` response or `Retry-After` header. An
// optional source string is regex-scanned for known limiter libraries.

import type { Finding, Severity } from "../../core/types.js";
import { buildApiFinding } from "./finding.js";

export type RateLimitStrategy =
  | "fixed_window"
  | "sliding_window"
  | "token_bucket"
  | "leaky_bucket"
  | "none";

export type RateLimitScope = "global" | "per_ip" | "per_user" | "per_api_key";

export interface RateLimitConfig {
  readonly enabled?: boolean;
  readonly strategy?: RateLimitStrategy;
  readonly scope?: RateLimitScope;
  readonly limit?: number;
  readonly window_seconds?: number;
  readonly applies_to_auth_endpoints?: boolean;
  readonly burst?: number;
  readonly returns_429?: boolean;
  readonly has_retry_after_header?: boolean;
}

export interface RateLimitAuditInput {
  readonly config: RateLimitConfig;
  readonly source?: string;
  readonly filename?: string;
}

const REFS = [
  "https://owasp.org/API-Security/editions/2023/en/0x11-t10/",
  "https://owasp.org/www-community/attacks/Brute_force_attack",
  "https://cwe.mitre.org/data/definitions/770.html",
];

interface LimiterLibrary {
  readonly name: string;
  readonly regex: RegExp;
}

// Well-known rate-limiting libraries across ecosystems.
const LIMITER_LIBRARIES: readonly LimiterLibrary[] = [
  { name: "express-rate-limit", regex: /express-rate-limit/i },
  { name: "rate-limiter-flexible", regex: /rate-limiter-flexible/i },
  { name: "slowapi", regex: /\bslowapi\b/i },
  { name: "bottleneck", regex: /\bbottleneck\b/i },
];

// A request budget above this many requests-per-second is treated as no
// meaningful limit for abuse / brute-force purposes.
const HIGH_RATE_PER_SECOND = 100;

export function auditRateLimiting(input: RateLimitAuditInput): readonly Finding[] {
  const file = input.filename;
  const cfg = input.config;
  const findings: Finding[] = [];

  const disabled = cfg.enabled === false || cfg.strategy === "none";

  // ── Rate limiting disabled / absent ───────────────────────────────────
  if (disabled) {
    findings.push(
      mk(
        file,
        "rate-limit-disabled",
        "high",
        "Rate limiting is disabled",
        "The configuration disables rate limiting (`enabled: false` or `strategy: none`). Without a limit a client can flood the API, exhausting CPU, memory, database connections, and downstream quotas.",
        "Enable rate limiting with a concrete strategy (`token_bucket` or `sliding_window`) and a per-client budget sized to legitimate traffic.",
        ["CWE-770", "CWE-400"],
        cfg.enabled === false ? "enabled: false" : "strategy: none",
        ["rate-limiting", "availability", "API4:2023"],
      ),
    );
    // When disabled, the remaining checks are moot — but auth-endpoint and
    // 429 gaps still apply implicitly; report them through the same path.
  }

  // ── Global-only scope ─────────────────────────────────────────────────
  if (!disabled && cfg.scope === "global") {
    findings.push(
      mk(
        file,
        "rate-limit-global-scope-only",
        "medium",
        "Rate limiting is scoped globally with no per-client dimension",
        "A single global budget is shared by every caller. One noisy or malicious client can consume the entire allowance and deny service to all other clients — and the limit gives no protection against per-account brute force.",
        "Scope rate limiting per client identity: `per_ip`, `per_user`, or `per_api_key`. A global cap can stay as an outer safety net but must not be the only dimension.",
        ["CWE-770"],
        "scope: global",
        ["rate-limiting", "availability", "API4:2023"],
      ),
    );
  }

  // ── Auth / login endpoints not rate-limited ───────────────────────────
  if (cfg.applies_to_auth_endpoints === false || disabled) {
    findings.push(
      mk(
        file,
        "rate-limit-auth-endpoints-unprotected",
        "high",
        "Authentication endpoints are not rate-limited",
        "Login, token, password-reset, and MFA endpoints are not covered by rate limiting. Unthrottled, they are open to credential stuffing, password spraying, and brute-force attacks against accounts.",
        "Apply strict per-IP and per-account rate limiting (and progressive backoff or lockout) specifically to authentication endpoints, independent of the general API budget.",
        ["CWE-307", "CWE-770"],
        disabled ? "rate limiting disabled" : "applies_to_auth_endpoints: false",
        ["rate-limiting", "authentication", "API4:2023"],
      ),
    );
  }

  // ── Budget too large to be meaningful ─────────────────────────────────
  if (
    !disabled &&
    cfg.limit !== undefined &&
    cfg.window_seconds !== undefined &&
    cfg.window_seconds > 0
  ) {
    const perSecond = cfg.limit / cfg.window_seconds;
    if (perSecond > HIGH_RATE_PER_SECOND) {
      findings.push(
        mk(
          file,
          "rate-limit-budget-too-high",
          "medium",
          "Rate-limit budget is too high to constrain abuse",
          `The configured budget allows roughly ${perSecond.toFixed(0)} requests/second per client (${cfg.limit} requests per ${cfg.window_seconds}s). A limit this loose does little to stop scraping, brute force, or resource exhaustion.`,
          "Lower the budget to reflect realistic legitimate usage. Size the limit from observed p99 traffic plus headroom, not from a round number.",
          ["CWE-770"],
          `limit: ${cfg.limit} per ${cfg.window_seconds}s`,
          ["rate-limiting", "availability", "API4:2023"],
        ),
      );
    }
  }

  // ── Missing 429 response ──────────────────────────────────────────────
  if (cfg.returns_429 === false) {
    findings.push(
      mk(
        file,
        "rate-limit-no-429-response",
        "low",
        "Rate-limited requests do not return HTTP 429",
        "When the limit is exceeded the API does not return `429 Too Many Requests`. Clients cannot distinguish throttling from a generic failure and may retry aggressively, amplifying load.",
        "Return `429 Too Many Requests` once the rate limit is exceeded, with a clear, non-revealing error body.",
        ["CWE-1059"],
        "returns_429: false",
        ["rate-limiting", "error-handling", "API4:2023"],
      ),
    );
  }

  // ── Missing Retry-After header ────────────────────────────────────────
  if (cfg.has_retry_after_header === false) {
    findings.push(
      mk(
        file,
        "rate-limit-no-retry-after",
        "low",
        "Rate-limit responses omit the `Retry-After` header",
        "Throttled responses do not include a `Retry-After` header. Without it, well-behaved clients cannot back off correctly and tend to retry immediately, prolonging the overload.",
        "Include a `Retry-After` header (and ideally `RateLimit-*` headers) on every `429` response so clients can back off deterministically.",
        ["CWE-1059"],
        "has_retry_after_header: false",
        ["rate-limiting", "error-handling", "API4:2023"],
      ),
    );
  }

  // ── Source scan for limiter libraries ─────────────────────────────────
  if (input.source !== undefined) {
    const found: string[] = [];
    for (const lib of LIMITER_LIBRARIES) {
      if (lib.regex.test(input.source)) found.push(lib.name);
    }
    if (found.length === 0) {
      findings.push(
        mk(
          file,
          "rate-limit-no-limiter-library",
          "medium",
          "No known rate-limiting library detected in the source",
          "The supplied source references none of the common rate-limiting libraries (express-rate-limit, rate-limiter-flexible, slowapi, bottleneck). Rate limiting may be missing, or implemented ad hoc and harder to audit.",
          "Adopt a vetted rate-limiting library backed by a shared store (for example Redis) so limits hold across instances, or confirm the gateway enforces the limit.",
          ["CWE-770"],
          "no limiter library referenced",
          ["rate-limiting", "library", "API4:2023"],
        ),
      );
    }
  }

  return findings;
}

function mk(
  file: string | undefined,
  rule: string,
  severity: Severity,
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
