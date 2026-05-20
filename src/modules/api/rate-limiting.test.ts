import { describe, expect, it } from "vitest";
import { auditRateLimiting } from "./rate-limiting.js";
import type { RateLimitConfig } from "./rate-limiting.js";

function has(config: RateLimitConfig, rule: string, source?: string): boolean {
  const input = source !== undefined ? { config, source } : { config };
  return auditRateLimiting(input).some((f) => f.rule === rule);
}

// A reasonably-hardened rate-limit configuration used as the negative baseline.
const SECURE_CONFIG: RateLimitConfig = {
  enabled: true,
  strategy: "token_bucket",
  scope: "per_user",
  limit: 60,
  window_seconds: 60,
  applies_to_auth_endpoints: true,
  burst: 10,
  returns_429: true,
  has_retry_after_header: true,
};

describe("auditRateLimiting — disabled / absent", () => {
  it("flags rate limiting disabled via enabled:false", () => {
    expect(has({ enabled: false }, "rate-limit-disabled")).toBe(true);
  });

  it("flags rate limiting disabled via strategy:none", () => {
    expect(has({ strategy: "none" }, "rate-limit-disabled")).toBe(true);
  });

  it("does not flag rate-limit-disabled when enabled", () => {
    expect(has(SECURE_CONFIG, "rate-limit-disabled")).toBe(false);
  });
});

describe("auditRateLimiting — scope and auth endpoints", () => {
  it("flags a global-only scope", () => {
    expect(has({ ...SECURE_CONFIG, scope: "global" }, "rate-limit-global-scope-only")).toBe(true);
  });

  it("does not flag a per-ip scope", () => {
    expect(has({ ...SECURE_CONFIG, scope: "per_ip" }, "rate-limit-global-scope-only")).toBe(false);
  });

  it("flags auth endpoints not covered by rate limiting", () => {
    expect(
      has(
        { ...SECURE_CONFIG, applies_to_auth_endpoints: false },
        "rate-limit-auth-endpoints-unprotected",
      ),
    ).toBe(true);
  });

  it("flags auth endpoints implicitly when rate limiting is disabled", () => {
    expect(has({ enabled: false }, "rate-limit-auth-endpoints-unprotected")).toBe(true);
  });
});

describe("auditRateLimiting — budget and headers", () => {
  it("flags a budget too high relative to the window", () => {
    expect(
      has({ ...SECURE_CONFIG, limit: 1_000_000, window_seconds: 60 }, "rate-limit-budget-too-high"),
    ).toBe(true);
  });

  it("does not flag a reasonable budget", () => {
    expect(has(SECURE_CONFIG, "rate-limit-budget-too-high")).toBe(false);
  });

  it("flags a missing 429 response", () => {
    expect(has({ ...SECURE_CONFIG, returns_429: false }, "rate-limit-no-429-response")).toBe(true);
  });

  it("flags a missing Retry-After header", () => {
    expect(
      has({ ...SECURE_CONFIG, has_retry_after_header: false }, "rate-limit-no-retry-after"),
    ).toBe(true);
  });
});

describe("auditRateLimiting — source library scan", () => {
  it("flags source with no known limiter library", () => {
    expect(has(SECURE_CONFIG, "rate-limit-no-limiter-library", "const x = 1;")).toBe(true);
  });

  it("does not flag source that uses a known limiter library", () => {
    expect(
      has(
        SECURE_CONFIG,
        "rate-limit-no-limiter-library",
        "import rateLimit from 'express-rate-limit';",
      ),
    ).toBe(false);
  });

  it("recognizes slowapi as a limiter library", () => {
    expect(has(SECURE_CONFIG, "rate-limit-no-limiter-library", "from slowapi import Limiter")).toBe(
      false,
    );
  });
});

describe("auditRateLimiting — baseline and shape", () => {
  it("produces no findings for a hardened configuration", () => {
    expect(auditRateLimiting({ config: SECURE_CONFIG })).toHaveLength(0);
  });

  it("produces deterministic finding IDs across runs", () => {
    const cfg: RateLimitConfig = { enabled: false };
    const a = auditRateLimiting({ config: cfg, filename: "rl.toml" });
    const b = auditRateLimiting({ config: cfg, filename: "rl.toml" });
    expect(a.map((f) => f.id)).toEqual(b.map((f) => f.id));
  });

  it("tags every finding with the api module, a CWE, and the api tag", () => {
    const findings = auditRateLimiting({ config: { enabled: false } });
    expect(findings.length).toBeGreaterThan(0);
    for (const f of findings) {
      expect(f.module).toBe("api");
      expect(f.cwe?.length ?? 0).toBeGreaterThan(0);
      expect(f.tags).toContain("api");
    }
  });
});
