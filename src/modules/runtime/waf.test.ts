import { describe, expect, it } from "vitest";
import { generateWafRules, type WafGeneratorInput } from "./waf.js";

describe("generateWafRules — ModSecurity", () => {
  it("emits SecRule directives for the requested attack classes", () => {
    const r = generateWafRules({
      platform: "modsecurity",
      protect_against: ["sql-injection", "xss"],
    });
    expect(r.platform).toBe("modsecurity");
    expect(r.rules).toHaveLength(2);
    for (const rule of r.rules) {
      expect(rule.definition).toContain("SecRule");
      expect(rule.definition).toContain("id:");
    }
  });

  it("emits a rate-limiting SecAction block for rate-abuse", () => {
    const r = generateWafRules({
      platform: "modsecurity",
      protect_against: ["rate-abuse"],
    });
    const rule = r.rules[0];
    expect(rule).toBeDefined();
    expect(rule?.definition).toContain("SecAction");
    expect(rule?.definition).toContain("status:429");
  });
});

describe("generateWafRules — Cloudflare", () => {
  it("emits a JSON ruleset expression for each attack class", () => {
    const r = generateWafRules({
      platform: "cloudflare",
      protect_against: ["path-traversal", "rce"],
    });
    expect(r.rules).toHaveLength(2);
    for (const rule of r.rules) {
      const parsed: unknown = JSON.parse(rule.definition);
      expect(parsed).toHaveProperty("expression");
      expect(parsed).toHaveProperty("action");
    }
  });

  it("includes a ratelimit block for rate-abuse", () => {
    const r = generateWafRules({
      platform: "cloudflare",
      protect_against: ["rate-abuse"],
    });
    const rule = r.rules[0];
    expect(rule).toBeDefined();
    const parsed = JSON.parse(rule?.definition ?? "{}") as Record<string, unknown>;
    expect(parsed).toHaveProperty("ratelimit");
  });
});

describe("generateWafRules — AWS WAF", () => {
  it("emits valid AWS WAFv2 rule JSON with managed rule groups", () => {
    const r = generateWafRules({
      platform: "aws-waf",
      protect_against: ["sql-injection"],
    });
    const rule = r.rules[0];
    expect(rule).toBeDefined();
    const parsed = JSON.parse(rule?.definition ?? "{}") as Record<string, unknown>;
    expect(parsed).toHaveProperty("Name");
    expect(parsed).toHaveProperty("Priority");
    expect(parsed).toHaveProperty("Statement");
  });

  it("emits a RateBasedStatement for rate-abuse", () => {
    const r = generateWafRules({
      platform: "aws-waf",
      protect_against: ["rate-abuse"],
    });
    const rule = r.rules[0];
    const parsed = JSON.parse(rule?.definition ?? "{}") as Record<string, unknown>;
    const stmt = parsed.Statement as Record<string, unknown>;
    expect(stmt).toHaveProperty("RateBasedStatement");
  });
});

describe("generateWafRules — NGINX/NAXSI", () => {
  it("emits MainRule and CheckRule directives", () => {
    const r = generateWafRules({
      platform: "nginx-naxsi",
      protect_against: ["xss"],
    });
    const rule = r.rules[0];
    expect(rule).toBeDefined();
    expect(rule?.definition).toContain("MainRule");
    expect(rule?.definition).toContain("CheckRule");
  });

  it("emits a limit_req zone for rate-abuse", () => {
    const r = generateWafRules({
      platform: "nginx-naxsi",
      protect_against: ["rate-abuse"],
    });
    const rule = r.rules[0];
    expect(rule?.definition).toContain("limit_req_zone");
  });
});

describe("generateWafRules — common behavior", () => {
  it("scopes rules to the requested paths", () => {
    const r = generateWafRules({
      platform: "cloudflare",
      protect_against: ["sql-injection"],
      paths_to_protect: ["/api/*"],
    });
    expect(r.paths_protected).toEqual(["/api/*"]);
    expect(r.rules[0]?.definition).toContain("/api/*");
  });

  it("defaults to protecting all paths when none are given", () => {
    const r = generateWafRules({
      platform: "modsecurity",
      protect_against: ["scanner"],
    });
    expect(r.paths_protected).toEqual(["/*"]);
  });

  it("always recommends detection mode first", () => {
    const r = generateWafRules({
      platform: "aws-waf",
      protect_against: ["ssrf"],
    });
    expect(r.recommendation.toLowerCase()).toContain("detection");
    expect(r.deployment_note.length).toBeGreaterThan(0);
    expect(r.references.length).toBeGreaterThan(0);
  });

  it("is deterministic — same input produces identical output", () => {
    const input: WafGeneratorInput = {
      platform: "modsecurity",
      protect_against: ["sql-injection", "xss", "rce"],
      paths_to_protect: ["/admin/*"],
    };
    expect(generateWafRules(input)).toEqual(generateWafRules(input));
  });
});
