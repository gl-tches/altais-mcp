import { describe, expect, it } from "vitest";
import { checkCanary } from "./canary.js";

const rules = (config: Parameters<typeof checkCanary>[0]["config"]): string[] =>
  checkCanary({ config }).map((f) => f.rule);

describe("checkCanary — deployment gaps", () => {
  it("flags no canary tokens deployed", () => {
    expect(rules({ canary_tokens_deployed: false })).toContain("no-canary-tokens");
  });

  it("flags no honeypots deployed", () => {
    expect(rules({ honeypots_deployed: false })).toContain("no-honeypots");
  });

  it("flags deployed deception with no alerting", () => {
    expect(rules({ canary_tokens_deployed: true, alerting_enabled: false })).toContain(
      "no-canary-alerting",
    );
  });

  it("flags deployed deception with no alert routing", () => {
    expect(rules({ honeypots_deployed: true })).toContain("no-canary-alert-routing");
  });
});

describe("checkCanary — coverage", () => {
  it("flags coverage gaps for uncovered sensitive areas", () => {
    const r = rules({
      canary_tokens_deployed: true,
      alert_routing: "secops-oncall",
      coverage_areas: ["database"],
      monitored_assets: ["prod-db"],
    });
    expect(r).toContain("canary-coverage-gap");
    expect(r).not.toContain("no-canary-alert-routing");
  });

  it("flags a missing monitored-asset inventory", () => {
    expect(
      rules({
        honeypots_deployed: true,
        alert_routing: "secops-oncall",
        coverage_areas: ["database", "credentials", "filesystem", "cloud", "endpoints"],
      }),
    ).toContain("no-monitored-assets");
  });

  it("does not flag a complete deception programme", () => {
    const r = rules({
      canary_tokens_deployed: true,
      honeypots_deployed: true,
      alerting_enabled: true,
      alert_routing: "secops-oncall",
      coverage_areas: ["database", "credentials", "filesystem", "cloud", "endpoints"],
      monitored_assets: ["prod-db", "vault"],
    });
    expect(r).toHaveLength(0);
  });
});

describe("checkCanary — finding shape", () => {
  it("produces deterministic finding IDs across runs", () => {
    const a = checkCanary({ config: { canary_tokens_deployed: false } });
    const b = checkCanary({ config: { canary_tokens_deployed: false } });
    expect(a.map((f) => f.id)).toEqual(b.map((f) => f.id));
  });

  it("tags every finding with the incident module, a CWE, and medium severity", () => {
    const findings = checkCanary({
      config: { canary_tokens_deployed: false, honeypots_deployed: false },
    });
    expect(findings.length).toBeGreaterThan(0);
    for (const f of findings) {
      expect(f.module).toBe("incident");
      expect(f.tags).toContain("incident");
      expect(f.cwe?.length ?? 0).toBeGreaterThan(0);
      expect(f.severity).toBe("medium");
    }
  });
});
