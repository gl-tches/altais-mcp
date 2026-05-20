import { describe, expect, it } from "vitest";
import { auditRogueAgents } from "./rogue-agents.js";

describe("auditRogueAgents — positive", () => {
  it("flags a missing behavioral baseline", () => {
    const f = auditRogueAgents({ config: { behavioral_baseline: false } });
    expect(f.some((x) => x.rule === "rogue-no-behavioral-baseline")).toBe(true);
  });

  it("flags missing anomaly detection as high", () => {
    const f = auditRogueAgents({ config: { anomaly_detection: false } });
    const hit = f.find((x) => x.rule === "rogue-no-anomaly-detection");
    expect(hit?.severity).toBe("high");
  });

  it("flags partial anomaly-detection coverage", () => {
    const f = auditRogueAgents({
      config: { anomaly_detection: true, anomaly_detection_coverage: "partial" },
    });
    expect(f.some((x) => x.rule === "rogue-partial-anomaly-coverage")).toBe(true);
  });

  it("flags missing inventory and governance", () => {
    const f = auditRogueAgents({
      config: { agent_inventory: false, agent_governance_policy: false },
    });
    expect(f.map((x) => x.rule)).toEqual(
      expect.arrayContaining(["rogue-no-agent-inventory", "rogue-no-governance-policy"]),
    );
  });

  it("flags missing sandboxing, audit logging, and revocation", () => {
    const f = auditRogueAgents({
      config: { sandboxing: false, audit_logging: false, revocation_capability: false },
    });
    expect(f.map((x) => x.rule)).toEqual(
      expect.arrayContaining([
        "rogue-no-sandboxing",
        "rogue-no-audit-logging",
        "rogue-no-revocation",
      ]),
    );
  });
});

describe("auditRogueAgents — negative", () => {
  it("returns nothing for a governed config", () => {
    const f = auditRogueAgents({
      config: {
        behavioral_baseline: true,
        anomaly_detection: true,
        anomaly_detection_coverage: "comprehensive",
        agent_inventory: true,
        agent_governance_policy: true,
        sandboxing: true,
        audit_logging: true,
        revocation_capability: true,
      },
    });
    expect(f).toHaveLength(0);
  });

  it("returns nothing when no config is supplied", () => {
    expect(auditRogueAgents({})).toHaveLength(0);
  });
});

describe("auditRogueAgents — shape & determinism", () => {
  it("produces deterministic IDs across runs", () => {
    const a = auditRogueAgents({ config: { anomaly_detection: false } });
    const b = auditRogueAgents({ config: { anomaly_detection: false } });
    expect(a.map((x) => x.id)).toEqual(b.map((x) => x.id));
  });

  it("tags every finding with the module, a CWE, and ASI10", () => {
    const f = auditRogueAgents({ config: { anomaly_detection: false } });
    expect(f.length).toBeGreaterThan(0);
    for (const x of f) {
      expect(x.module).toBe("agentic");
      expect((x.cwe ?? []).length).toBeGreaterThan(0);
      expect(x.tags).toContain("agentic");
      expect(x.tags).toContain("ASI10");
    }
  });
});
