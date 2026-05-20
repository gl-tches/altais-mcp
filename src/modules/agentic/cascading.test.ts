import { describe, expect, it } from "vitest";
import { auditCascadingFailures } from "./cascading.js";

describe("auditCascadingFailures — positive", () => {
  it("flags a missing kill switch", () => {
    const f = auditCascadingFailures({ config: { kill_switch: false } });
    const hit = f.find((x) => x.rule === "cascading-no-kill-switch");
    expect(hit?.severity).toBe("high");
  });

  it("flags missing circuit breakers and isolation", () => {
    const f = auditCascadingFailures({
      config: { circuit_breakers: false, agent_isolation: false },
    });
    expect(f.map((x) => x.rule)).toEqual(
      expect.arrayContaining(["cascading-no-circuit-breakers", "cascading-no-agent-isolation"]),
    );
  });

  it("flags an unbounded blast radius", () => {
    const f = auditCascadingFailures({ config: { blast_radius_limits: false } });
    expect(f.some((x) => x.rule === "cascading-unbounded-blast-radius")).toBe(true);
  });

  it("flags a missing chain-depth limit", () => {
    const f = auditCascadingFailures({ config: { kill_switch: true } });
    expect(f.some((x) => x.rule === "cascading-no-chain-depth-limit")).toBe(true);
  });

  it("flags an excessively high chain-depth limit", () => {
    const f = auditCascadingFailures({ config: { max_agent_chain_depth: 500 } });
    expect(f.some((x) => x.rule === "cascading-chain-depth-too-high")).toBe(true);
  });
});

describe("auditCascadingFailures — negative", () => {
  it("returns nothing for a resilient config", () => {
    const f = auditCascadingFailures({
      config: {
        kill_switch: true,
        circuit_breakers: true,
        blast_radius_limits: true,
        agent_isolation: true,
        failure_detection: true,
        rate_limits_between_agents: true,
        max_agent_chain_depth: 5,
      },
    });
    expect(f).toHaveLength(0);
  });

  it("returns nothing when no config is supplied", () => {
    expect(auditCascadingFailures({})).toHaveLength(0);
  });

  it("does not flag a reasonable chain-depth limit", () => {
    const f = auditCascadingFailures({ config: { max_agent_chain_depth: 8 } });
    expect(f.some((x) => x.rule.startsWith("cascading-chain-depth"))).toBe(false);
    expect(f.some((x) => x.rule === "cascading-no-chain-depth-limit")).toBe(false);
  });
});

describe("auditCascadingFailures — shape & determinism", () => {
  it("produces deterministic IDs across runs", () => {
    const a = auditCascadingFailures({ config: { kill_switch: false } });
    const b = auditCascadingFailures({ config: { kill_switch: false } });
    expect(a.map((x) => x.id)).toEqual(b.map((x) => x.id));
  });

  it("tags every finding with the module, a CWE, and ASI08", () => {
    const f = auditCascadingFailures({ config: { kill_switch: false } });
    expect(f.length).toBeGreaterThan(0);
    for (const x of f) {
      expect(x.module).toBe("agentic");
      expect((x.cwe ?? []).length).toBeGreaterThan(0);
      expect(x.tags).toContain("agentic");
      expect(x.tags).toContain("ASI08");
    }
  });
});
