import { describe, expect, it } from "vitest";
import { auditGoalHijack } from "./goal-hijack.js";

describe("auditGoalHijack — positive", () => {
  it("flags missing instruction/data separation", () => {
    const f = auditGoalHijack({ config: { instruction_data_separation: false } });
    expect(f.some((x) => x.rule === "goal-no-instruction-data-separation")).toBe(true);
  });

  it("flags tool output reaching the planner without validation", () => {
    const f = auditGoalHijack({ config: { untrusted_tool_output_to_planner: true } });
    const hit = f.find((x) => x.rule === "goal-untrusted-tool-output-to-planner");
    expect(hit?.severity).toBe("high");
  });

  it("flags untrusted data reaching the planner", () => {
    const f = auditGoalHijack({ config: { untrusted_data_to_planner: true } });
    expect(f.some((x) => x.rule === "goal-untrusted-data-to-planner")).toBe(true);
  });

  it("flags missing goal validation and unprotected system prompt", () => {
    const f = auditGoalHijack({
      config: { goal_validation: false, system_prompt_protected: false, plan_review: false },
    });
    expect(f.map((x) => x.rule)).toEqual(
      expect.arrayContaining([
        "goal-no-goal-validation",
        "goal-system-prompt-unprotected",
        "goal-no-plan-review",
      ]),
    );
  });
});

describe("auditGoalHijack — negative", () => {
  it("returns nothing for a fully controlled config", () => {
    const f = auditGoalHijack({
      config: {
        instruction_data_separation: true,
        goal_validation: true,
        untrusted_tool_output_to_planner: false,
        untrusted_data_to_planner: false,
        system_prompt_protected: true,
        plan_review: true,
      },
    });
    expect(f).toHaveLength(0);
  });

  it("returns nothing when no config is supplied", () => {
    expect(auditGoalHijack({})).toHaveLength(0);
  });
});

describe("auditGoalHijack — shape & determinism", () => {
  it("produces deterministic IDs across runs", () => {
    const a = auditGoalHijack({ config: { instruction_data_separation: false } });
    const b = auditGoalHijack({ config: { instruction_data_separation: false } });
    expect(a.map((x) => x.id)).toEqual(b.map((x) => x.id));
  });

  it("tags every finding with the module, a CWE, and ASI01", () => {
    const f = auditGoalHijack({ config: { instruction_data_separation: false } });
    expect(f.length).toBeGreaterThan(0);
    for (const x of f) {
      expect(x.module).toBe("agentic");
      expect((x.cwe ?? []).length).toBeGreaterThan(0);
      expect(x.tags).toContain("agentic");
      expect(x.tags).toContain("ASI01");
    }
  });
});
