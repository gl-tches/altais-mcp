import { describe, expect, it } from "vitest";
import { generateRedTeamScope, RedTeamScopeError } from "./red-team.js";

const base = {
  objectives: ["demonstrate access to the crown-jewel database"],
  constraints: [],
  duration_weeks: 4,
  assumed_breach: false,
};

describe("generateRedTeamScope — TTP tiering", () => {
  it("emulates a small TTP set for an opportunistic actor", () => {
    const r = generateRedTeamScope({ ...base, threat_actor_profile: "opportunistic" });
    expect(r.ttps.length).toBeGreaterThan(0);
  });

  it("emulates more TTPs for a nation-state actor than an opportunistic one", () => {
    const opp = generateRedTeamScope({ ...base, threat_actor_profile: "opportunistic" });
    const apt = generateRedTeamScope({ ...base, threat_actor_profile: "nation-state" });
    expect(apt.ttps.length).toBeGreaterThan(opp.ttps.length);
  });

  it("includes a supply-chain technique for a nation-state actor", () => {
    const r = generateRedTeamScope({ ...base, threat_actor_profile: "nation-state" });
    expect(r.ttps.some((t) => t.technique_id === "T1195")).toBe(true);
  });

  it("maps every TTP to an ATT&CK technique id", () => {
    const r = generateRedTeamScope({ ...base, threat_actor_profile: "organized-crime" });
    for (const t of r.ttps) {
      expect(t.technique_id).toMatch(/^T\d{4}$/);
      expect(t.technique.length).toBeGreaterThan(0);
    }
  });

  it("starts an insider engagement with valid accounts", () => {
    const r = generateRedTeamScope({ ...base, threat_actor_profile: "insider" });
    expect(r.ttps[0]?.technique_id).toBe("T1078");
  });
});

describe("generateRedTeamScope — scope content", () => {
  it("adjusts success criteria for an assumed-breach start", () => {
    const r = generateRedTeamScope({
      ...base,
      threat_actor_profile: "organized-crime",
      assumed_breach: true,
    });
    expect(r.success_criteria.join(" ")).toContain("assumed-breach");
  });

  it("includes deconfliction procedures and flags", () => {
    const r = generateRedTeamScope({ ...base, threat_actor_profile: "opportunistic" });
    expect(r.deconfliction.length).toBeGreaterThan(0);
    expect(r.flags.length).toBeGreaterThan(0);
    expect(r.references.join(" ")).toContain("attack.mitre.org");
  });

  it("folds client constraints into the rules of engagement", () => {
    const r = generateRedTeamScope({
      ...base,
      threat_actor_profile: "insider",
      constraints: ["no impact to payroll runs"],
    });
    expect(r.rules_of_engagement.join(" ")).toContain("no impact to payroll runs");
  });
});

describe("generateRedTeamScope — validation and determinism", () => {
  it("rejects an empty objectives list", () => {
    expect(() =>
      generateRedTeamScope({ ...base, objectives: [], threat_actor_profile: "insider" }),
    ).toThrow(RedTeamScopeError);
  });

  it("rejects an out-of-range duration", () => {
    expect(() =>
      generateRedTeamScope({ ...base, duration_weeks: 0, threat_actor_profile: "insider" }),
    ).toThrow(RedTeamScopeError);
  });

  it("is deterministic for the same input", () => {
    const input = { ...base, threat_actor_profile: "nation-state" as const };
    expect(JSON.stringify(generateRedTeamScope(input))).toBe(
      JSON.stringify(generateRedTeamScope(input)),
    );
  });
});
