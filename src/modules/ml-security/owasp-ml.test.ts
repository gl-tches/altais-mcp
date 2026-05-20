import { describe, expect, it } from "vitest";
import { checkOwaspMl } from "./owasp-ml.js";

describe("checkOwaspMl — coverage", () => {
  it("marks every category needs_review with an empty config", () => {
    const r = checkOwaspMl({});
    expect(r.categories).toHaveLength(10);
    expect(r.categories.every((c) => c.status === "needs_review")).toBe(true);
    expect(r.findings).toHaveLength(10);
  });

  it("marks a covered category as covered and emits no finding for it", () => {
    const r = checkOwaspMl({ config: { data_validation: true } });
    const ml02 = r.categories.find((c) => c.id === "ML02");
    expect(ml02?.status).toBe("covered");
    expect(r.findings.some((f) => f.rule === "owasp-ml02-data-poisoning")).toBe(false);
  });

  it("marks every category covered when all controls are present", () => {
    const r = checkOwaspMl({
      config: {
        input_validation: true,
        data_validation: true,
        inversion_defenses: true,
        membership_inference_defenses: true,
        model_theft_controls: true,
        supply_chain_verified: true,
        transfer_learning_reviewed: true,
        skewing_monitored: true,
        output_integrity_verified: true,
        training_access_controlled: true,
      },
    });
    expect(r.categories.every((c) => c.status === "covered")).toBe(true);
    expect(r.findings).toHaveLength(0);
  });

  it("includes ML01 through ML10 in order", () => {
    const ids = checkOwaspMl({}).categories.map((c) => c.id);
    expect(ids).toEqual([
      "ML01",
      "ML02",
      "ML03",
      "ML04",
      "ML05",
      "ML06",
      "ML07",
      "ML08",
      "ML09",
      "ML10",
    ]);
  });

  it("every category result carries a detection hint", () => {
    for (const c of checkOwaspMl({}).categories) {
      expect(c.detection_hint.length).toBeGreaterThan(0);
    }
  });
});

describe("checkOwaspMl — shape and determinism", () => {
  it("produces deterministic finding IDs", () => {
    const a = checkOwaspMl({ config: { data_validation: true } });
    const b = checkOwaspMl({ config: { data_validation: true } });
    expect(a.findings.map((f) => f.id)).toEqual(b.findings.map((f) => f.id));
  });

  it("tags every finding with the ml_security module, ml-security tag, and a CWE", () => {
    const findings = checkOwaspMl({}).findings;
    expect(findings.length).toBeGreaterThan(0);
    for (const f of findings) {
      expect(f.module).toBe("ml_security");
      expect(f.tags).toContain("ml-security");
      expect(f.cwe?.length ?? 0).toBeGreaterThan(0);
    }
  });
});
