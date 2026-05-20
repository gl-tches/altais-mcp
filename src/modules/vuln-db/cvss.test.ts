import { describe, expect, it } from "vitest";
import { calculateCvss, calculateCvssV31, calculateCvssV40, CvssCalcError } from "./cvss.js";

describe("CVSS v3.1 — base scoring", () => {
  it("scores the canonical 9.8 critical reference vector", () => {
    const r = calculateCvssV31("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
    expect(r.version).toBe("3.1");
    expect(r.base_score).toBe(9.8);
    expect(r.base_severity).toBe("critical");
    expect(r.score).toBe(9.8);
  });

  it("scores a scope-changed 10.0 reference vector (Log4Shell)", () => {
    const r = calculateCvssV31("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H");
    expect(r.base_score).toBe(10.0);
    expect(r.severity).toBe("critical");
  });

  it("scores a 7.5 high reference vector (Heartbleed)", () => {
    const r = calculateCvssV31("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
    expect(r.base_score).toBe(7.5);
    expect(r.base_severity).toBe("high");
  });

  it("scores a 6.1 medium reference vector (reflected XSS)", () => {
    const r = calculateCvssV31("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
    expect(r.base_score).toBe(6.1);
    expect(r.base_severity).toBe("medium");
  });

  it("exposes impact and exploitability subscores", () => {
    const r = calculateCvssV31("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
    expect(r.impact_subscore).toBeGreaterThan(0);
    expect(r.exploitability_subscore).toBeGreaterThan(0);
  });
});

describe("CVSS v3.1 — temporal and environmental", () => {
  it("applies the temporal metric group when present", () => {
    const r = calculateCvssV31("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/E:U/RL:O/RC:C");
    expect(r.temporal_score).toBeDefined();
    // Temporal multipliers (E:U=0.91, RL:O=0.95) reduce the 9.8 base.
    expect(r.temporal_score).toBeLessThan(9.8);
    expect(r.score).toBe(r.temporal_score);
    expect(r.metric_groups.temporal).toBeDefined();
  });

  it("applies the environmental metric group when present", () => {
    const r = calculateCvssV31(
      "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/CR:L/IR:L/AR:L/MC:L/MI:L/MA:L",
    );
    expect(r.environmental_score).toBeDefined();
    // Lowered security requirements and modified impacts reduce the score.
    expect(r.environmental_score).toBeLessThan(9.8);
    expect(r.score).toBe(r.environmental_score);
    expect(r.metric_groups.environmental).toBeDefined();
  });

  it("leaves the base score unchanged when no extra groups are given", () => {
    const r = calculateCvssV31("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
    expect(r.temporal_score).toBeUndefined();
    expect(r.environmental_score).toBeUndefined();
    expect(r.score).toBe(r.base_score);
  });
});

describe("CVSS v4.0 — full four-group scoring", () => {
  it("scores a maximum-severity Base-only vector at 10.0", () => {
    const r = calculateCvssV40("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H");
    expect(r.version).toBe("4.0");
    expect(r.macro_vector).toMatch(/^\d{6}$/);
    expect(r.base_score).toBe(10.0);
    expect(r.severity).toBe("critical");
  });

  it("scores a no-impact Base vector at 0.0", () => {
    const r = calculateCvssV40("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N/SC:N/SI:N/SA:N");
    expect(r.base_score).toBe(0.0);
    expect(r.severity).toBe("info");
  });

  it("derives a MacroVector and a score in range for a mid vector", () => {
    const r = calculateCvssV40("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N");
    expect(r.macro_vector).toMatch(/^\d{6}$/);
    expect(r.base_score).toBeGreaterThan(0);
    expect(r.base_score).toBeLessThanOrEqual(10);
  });

  it("parses all four metric groups when present", () => {
    const r = calculateCvssV40(
      "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H/E:P/CR:H/IR:M/AR:L/S:P/AU:Y/R:U/V:D/RE:L/U:Red",
    );
    expect(Object.keys(r.metric_groups.base).length).toBe(11);
    expect(r.metric_groups.threat.E).toBe("P");
    expect(r.metric_groups.environmental.CR).toBe("H");
    expect(r.metric_groups.supplemental.AU).toBe("Y");
    expect(r.note).toMatch(/MacroVector/);
  });

  it("the Threat metric E lowers the score relative to the base default", () => {
    const high = calculateCvssV40(
      "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
    );
    const lower = calculateCvssV40(
      "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/E:U",
    );
    expect(lower.base_score).toBeLessThanOrEqual(high.base_score);
  });

  it("is deterministic across repeated computation", () => {
    const v = "CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:L/VA:N/SC:N/SI:N/SA:N";
    expect(calculateCvssV40(v).base_score).toBe(calculateCvssV40(v).base_score);
  });
});

describe("CVSS — dispatch and error handling", () => {
  it("dispatches a v3.1 vector to the v3.1 calculator", () => {
    const r = calculateCvss("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
    expect(r.version).toBe("3.1");
  });

  it("dispatches a v4.0 vector to the v4.0 calculator", () => {
    const r = calculateCvss("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H");
    expect(r.version).toBe("4.0");
  });

  it("throws CvssCalcError on an unsupported prefix", () => {
    expect(() => calculateCvss("CVSS:2.0/AV:N")).toThrow(CvssCalcError);
  });

  it("throws CvssCalcError on a v3.1 vector missing a base metric", () => {
    expect(() => calculateCvss("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H")).toThrow(CvssCalcError);
  });

  it("throws CvssCalcError on a v3.1 invalid metric value", () => {
    expect(() => calculateCvss("CVSS:3.1/AV:Z/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")).toThrow(
      CvssCalcError,
    );
  });

  it("throws CvssCalcError on a v4.0 vector missing a base metric", () => {
    expect(() => calculateCvss("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H")).toThrow(
      CvssCalcError,
    );
  });

  it("throws CvssCalcError on an unknown v4.0 metric", () => {
    expect(() =>
      calculateCvss("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H/ZZ:Q"),
    ).toThrow(CvssCalcError);
  });

  it("throws CvssCalcError on a malformed segment", () => {
    expect(() => calculateCvss("CVSS:3.1/AV/AC:L")).toThrow(CvssCalcError);
  });
});
