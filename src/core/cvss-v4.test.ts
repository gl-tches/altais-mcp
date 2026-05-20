import { describe, expect, it } from "vitest";
import { calculateCvssV40 } from "./cvss-v4.js";
import { CvssError } from "./scoring.js";

describe("calculateCvssV40", () => {
  it("scores a maximum-severity Base-only vector at 10.0", () => {
    const r = calculateCvssV40("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H");
    expect(r.version).toBe("4.0");
    expect(r.macro_vector).toMatch(/^\d{6}$/);
    expect(r.base_score).toBe(10.0);
    expect(r.severity).toBe("critical");
  });

  it("scores the canonical 9.3 critical reference vector", () => {
    // FIRST CVSS v4.0 calculator: this vector evaluates to 9.3 (critical).
    const r = calculateCvssV40("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N");
    expect(r.base_score).toBe(9.3);
    expect(r.severity).toBe("critical");
  });

  it("scores a no-impact Base vector at 0.0 (info)", () => {
    const r = calculateCvssV40("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N/SC:N/SI:N/SA:N");
    expect(r.base_score).toBe(0.0);
    expect(r.severity).toBe("info");
  });

  it("parses all four metric groups when present", () => {
    const r = calculateCvssV40(
      "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H/E:P/CR:H/IR:M/AR:L/S:P/AU:Y/R:U/V:D/RE:L/U:Red",
    );
    expect(Object.keys(r.metric_groups.base).length).toBe(11);
    expect(r.metric_groups.threat.E).toBe("P");
    expect(r.metric_groups.environmental.CR).toBe("H");
    expect(r.metric_groups.supplemental.AU).toBe("Y");
  });

  it("is deterministic across repeated computation", () => {
    const v = "CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:L/VA:N/SC:N/SI:N/SA:N";
    expect(calculateCvssV40(v).base_score).toBe(calculateCvssV40(v).base_score);
  });

  it("throws CvssError on a vector missing a required Base metric", () => {
    expect(() => calculateCvssV40("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H")).toThrow(
      CvssError,
    );
  });

  it("throws CvssError on an unknown metric", () => {
    expect(() =>
      calculateCvssV40("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H/ZZ:Q"),
    ).toThrow(CvssError);
  });

  it("throws CvssError on an invalid metric value", () => {
    expect(() =>
      calculateCvssV40("CVSS:4.0/AV:Z/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H"),
    ).toThrow(CvssError);
  });

  it("throws CvssError on a malformed segment", () => {
    expect(() =>
      calculateCvssV40("CVSS:4.0/AV/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H"),
    ).toThrow(CvssError);
  });
});
