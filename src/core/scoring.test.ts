import { describe, expect, it } from "vitest";
import {
  CvssError,
  computeCvssV31,
  cvssSeverity,
  parseCvssV31Vector,
  riskSummary,
  scoreCvss,
} from "./scoring.js";
import type { Finding } from "./types.js";

describe("parseCvssV31Vector", () => {
  it("parses a complete v3.1 vector", () => {
    const m = parseCvssV31Vector("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
    expect(m).toEqual({
      attack_vector: "N",
      attack_complexity: "L",
      privileges_required: "N",
      user_interaction: "N",
      scope: "U",
      confidentiality: "H",
      integrity: "H",
      availability: "H",
    });
  });

  it("rejects non-v3.1 prefix", () => {
    expect(() => parseCvssV31Vector("CVSS:2.0/AV:N")).toThrow(CvssError);
  });

  it("rejects missing required metric", () => {
    expect(() => parseCvssV31Vector("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H")).toThrow(
      /missing required metric: A/,
    );
  });

  it("rejects invalid metric value", () => {
    expect(() => parseCvssV31Vector("CVSS:3.1/AV:X/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")).toThrow(
      /invalid value for AV/,
    );
  });
});

describe("computeCvssV31", () => {
  // Reference scores from the official FIRST calculator.
  const cases: readonly (readonly [string, number])[] = [
    ["CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8],
    ["CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", 10.0],
    ["CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H", 8.8],
    ["CVSS:3.1/AV:L/AC:L/PR:H/UI:N/S:U/C:N/I:N/A:H", 4.4],
    ["CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N", 3.1],
    ["CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N", 0.0],
    ["CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:N", 5.4],
  ];

  for (const [vector, expected] of cases) {
    it(`scores ${vector} as ${expected}`, () => {
      const m = parseCvssV31Vector(vector);
      const { base_score } = computeCvssV31(m);
      expect(base_score).toBeCloseTo(expected, 1);
    });
  }
});

describe("cvssSeverity", () => {
  it("maps thresholds correctly", () => {
    expect(cvssSeverity(0)).toBe("info");
    expect(cvssSeverity(0.1)).toBe("low");
    expect(cvssSeverity(3.9)).toBe("low");
    expect(cvssSeverity(4.0)).toBe("medium");
    expect(cvssSeverity(6.9)).toBe("medium");
    expect(cvssSeverity(7.0)).toBe("high");
    expect(cvssSeverity(8.9)).toBe("high");
    expect(cvssSeverity(9.0)).toBe("critical");
    expect(cvssSeverity(10)).toBe("critical");
  });
});

describe("scoreCvss", () => {
  it("returns a populated v3.1 score with subscores", () => {
    const r = scoreCvss("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
    expect(r.version).toBe("3.1");
    expect(r.base_score).toBeCloseTo(9.8, 1);
    expect(r.severity).toBe("critical");
    expect(r.impact_subscore).toBeGreaterThan(0);
    expect(r.exploitability_subscore).toBeGreaterThan(0);
  });

  it("rejects v4.0 vectors (scored by calculateCvssV40, not scoreCvss)", () => {
    expect(() =>
      scoreCvss("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"),
    ).toThrow(CvssError);
  });

  it("rejects unknown prefix", () => {
    expect(() => scoreCvss("CVSS:2.0/AV:N/AC:L")).toThrow(CvssError);
  });
});

function f(severity: Finding["severity"], id: string): Finding {
  return {
    id,
    module: "test",
    rule: "rule",
    severity,
    title: "x",
    description: "x",
    remediation: "x",
    references: [],
    tags: [],
    status: "open",
  };
}

describe("riskSummary", () => {
  it("returns 0 for empty input", () => {
    expect(riskSummary([])).toBe(0);
  });

  it("scales with severity weight", () => {
    const low = riskSummary([f("low", "1"), f("low", "2")]);
    const high = riskSummary([f("high", "1"), f("high", "2")]);
    expect(high).toBeGreaterThan(low);
  });

  it("caps below 100", () => {
    const findings = Array.from({ length: 100 }, (_, i) => f("critical", String(i)));
    const score = riskSummary(findings);
    expect(score).toBeLessThanOrEqual(100);
    expect(score).toBeGreaterThan(90);
  });

  it("treats info findings as zero contribution", () => {
    const infoOnly = riskSummary([f("info", "1"), f("info", "2"), f("info", "3")]);
    expect(infoOnly).toBe(0);
  });
});
