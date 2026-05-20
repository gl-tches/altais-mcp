import { describe, expect, it } from "vitest";
import type { Finding } from "../../core/types.js";
import type { AsvsControl, OwaspCategory } from "./knowledge.js";
import { mapFindingsToCategories, reportAsvs } from "./matcher.js";

function f(rule: string, cwe: readonly string[], severity: Finding["severity"] = "high"): Finding {
  return {
    id: `m:${rule}:abc`,
    module: "scan",
    rule,
    severity,
    cwe,
    title: rule,
    description: "test",
    remediation: "",
    references: [],
    tags: [],
    status: "open",
  };
}

const SAMPLE_CATEGORIES: readonly OwaspCategory[] = [
  {
    id: "A01:2025",
    name: "Broken Access Control",
    description: "BAC",
    cwes: ["CWE-22", "CWE-918", "CWE-639"],
    detection_hints: ["hint a"],
    remediation: "fix a",
  },
  {
    id: "A02:2025",
    name: "Cryptographic Failures",
    description: "crypto",
    cwes: ["CWE-327", "CWE-330"],
    detection_hints: ["hint b"],
    remediation: "fix b",
  },
];

describe("mapFindingsToCategories", () => {
  it("matches findings via CWE overlap", () => {
    const r = mapFindingsToCategories(
      [f("path-traversal-fs-request-js", ["CWE-22"])],
      SAMPLE_CATEGORIES,
      "Sample",
    );
    const a01 = r.categories.find((c) => c.id === "A01:2025");
    expect(a01?.status).toBe("covered");
    expect(a01?.matched_findings.length).toBe(1);
  });

  it("marks uncovered categories as needs_review", () => {
    const r = mapFindingsToCategories(
      [f("path-traversal-fs-request-js", ["CWE-22"])],
      SAMPLE_CATEGORIES,
      "Sample",
    );
    const a02 = r.categories.find((c) => c.id === "A02:2025");
    expect(a02?.status).toBe("needs_review");
    expect(a02?.matched_findings).toHaveLength(0);
  });

  it("normalizes CWE references that lack the `CWE-` prefix", () => {
    const r = mapFindingsToCategories([f("x", ["22"])], SAMPLE_CATEGORIES, "Sample");
    expect(r.categories[0]?.status).toBe("covered");
  });

  it("computes highest severity per category", () => {
    const r = mapFindingsToCategories(
      [f("low", ["CWE-22"], "low"), f("crit", ["CWE-918"], "critical")],
      SAMPLE_CATEGORIES,
      "Sample",
    );
    const a01 = r.categories.find((c) => c.id === "A01:2025");
    expect(a01?.highest_severity).toBe("critical");
  });

  it("summary counts cover/review", () => {
    const r = mapFindingsToCategories([f("x", ["CWE-22"])], SAMPLE_CATEGORIES, "Sample");
    expect(r.summary.covered).toBe(1);
    expect(r.summary.needs_review).toBe(1);
  });
});

const ASVS_CONTROLS: readonly AsvsControl[] = [
  {
    id: "V2.1.1",
    section: "V2",
    section_name: "Authentication",
    level: 1,
    description: "password length",
  },
  {
    id: "V2.10.4",
    section: "V2",
    section_name: "Authentication",
    level: 3,
    description: "secret mgmt",
  },
  {
    id: "V5.3.4",
    section: "V5",
    section_name: "Validation, Sanitization and Encoding",
    level: 1,
    description: "parameterized queries",
  },
  {
    id: "V6.1.1",
    section: "V6",
    section_name: "Stored Cryptography",
    level: 2,
    description: "encrypt at rest",
  },
];

describe("reportAsvs", () => {
  it("filters by level (level 1 returns only level-1 controls)", () => {
    const r = reportAsvs(ASVS_CONTROLS, { level: 1 }, [], "4.0.3");
    expect(r.controls.map((c) => c.id).sort()).toEqual(["V2.1.1", "V5.3.4"]);
  });

  it("level N returns controls at levels 1..N", () => {
    const r = reportAsvs(ASVS_CONTROLS, { level: 2 }, [], "4.0.3");
    expect(r.controls.map((c) => c.id).sort()).toEqual(["V2.1.1", "V5.3.4", "V6.1.1"]);
  });

  it("level 3 returns every control", () => {
    const r = reportAsvs(ASVS_CONTROLS, { level: 3 }, [], "4.0.3");
    expect(r.controls.length).toBe(ASVS_CONTROLS.length);
  });

  it("filters by section", () => {
    const r = reportAsvs(ASVS_CONTROLS, { level: 3, section: "V2" }, [], "4.0.3");
    expect(r.controls.every((c) => c.section === "V2")).toBe(true);
  });

  it("annotates controls with matching findings via CWE→section mapping", () => {
    const r = reportAsvs(ASVS_CONTROLS, { level: 1 }, [f("sql-injection", ["CWE-89"])], "4.0.3");
    const v5 = r.controls.find((c) => c.id === "V5.3.4");
    expect(v5?.evidence.status).toBe("covered");
    expect(v5?.evidence.matched_findings.length).toBe(1);
  });
});
