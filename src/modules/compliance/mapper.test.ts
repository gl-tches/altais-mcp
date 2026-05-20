import { describe, expect, it } from "vitest";
import type { Finding } from "../../core/types.js";
import type { ComplianceControl, ComplianceFramework } from "./frameworks.js";
import {
  findingMatchesControl,
  isHighRiskFamily,
  mapFindingsToFramework,
  normalizeCwe,
  toMappable,
  type MappableFinding,
} from "./mapper.js";

function mf(
  rule: string,
  cwe: readonly string[],
  title = rule,
  severity: MappableFinding["severity"] = "high",
): MappableFinding {
  return { id: `id:${rule}`, rule, title, severity, cwe };
}

const SQLI_CONTROL: ComplianceControl = {
  id: "SI-10",
  title: "Information Input Validation",
  family: "system-integrity",
  description: "Validates inputs.",
  cwes: ["CWE-89", "CWE-79"],
  keywords: ["sql injection", "input validation"],
};

const CRYPTO_CONTROL: ComplianceControl = {
  id: "SC-13",
  title: "Cryptographic Protection",
  family: "system-communications",
  description: "Uses strong crypto.",
  cwes: ["CWE-327"],
  keywords: ["weak cipher", "cryptography"],
};

const AUTH_CONTROL: ComplianceControl = {
  id: "IA-2",
  title: "Identification and Authentication",
  family: "identification-authentication",
  description: "Authenticates users.",
  cwes: ["CWE-287"],
  keywords: ["authentication"],
};

const SAMPLE_FRAMEWORK: ComplianceFramework = {
  id: "sample",
  name: "Sample Framework",
  version: "1.0",
  controls: [SQLI_CONTROL, CRYPTO_CONTROL, AUTH_CONTROL],
};

describe("normalizeCwe", () => {
  it("adds the CWE- prefix when missing", () => {
    expect(normalizeCwe("89")).toBe("CWE-89");
  });

  it("uppercases and trims an existing CWE id", () => {
    expect(normalizeCwe("  cwe-89 ")).toBe("CWE-89");
  });

  it("returns empty string for empty input", () => {
    expect(normalizeCwe("   ")).toBe("");
  });
});

describe("findingMatchesControl", () => {
  it("matches via CWE intersection", () => {
    expect(findingMatchesControl(mf("x", ["CWE-89"]), SQLI_CONTROL)).toBe(true);
  });

  it("matches a CWE without the prefix", () => {
    expect(findingMatchesControl(mf("x", ["89"]), SQLI_CONTROL)).toBe(true);
  });

  it("matches via keyword in the rule", () => {
    expect(findingMatchesControl(mf("sql-injection-check", []), SQLI_CONTROL)).toBe(true);
  });

  it("matches via keyword in the title", () => {
    expect(findingMatchesControl(mf("x", [], "Weak Cipher detected"), CRYPTO_CONTROL)).toBe(true);
  });

  it("is case-insensitive on keyword matches", () => {
    expect(findingMatchesControl(mf("WEAK-CIPHER", []), CRYPTO_CONTROL)).toBe(true);
  });

  it("does not match an unrelated finding", () => {
    expect(findingMatchesControl(mf("open-redirect", ["CWE-601"]), CRYPTO_CONTROL)).toBe(false);
  });
});

describe("isHighRiskFamily", () => {
  it("treats access-control as high risk", () => {
    expect(isHighRiskFamily("access-control")).toBe(true);
  });

  it("treats cryptography as high risk", () => {
    expect(isHighRiskFamily("cryptography")).toBe(true);
  });

  it("treats authentication families as high risk", () => {
    expect(isHighRiskFamily("identification-authentication")).toBe(true);
  });

  it("treats logging as not high risk", () => {
    expect(isHighRiskFamily("logging")).toBe(false);
  });
});

describe("mapFindingsToFramework", () => {
  it("maps a known-CWE finding to the expected control", () => {
    const r = mapFindingsToFramework([mf("sqli", ["CWE-89"])], SAMPLE_FRAMEWORK);
    const si10 = r.mappings.find((m) => m.control.id === "SI-10");
    expect(si10?.status).toBe("addressed");
    expect(si10?.matched_findings).toHaveLength(1);
  });

  it("marks unmatched controls as gaps", () => {
    const r = mapFindingsToFramework([mf("sqli", ["CWE-89"])], SAMPLE_FRAMEWORK);
    const sc13 = r.mappings.find((m) => m.control.id === "SC-13");
    expect(sc13?.status).toBe("gap");
    expect(sc13?.matched_findings).toHaveLength(0);
  });

  it("computes coverage percentage", () => {
    const r = mapFindingsToFramework([mf("sqli", ["CWE-89"])], SAMPLE_FRAMEWORK);
    expect(r.summary.total_controls).toBe(3);
    expect(r.summary.addressed).toBe(1);
    expect(r.summary.gap).toBe(2);
    expect(r.summary.coverage_pct).toBe(33);
  });

  it("reports 100% coverage when every control is addressed", () => {
    const r = mapFindingsToFramework(
      [mf("a", ["CWE-89"]), mf("b", ["CWE-327"]), mf("c", ["CWE-287"])],
      SAMPLE_FRAMEWORK,
    );
    expect(r.summary.coverage_pct).toBe(100);
  });

  it("reports 0% coverage with no findings", () => {
    const r = mapFindingsToFramework([], SAMPLE_FRAMEWORK);
    expect(r.summary.coverage_pct).toBe(0);
    expect(r.summary.addressed).toBe(0);
  });

  it("computes highest severity per control", () => {
    const r = mapFindingsToFramework(
      [mf("low", ["CWE-89"], "low", "low"), mf("crit", ["CWE-89"], "crit", "critical")],
      SAMPLE_FRAMEWORK,
    );
    const si10 = r.mappings.find((m) => m.control.id === "SI-10");
    expect(si10?.highest_severity).toBe("critical");
  });

  it("counts distinct mapped findings", () => {
    const r = mapFindingsToFramework(
      [mf("sqli", ["CWE-89"]), mf("xss", ["CWE-79"]), mf("redirect", ["CWE-601"])],
      SAMPLE_FRAMEWORK,
    );
    expect(r.summary.total_findings).toBe(3);
    expect(r.summary.mapped_findings).toBe(2);
  });

  it("preserves the framework's control order in the mappings", () => {
    const r = mapFindingsToFramework([], SAMPLE_FRAMEWORK);
    expect(r.mappings.map((m) => m.control.id)).toEqual(["SI-10", "SC-13", "IA-2"]);
  });

  it("is deterministic across repeated calls", () => {
    const findings = [mf("sqli", ["CWE-89"])];
    const a = mapFindingsToFramework(findings, SAMPLE_FRAMEWORK);
    const b = mapFindingsToFramework(findings, SAMPLE_FRAMEWORK);
    expect(JSON.stringify(a)).toBe(JSON.stringify(b));
  });
});

describe("toMappable", () => {
  it("normalizes a Finding into a MappableFinding", () => {
    const finding: Finding = {
      id: "compliance:x:abc",
      module: "scan",
      rule: "sql-injection",
      severity: "high",
      cwe: ["CWE-89"],
      title: "SQL Injection",
      description: "d",
      remediation: "r",
      references: [],
      tags: [],
      status: "open",
    };
    const m = toMappable(finding);
    expect(m).toEqual({
      id: "compliance:x:abc",
      rule: "sql-injection",
      title: "SQL Injection",
      severity: "high",
      cwe: ["CWE-89"],
    });
  });

  it("defaults missing cwe to an empty array", () => {
    const finding: Finding = {
      id: "id",
      module: "scan",
      rule: "r",
      severity: "low",
      title: "t",
      description: "d",
      remediation: "r",
      references: [],
      tags: [],
      status: "open",
    };
    expect(toMappable(finding).cwe).toEqual([]);
  });
});
