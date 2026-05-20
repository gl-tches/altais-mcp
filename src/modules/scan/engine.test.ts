import { describe, expect, it } from "vitest";
import { runPatterns } from "./engine.js";
import type { Pattern } from "./patterns/types.js";

const dangerousJs: Pattern = {
  id: "dangerous-js",
  category: "injection",
  title: "test",
  description: "test",
  severity: "high",
  cwe: ["CWE-0"],
  remediation: "test",
  references: [],
  languages: ["javascript", "typescript"],
  matcher: { type: "regex", regex: /eval\s*\(/ },
};

const pythonOnly: Pattern = {
  id: "python-only",
  category: "injection",
  title: "test",
  description: "test",
  severity: "high",
  cwe: ["CWE-0"],
  remediation: "test",
  references: [],
  languages: ["python"],
  matcher: { type: "regex", regex: /__import__\s*\(/ },
};

describe("runPatterns", () => {
  it("only runs patterns whose language matches", () => {
    const findings = runPatterns([dangerousJs, pythonOnly], {
      source: "eval(x)",
      language: "javascript",
    });
    expect(findings.map((f) => f.rule)).toEqual(["dangerous-js"]);
  });

  it("attaches deterministic finding IDs", () => {
    const a = runPatterns([dangerousJs], {
      source: "eval(x)",
      language: "javascript",
      file: "a.js",
    });
    const b = runPatterns([dangerousJs], {
      source: "eval(x)",
      language: "javascript",
      file: "a.js",
    });
    expect(a[0]?.id).toBe(b[0]?.id);
  });

  it("computes 1-indexed line numbers", () => {
    const findings = runPatterns([dangerousJs], {
      source: "// nothing here\nconst y = eval('x')\n",
      language: "javascript",
    });
    expect(findings).toHaveLength(1);
    expect(findings[0]?.location?.line_start).toBe(2);
  });

  it("does not fire on commented code", () => {
    const findings = runPatterns([dangerousJs], {
      source: "// eval('bad') in a comment\n",
      language: "javascript",
    });
    expect(findings).toHaveLength(0);
  });

  it("respects rule filter by id", () => {
    const findings = runPatterns(
      [dangerousJs, pythonOnly],
      { source: "eval(x)", language: "javascript" },
      { rules: ["python-only"] },
    );
    expect(findings).toHaveLength(0);
  });

  it("respects rule filter by category", () => {
    const findings = runPatterns(
      [dangerousJs],
      { source: "eval(x)", language: "javascript" },
      { rules: ["injection"] },
    );
    expect(findings).toHaveLength(1);
  });

  it("caps total findings via maxFindings", () => {
    const findings = runPatterns(
      [dangerousJs],
      { source: "eval(a); eval(b); eval(c); eval(d);", language: "javascript" },
      { maxFindings: 2 },
    );
    expect(findings).toHaveLength(2);
  });

  it("emits a finding with category as a tag", () => {
    const findings = runPatterns([dangerousJs], { source: "eval(x)", language: "javascript" });
    expect(findings[0]?.tags).toContain("injection");
  });
});
