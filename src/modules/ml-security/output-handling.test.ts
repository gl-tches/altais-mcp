import { describe, expect, it } from "vitest";
import { auditOutputHandling } from "./output-handling.js";

const rules = (input: Parameters<typeof auditOutputHandling>[0]): string[] =>
  auditOutputHandling(input).map((f) => f.rule);

describe("auditOutputHandling — source sinks", () => {
  it("flags LLM output written into innerHTML", () => {
    expect(rules({ source: "el.innerHTML = completion;" })).toContain("output-handling-into-html");
  });

  it("flags LLM output interpolated into SQL", () => {
    expect(
      rules({ source: 'cursor.execute(f"SELECT * FROM t WHERE x = {llm_output}")' }),
    ).toContain("output-handling-into-sql");
  });

  it("flags LLM output passed into a shell", () => {
    expect(rules({ source: "os.system(model_output)" })).toContain("output-handling-into-shell");
  });

  it("flags LLM output passed into eval", () => {
    expect(rules({ source: "eval(generated_code)" })).toContain("output-handling-into-eval");
  });

  it("flags LLM output used to build a file path", () => {
    expect(rules({ source: "open(llm_response)" })).toContain("output-handling-into-file-path");
  });

  it("does not flag code that only uses non-LLM variables", () => {
    expect(rules({ source: "el.innerHTML = staticTemplate;" })).not.toContain(
      "output-handling-into-html",
    );
  });
});

describe("auditOutputHandling — config", () => {
  it("flags missing encoding, parameterization, and shell safety", () => {
    const r = rules({
      config: { html_encoded: false, sql_parameterized: false, shell_safe: false },
    });
    expect(r).toContain("output-handling-no-html-encoding");
    expect(r).toContain("output-handling-no-sql-parameterization");
    expect(r).toContain("output-handling-shell-unsafe");
  });

  it("flags output treated as trusted and missing schema validation", () => {
    const r = rules({ config: { treated_as_trusted: true, schema_validated: false } });
    expect(r).toContain("output-handling-treated-as-trusted");
    expect(r).toContain("output-handling-no-schema-validation");
  });

  it("returns no findings for a fully hardened output-handling config", () => {
    expect(
      auditOutputHandling({
        config: {
          html_encoded: true,
          sql_parameterized: true,
          shell_safe: true,
          schema_validated: true,
          treated_as_trusted: false,
        },
      }),
    ).toHaveLength(0);
  });
});

describe("auditOutputHandling — severity, shape, and determinism", () => {
  it("rates a shell sink as critical", () => {
    const findings = auditOutputHandling({ source: "os.system(model_output)" });
    expect(findings.some((f) => f.severity === "critical")).toBe(true);
  });

  it("produces deterministic finding IDs", () => {
    const a = auditOutputHandling({ source: "eval(generated_code)", filename: "app.js" });
    const b = auditOutputHandling({ source: "eval(generated_code)", filename: "app.js" });
    expect(a.map((f) => f.id)).toEqual(b.map((f) => f.id));
  });

  it("tags every finding with the ml_security module, ml-security tag, and a CWE", () => {
    const findings = auditOutputHandling({
      source: "el.innerHTML = completion;",
      config: { shell_safe: false },
    });
    expect(findings.length).toBeGreaterThan(0);
    for (const f of findings) {
      expect(f.module).toBe("ml_security");
      expect(f.tags).toContain("ml-security");
      expect(f.cwe?.length ?? 0).toBeGreaterThan(0);
    }
  });
});
