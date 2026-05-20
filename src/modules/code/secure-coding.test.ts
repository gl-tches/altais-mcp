import { describe, expect, it } from "vitest";
import { reviewSecureCoding, type SecureCodingLanguage } from "./secure-coding.js";

const has = (source: string, language: SecureCodingLanguage, rule: string): boolean =>
  reviewSecureCoding({ source, language }).some((f) => f.rule === rule);

describe("reviewSecureCoding — format strings", () => {
  it("flags printf with a non-literal first argument", () => {
    expect(has("printf(userInput);\n", "c", "format-string-non-literal")).toBe(true);
  });

  it("accepts printf with a string literal format", () => {
    expect(has('printf("%s", userInput);\n', "c", "format-string-non-literal")).toBe(false);
  });

  it("flags fprintf whose format argument is non-literal", () => {
    expect(has("fprintf(stderr, msg);\n", "cpp", "format-string-non-literal")).toBe(true);
  });

  it("accepts fprintf with a literal format argument", () => {
    expect(has('fprintf(stderr, "error: %s", msg);\n', "c", "format-string-non-literal")).toBe(
      false,
    );
  });
});

describe("reviewSecureCoding — dangerous APIs", () => {
  it("flags system()", () => {
    expect(has('system("ls " + dir);\n', "c", "dangerous-api-system")).toBe(true);
  });

  it("flags eval in javascript", () => {
    expect(has("eval(payload);\n", "javascript", "dangerous-api-system")).toBe(true);
  });

  it("flags subprocess in python", () => {
    expect(has("subprocess.call(cmd)\n", "python", "dangerous-api-system")).toBe(true);
  });

  it("does not flag an ordinary function call", () => {
    expect(has("compute(value);\n", "c", "dangerous-api-system")).toBe(false);
  });
});

describe("reviewSecureCoding — integer / return / TOCTOU", () => {
  it("flags an integer-overflow risk in malloc", () => {
    expect(has("char *p = malloc(n * size);\n", "c", "integer-overflow-risk")).toBe(true);
  });

  it("flags an ignored malloc return value", () => {
    expect(has("malloc(64);\n", "c", "unchecked-return-value")).toBe(true);
  });

  it("flags a TOCTOU access() check", () => {
    expect(has("if (access(path, R_OK) == 0) {}\n", "c", "toctou-race")).toBe(true);
  });

  it("flags a signed/unsigned comparison", () => {
    expect(has("int n = -1; if (n < buf_size) {}\n", "c", "signed-unsigned-comparison")).toBe(true);
  });
});

describe("reviewSecureCoding — switch default", () => {
  it("flags a switch with no default", () => {
    const src = "switch (x) {\n  case 1: break;\n  case 2: break;\n}\n";
    expect(has(src, "c", "missing-switch-default")).toBe(true);
  });

  it("accepts a switch that has a default", () => {
    const src = "switch (x) {\n  case 1: break;\n  default: break;\n}\n";
    expect(has(src, "c", "missing-switch-default")).toBe(false);
  });

  it("ignores commented-out code", () => {
    expect(has("// system(cmd);\n", "c", "dangerous-api-system")).toBe(false);
  });
});

describe("reviewSecureCoding — finding shape", () => {
  it("produces deterministic finding IDs across runs", () => {
    const src = "printf(userInput);\nsystem(cmd);\n";
    const a = reviewSecureCoding({ source: src, language: "c", filename: "a.c" });
    const b = reviewSecureCoding({ source: src, language: "c", filename: "a.c" });
    expect(a.map((f) => f.id)).toEqual(b.map((f) => f.id));
  });

  it("tags every finding with the code module and a CWE", () => {
    const findings = reviewSecureCoding({ source: "printf(userInput);\n", language: "c" });
    expect(findings.length).toBeGreaterThan(0);
    for (const f of findings) {
      expect(f.module).toBe("code");
      expect(f.tags).toContain("code");
      expect(f.cwe?.length ?? 0).toBeGreaterThan(0);
    }
  });
});
