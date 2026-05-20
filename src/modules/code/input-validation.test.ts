import { describe, expect, it } from "vitest";
import { checkInputValidation, type InputValidationLanguage } from "./input-validation.js";

const has = (source: string, language: InputValidationLanguage, rule: string): boolean =>
  checkInputValidation({ source, language }).some((f) => f.rule === rule);

describe("checkInputValidation — missing validator", () => {
  it("flags request input used with no validator", () => {
    expect(
      has("const name = req.body.name;\nsave(name);\n", "javascript", "unvalidated-request-input"),
    ).toBe(true);
  });

  it("does not flag request input when Zod is used", () => {
    const src = "const data = schema.parse(req.body);\nconst x = z.string();\n";
    expect(has(src, "typescript", "unvalidated-request-input")).toBe(false);
  });

  it("does not flag request input when express-validator is used", () => {
    const src = "router.post('/', body('name').isString(), (req, res) => { use(req.body); });\n";
    expect(has(src, "javascript", "unvalidated-request-input")).toBe(false);
  });

  it("flags Python request.form used with no pydantic model", () => {
    expect(has("name = request.form['name']\n", "python", "unvalidated-request-input")).toBe(true);
  });

  it("does not flag code that reads no request input", () => {
    expect(has("const x = 1 + 2;\n", "javascript", "unvalidated-request-input")).toBe(false);
  });
});

describe("checkInputValidation — parseInt radix", () => {
  it("flags parseInt without a radix", () => {
    expect(has("const n = parseInt(input);\n", "javascript", "parseint-missing-radix")).toBe(true);
  });

  it("accepts parseInt with a radix", () => {
    expect(has("const n = parseInt(input, 10);\n", "javascript", "parseint-missing-radix")).toBe(
      false,
    );
  });
});

describe("checkInputValidation — unbounded regex", () => {
  it("flags a regex applied directly to request input", () => {
    expect(
      has("if (req.body.email.match(re)) {}\n", "javascript", "unbounded-regex-on-input"),
    ).toBe(true);
  });

  it("does not flag a regex on a non-request value", () => {
    expect(has("if (constant.match(re)) {}\n", "javascript", "unbounded-regex-on-input")).toBe(
      false,
    );
  });

  it("ignores commented-out code", () => {
    expect(has("// const n = parseInt(input);\n", "javascript", "parseint-missing-radix")).toBe(
      false,
    );
  });
});

describe("checkInputValidation — finding shape", () => {
  it("produces deterministic finding IDs across runs", () => {
    const src = "const n = parseInt(req.query.page);\n";
    const a = checkInputValidation({ source: src, language: "javascript", filename: "h.js" });
    const b = checkInputValidation({ source: src, language: "javascript", filename: "h.js" });
    expect(a.map((f) => f.id)).toEqual(b.map((f) => f.id));
  });

  it("tags every finding with the code module and a CWE", () => {
    const findings = checkInputValidation({
      source: "const n = parseInt(req.query.page);\n",
      language: "javascript",
    });
    expect(findings.length).toBeGreaterThan(0);
    for (const f of findings) {
      expect(f.module).toBe("code");
      expect(f.tags).toContain("code");
      expect(f.cwe?.length ?? 0).toBeGreaterThan(0);
    }
  });
});
