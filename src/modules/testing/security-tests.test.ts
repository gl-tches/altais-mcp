import { describe, expect, it } from "vitest";
import { generateSecurityTests, SecurityTestsError } from "./security-tests.js";

describe("generateSecurityTests — per language", () => {
  it("generates a pytest file for an injection class in Python", () => {
    const r = generateSecurityTests({ vulnerability_class: "injection", language: "python" });
    expect(r.framework).toBe("pytest");
    expect(r.test_file.filename).toContain(".py");
    expect(r.test_file.content).toContain("def test_rejects_malicious_input");
  });

  it("generates a Jest file for an XSS class in JavaScript", () => {
    const r = generateSecurityTests({ vulnerability_class: "xss", language: "javascript" });
    expect(r.framework).toBe("jest");
    expect(r.test_file.content).toContain("describe(");
    expect(r.test_file.content).toContain("<script>");
  });

  it("generates a Go test file for an access-control class", () => {
    const r = generateSecurityTests({
      vulnerability_class: "access-control",
      language: "go",
    });
    expect(r.test_file.filename).toContain("_test.go");
    expect(r.test_file.content).toContain("func TestRejectsMaliciousInput");
  });

  it("generates a Rust test module for a crypto class", () => {
    const r = generateSecurityTests({ vulnerability_class: "crypto", language: "rust" });
    expect(r.test_file.content).toContain("#[test]");
    expect(r.cwe).toContain("CWE-327");
  });
});

describe("generateSecurityTests — cases and metadata", () => {
  it("includes both positive and negative cases", () => {
    const r = generateSecurityTests({ vulnerability_class: "ssrf", language: "python" });
    const types = r.cases.map((c) => c.type);
    expect(types).toContain("positive");
    expect(types).toContain("negative");
  });

  it("maps SSRF to CWE-918", () => {
    const r = generateSecurityTests({ vulnerability_class: "ssrf", language: "go" });
    expect(r.cwe).toContain("CWE-918");
    expect(r.references.length).toBeGreaterThan(0);
  });

  it("honors an explicit framework override", () => {
    const r = generateSecurityTests({
      vulnerability_class: "csrf",
      language: "python",
      framework: "unittest",
    });
    expect(r.framework).toBe("unittest");
  });
});

describe("generateSecurityTests — validation and determinism", () => {
  it("rejects an invalid framework name", () => {
    expect(() =>
      generateSecurityTests({
        vulnerability_class: "auth",
        language: "python",
        framework: "bad name!",
      }),
    ).toThrow(SecurityTestsError);
  });

  it("is deterministic for the same input", () => {
    const input = { vulnerability_class: "business-logic" as const, language: "java" as const };
    expect(JSON.stringify(generateSecurityTests(input))).toBe(
      JSON.stringify(generateSecurityTests(input)),
    );
  });
});
