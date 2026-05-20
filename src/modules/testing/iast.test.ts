import { describe, expect, it } from "vitest";
import { generateIastConfig, IastConfigError } from "./iast.js";

describe("generateIastConfig — supported runtimes", () => {
  it("generates a Java IAST setup with javaagent instrumentation", () => {
    const r = generateIastConfig({ tool: "contrast", language: "java" });
    expect(r.supported).toBe(true);
    expect(r.instrumentation.content).toContain("agent");
    expect(r.setup_steps.join(" ")).toContain("javaagent");
  });

  it("generates a Python IAST setup", () => {
    const r = generateIastConfig({ tool: "seeker", language: "python" });
    expect(r.supported).toBe(true);
    expect(r.instrumentation.filename).toContain(".yaml");
  });

  it("generates a JavaScript IAST setup", () => {
    const r = generateIastConfig({ tool: "dynatrace", language: "javascript" });
    expect(r.supported).toBe(true);
    expect(r.instrumentation.content).toContain("module.exports");
  });

  it("uses the default framework for the language", () => {
    const r = generateIastConfig({ tool: "open-source", language: "python" });
    expect(r.framework).toBe("django");
  });

  it("honors an explicit framework override", () => {
    const r = generateIastConfig({
      tool: "contrast",
      language: "java",
      framework: "quarkus",
    });
    expect(r.framework).toBe("quarkus");
  });
});

describe("generateIastConfig — unsupported native runtimes", () => {
  it("flags Rust as not applicable to IAST", () => {
    const r = generateIastConfig({ tool: "contrast", language: "rust" });
    expect(r.supported).toBe(false);
    expect(r.notes.join(" ")).toContain("DAST");
  });

  it("flags C as not applicable to IAST", () => {
    const r = generateIastConfig({ tool: "seeker", language: "c" });
    expect(r.supported).toBe(false);
    expect(r.instrumentation.filename).toContain("NOT_SUPPORTED");
  });
});

describe("generateIastConfig — shape, validation, determinism", () => {
  it("always includes CI integration and coverage guidance", () => {
    const r = generateIastConfig({ tool: "contrast", language: "java" });
    expect(r.ci_integration.content).toContain("iast");
    expect(r.coverage_guidance.length).toBeGreaterThan(0);
    expect(r.references.length).toBeGreaterThan(0);
  });

  it("rejects an invalid framework name", () => {
    expect(() =>
      generateIastConfig({ tool: "contrast", language: "java", framework: "bad name!" }),
    ).toThrow(IastConfigError);
  });

  it("is deterministic for the same input", () => {
    const input = { tool: "contrast" as const, language: "java" as const };
    expect(JSON.stringify(generateIastConfig(input))).toBe(
      JSON.stringify(generateIastConfig(input)),
    );
  });
});
