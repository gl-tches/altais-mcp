import { describe, expect, it } from "vitest";
import { recommendRasp, type RaspGeneratorInput } from "./rasp.js";

describe("recommendRasp — language-specific instrumentation", () => {
  it("recommends a -javaagent for Java", () => {
    const r = recommendRasp({
      language: "java",
      framework: "spring-boot",
      deployment: "container",
      risk_tolerance: "medium",
    });
    expect(r.instrumentation.toLowerCase()).toContain("javaagent");
    expect(r.setup_steps.length).toBeGreaterThan(0);
  });

  it("recommends CLR profiling for .NET", () => {
    const r = recommendRasp({
      language: "dotnet",
      framework: "aspnetcore",
      deployment: "vm",
      risk_tolerance: "medium",
    });
    expect(r.instrumentation.toLowerCase()).toContain("profil");
  });

  it("recommends a --require bootstrap for Node", () => {
    const r = recommendRasp({
      language: "node",
      framework: "express",
      deployment: "container",
      risk_tolerance: "medium",
    });
    expect(r.instrumentation).toContain("--require");
  });

  it("notes Go has no runtime agent and uses SDK integration", () => {
    const r = recommendRasp({
      language: "go",
      framework: "gin",
      deployment: "container",
      risk_tolerance: "medium",
    });
    expect(r.instrumentation.toLowerCase()).toContain("sdk");
  });
});

describe("recommendRasp — deserialization protection", () => {
  it("includes unsafe deserialization protection (CWE-502) for Java", () => {
    const r = recommendRasp({
      language: "java",
      framework: "spring",
      deployment: "container",
      risk_tolerance: "medium",
    });
    const deser = r.protections.find((p) => p.cwe.includes("CWE-502"));
    expect(deser).toBeDefined();
  });

  it("omits deserialization protection for Node (not a native risk)", () => {
    const r = recommendRasp({
      language: "node",
      framework: "express",
      deployment: "container",
      risk_tolerance: "medium",
    });
    const deser = r.protections.find((p) => p.cwe.includes("CWE-502"));
    expect(deser).toBeUndefined();
  });
});

describe("recommendRasp — risk tolerance drives enforcement", () => {
  it("blocks every protection when risk tolerance is low", () => {
    const r = recommendRasp({
      language: "python",
      framework: "django",
      deployment: "vm",
      risk_tolerance: "low",
    });
    expect(r.protections.every((p) => p.mode === "block")).toBe(true);
  });

  it("monitors every protection when risk tolerance is high", () => {
    const r = recommendRasp({
      language: "python",
      framework: "django",
      deployment: "vm",
      risk_tolerance: "high",
    });
    expect(r.protections.every((p) => p.mode === "monitor")).toBe(true);
  });

  it("blocks only catastrophic classes at medium risk tolerance", () => {
    const r = recommendRasp({
      language: "ruby",
      framework: "rails",
      deployment: "vm",
      risk_tolerance: "medium",
    });
    const blocked = r.protections.filter((p) => p.mode === "block");
    expect(blocked.length).toBeGreaterThan(0);
    for (const p of blocked) {
      expect(p.cwe.includes("CWE-502") || p.cwe.includes("CWE-78")).toBe(true);
    }
  });
});

describe("recommendRasp — deployment guidance", () => {
  it("warns about cold-start cost for serverless", () => {
    const r = recommendRasp({
      language: "node",
      framework: "express",
      deployment: "serverless",
      risk_tolerance: "medium",
    });
    expect(r.performance_considerations.some((p) => p.toLowerCase().includes("cold"))).toBe(true);
  });

  it("returns a product category, blocking guidance, and references", () => {
    const r = recommendRasp({
      language: "java",
      framework: "spring-boot",
      deployment: "container",
      risk_tolerance: "low",
    });
    expect(r.product_category.length).toBeGreaterThan(0);
    expect(r.blocking_guidance.length).toBeGreaterThan(0);
    expect(r.references.length).toBeGreaterThan(0);
  });

  it("is deterministic — same input produces identical output", () => {
    const input: RaspGeneratorInput = {
      language: "java",
      framework: "spring-boot",
      deployment: "container",
      risk_tolerance: "medium",
    };
    expect(recommendRasp(input)).toEqual(recommendRasp(input));
  });
});
