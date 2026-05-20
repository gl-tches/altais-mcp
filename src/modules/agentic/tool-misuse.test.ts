import { describe, expect, it } from "vitest";
import { auditToolMisuse } from "./tool-misuse.js";

describe("auditToolMisuse — positive", () => {
  it("flags over-permissioned tool APIs", () => {
    const f = auditToolMisuse({ config: { over_permissioned_apis: true } });
    const hit = f.find((x) => x.rule === "tool-over-permissioned-apis");
    expect(hit?.severity).toBe("high");
  });

  it("flags unverified MCP tool descriptors", () => {
    const f = auditToolMisuse({ config: { tool_descriptors_verified: false } });
    expect(f.some((x) => x.rule === "tool-descriptors-unverified")).toBe(true);
  });

  it("flags a missing tool allowlist", () => {
    const f = auditToolMisuse({ config: { tool_allowlist: false } });
    expect(f.some((x) => x.rule === "tool-no-allowlist")).toBe(true);
  });

  it("flags unvalidated tool arguments and output", () => {
    const f = auditToolMisuse({
      config: { input_validation_on_tool_args: false, tool_output_validation: false },
    });
    expect(f.map((x) => x.rule)).toEqual(
      expect.arrayContaining(["tool-args-not-validated", "tool-output-not-validated"]),
    );
  });

  it("flags a tool registered with a wildcard scope", () => {
    const f = auditToolMisuse({
      config: { tools: [{ name: "shell", scope: "*" }] },
    });
    expect(f.some((x) => x.rule === "tool-wildcard-scope")).toBe(true);
  });
});

describe("auditToolMisuse — negative", () => {
  it("returns nothing for a hardened config", () => {
    const f = auditToolMisuse({
      config: {
        tools: [{ name: "search", scope: "read:docs" }],
        tool_allowlist: true,
        tool_descriptors_verified: true,
        over_permissioned_apis: false,
        input_validation_on_tool_args: true,
        tool_output_validation: true,
        rate_limited: true,
      },
    });
    expect(f).toHaveLength(0);
  });

  it("returns nothing when no config is supplied", () => {
    expect(auditToolMisuse({})).toHaveLength(0);
  });
});

describe("auditToolMisuse — shape & determinism", () => {
  it("produces deterministic IDs across runs", () => {
    const a = auditToolMisuse({ config: { over_permissioned_apis: true } });
    const b = auditToolMisuse({ config: { over_permissioned_apis: true } });
    expect(a.map((x) => x.id)).toEqual(b.map((x) => x.id));
  });

  it("tags every finding with the module, a CWE, and ASI02", () => {
    const f = auditToolMisuse({ config: { tool_allowlist: false } });
    expect(f.length).toBeGreaterThan(0);
    for (const x of f) {
      expect(x.module).toBe("agentic");
      expect((x.cwe ?? []).length).toBeGreaterThan(0);
      expect(x.tags).toContain("agentic");
      expect(x.tags).toContain("ASI02");
    }
  });
});
