import { describe, expect, it } from "vitest";
import { checkLicenses } from "./licenses.js";
import type { DependencyPackage } from "./types.js";

function p(name: string, license: string | undefined): DependencyPackage {
  return {
    name,
    version: "1.0.0",
    ecosystem: "npm",
    ...(license !== undefined ? { license } : {}),
  };
}

describe("checkLicenses", () => {
  it("allows MIT / Apache-2.0", () => {
    const r = checkLicenses([p("a", "MIT"), p("b", "Apache-2.0")], {}, undefined);
    expect(r.findings).toEqual([]);
    expect(r.summary.allowed).toBe(2);
  });

  it("flags GPL-3.0 as denied", () => {
    const r = checkLicenses([p("a", "GPL-3.0")], {}, undefined);
    expect(r.findings[0]?.rule).toBe("license-denied");
    expect(r.findings[0]?.severity).toBe("high");
  });

  it("flags LGPL-3.0 as warn (weak copyleft)", () => {
    const r = checkLicenses([p("a", "LGPL-3.0")], {}, undefined);
    expect(r.findings[0]?.rule).toBe("license-warn");
  });

  it("flags missing license as unknown", () => {
    const r = checkLicenses([p("a", undefined)], {}, undefined);
    expect(r.findings[0]?.rule).toBe("license-unknown");
  });

  it("respects a custom deny list", () => {
    const r = checkLicenses([p("a", "MIT")], { deny: ["MIT"] }, undefined);
    expect(r.findings[0]?.rule).toBe("license-denied");
  });

  it("classifies composite expressions (MIT OR Apache-2.0)", () => {
    const r = checkLicenses([p("a", "(MIT OR Apache-2.0)")], {}, undefined);
    expect(r.findings).toEqual([]);
  });
});
