import { describe, expect, it } from "vitest";
import type { DependencyPackage } from "./types.js";
import { detectTyposquat } from "./typosquat.js";

function p(name: string, ecosystem: DependencyPackage["ecosystem"] = "npm"): DependencyPackage {
  return { name, version: "1.0.0", ecosystem };
}

describe("detectTyposquat", () => {
  it("flags a one-edit-away package name (single insertion)", () => {
    // "lodashs" = "lodash" + s -> distance 1.
    const r = detectTyposquat([p("lodashs")], undefined);
    expect(r.hits.map((h) => h.suspect)).toContain("lodashs");
    expect(r.findings[0]?.severity).toBe("high");
  });

  it("flags a two-edit-away name as medium", () => {
    // "axois" = swap o/i in "axios" -> classic Levenshtein distance 2.
    const r = detectTyposquat([p("axois")], undefined);
    expect(r.hits.length).toBeGreaterThan(0);
    expect(r.findings[0]?.severity).toBe("medium");
  });

  it("does not flag exact matches", () => {
    const r = detectTyposquat([p("react"), p("vue"), p("lodash")], undefined);
    expect(r.findings).toEqual([]);
  });

  it("does not flag unrelated names", () => {
    const r = detectTyposquat([p("totally-unique-internal-name")], undefined);
    expect(r.findings).toEqual([]);
  });

  it("handles a custom popular list", () => {
    const r = detectTyposquat([p("my-pkg-1")], undefined, {
      npm: ["my-pkg"] as readonly string[],
      cargo: [] as readonly string[],
      pypi: [] as readonly string[],
      go: [] as readonly string[],
    });
    expect(r.findings.length).toBe(1);
  });
});
