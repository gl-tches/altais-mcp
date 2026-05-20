import { describe, expect, it } from "vitest";
import { cmp, inRange, levenshtein, parse } from "./semver.js";

describe("parse + cmp", () => {
  it("parses N.N.N versions", () => {
    expect(parse("1.2.3")).toEqual({ major: 1, minor: 2, patch: 3, pre: [] });
  });

  it("parses prereleases", () => {
    expect(parse("1.0.0-alpha.1")).toEqual({ major: 1, minor: 0, patch: 0, pre: ["alpha", 1] });
  });

  it("orders by major.minor.patch", () => {
    expect(cmp("1.2.3", "1.2.4")).toBe(-1);
    expect(cmp("2.0.0", "1.9.9")).toBe(1);
    expect(cmp("1.2.3", "1.2.3")).toBe(0);
  });

  it("treats prerelease as < release", () => {
    expect(cmp("1.0.0-alpha", "1.0.0")).toBe(-1);
    expect(cmp("1.0.0-rc.1", "1.0.0")).toBe(-1);
  });

  it("compares prerelease tokens numerically when both numeric", () => {
    expect(cmp("1.0.0-alpha.2", "1.0.0-alpha.10")).toBe(-1);
  });
});

describe("inRange", () => {
  it("matches by introduced/fixed", () => {
    expect(inRange("4.17.10", { fixed: "4.17.12" })).toBe(true);
    expect(inRange("4.17.12", { fixed: "4.17.12" })).toBe(false);
    expect(inRange("4.17.5", { introduced: "4.17.0", fixed: "4.17.12" })).toBe(true);
    expect(inRange("4.16.0", { introduced: "4.17.0", fixed: "4.17.12" })).toBe(false);
  });

  it("treats missing introduced as 0", () => {
    expect(inRange("0.0.1", { fixed: "1.0.0" })).toBe(true);
  });

  it("supports last_affected", () => {
    expect(inRange("1.0.0", { last_affected: "1.0.0" })).toBe(true);
    expect(inRange("1.0.1", { last_affected: "1.0.0" })).toBe(false);
  });
});

describe("levenshtein", () => {
  it("returns 0 for equal strings", () => {
    expect(levenshtein("foo", "foo", 2)).toBe(0);
  });

  it("returns the edit distance", () => {
    expect(levenshtein("axios", "axois", 2)).toBe(2);
    expect(levenshtein("lodash", "loadash", 2)).toBe(1);
  });

  it("returns null when distance exceeds max", () => {
    expect(levenshtein("react", "vue", 2)).toBeNull();
  });
});
