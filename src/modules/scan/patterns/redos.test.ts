import { describe, expect, it } from "vitest";
import { runPatterns } from "../engine.js";
import type { Language } from "../languages.js";
import { REDOS_PATTERNS } from "./redos.js";

function scan(source: string, language: Language): readonly string[] {
  return runPatterns(REDOS_PATTERNS, { source, language }).map((f) => f.rule);
}

describe("redos patterns", () => {
  it("has unique pattern ids", () => {
    const ids = REDOS_PATTERNS.map((p) => p.id);
    expect(new Set(ids).size).toBe(ids.length);
  });

  describe("positives", () => {
    it("flags a regex literal with a nested quantifier", () => {
      const rules = scan(`const re = /(a+)+$/;`, "javascript");
      expect(rules).toContain("redos-nested-quantifier-js");
    });

    it("flags a regex literal with overlapping quantified alternation", () => {
      const rules = scan(`const re = /(.|\\s)*x/;`, "javascript");
      expect(rules).toContain("redos-nested-quantifier-js");
    });

    it("flags new RegExp with a nested quantifier literal", () => {
      const rules = scan(`const re = new RegExp("(\\\\d+)+$");`, "javascript");
      expect(rules).toContain("redos-new-regexp-nested-quantifier-js");
    });

    it("flags new RegExp built from a variable", () => {
      const rules = scan(`const re = new RegExp(userPattern);`, "javascript");
      expect(rules).toContain("redos-regex-from-input-js");
    });

    it("flags re.compile with a nested quantifier literal (Python)", () => {
      const rules = scan(`pat = re.compile("(a+)+")`, "python");
      expect(rules).toContain("redos-re-compile-nested-quantifier-py");
    });

    it("flags re.compile built from a variable (Python)", () => {
      const rules = scan(`pat = re.compile(user_input)`, "python");
      expect(rules).toContain("redos-re-compile-from-input-py");
    });

    it("flags a regex literal with (.*)* shape", () => {
      const rules = scan(`const re = /^(.*)*$/;`, "typescript");
      expect(rules).toContain("redos-nested-quantifier-js");
    });
  });

  describe("negatives", () => {
    it("does not flag a safe regex literal", () => {
      const rules = scan(`const re = /^[a-z0-9]+$/;`, "javascript");
      expect(rules).toEqual([]);
    });

    it("does not flag new RegExp with a safe literal", () => {
      const rules = scan(`const re = new RegExp("^[0-9]{1,10}$");`, "javascript");
      expect(rules).toEqual([]);
    });

    it("does not flag a safe re.compile literal (Python)", () => {
      const rules = scan(`pat = re.compile("^[a-z]+$")`, "python");
      expect(rules).toEqual([]);
    });

    it("does not flag a division expression that resembles a regex", () => {
      const rules = scan(`const ratio = total / (count + count) / scale;`, "javascript");
      expect(rules).not.toContain("redos-nested-quantifier-js");
    });
  });
});
