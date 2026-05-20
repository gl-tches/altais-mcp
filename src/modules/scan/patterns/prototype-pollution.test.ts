import { describe, expect, it } from "vitest";
import { runPatterns } from "../engine.js";
import type { Language } from "../languages.js";
import { PROTOTYPE_POLLUTION_PATTERNS } from "./prototype-pollution.js";

function scan(source: string, language: Language): readonly string[] {
  return runPatterns(PROTOTYPE_POLLUTION_PATTERNS, { source, language }).map((f) => f.rule);
}

describe("prototype-pollution patterns", () => {
  it("has unique pattern ids", () => {
    const ids = PROTOTYPE_POLLUTION_PATTERNS.map((p) => p.id);
    expect(new Set(ids).size).toBe(ids.length);
  });

  describe("positives", () => {
    it("flags assignment to a __proto__ string key", () => {
      const rules = scan(`obj["__proto__"] = payload;`, "javascript");
      expect(rules).toContain("prototype-pollution-proto-assignment-js");
    });

    it("flags computed write through a __proto__ key", () => {
      const rules = scan(`target["__proto__"][userKey] = value;`, "javascript");
      expect(rules).toContain("prototype-pollution-proto-assignment-js");
    });

    it("flags dotted __proto__ assignment", () => {
      const rules = scan(`node.__proto__ = malicious;`, "typescript");
      expect(rules).toContain("prototype-pollution-proto-assignment-js");
    });

    it("flags a constructor.prototype gadget write", () => {
      const rules = scan(`obj[key].constructor.prototype.polluted = 1;`, "javascript");
      expect(rules).toContain("prototype-pollution-computed-proto-chain-js");
    });

    it("flags an unsafe recursive merge function", () => {
      const src = `function deepMerge(target, source) {
  for (const key in source) {
    if (typeof source[key] === "object") {
      deepMerge(target[key], source[key]);
    } else {
      target[key] = source[key];
    }
  }
  return target;
}`;
      const rules = scan(src, "javascript");
      expect(rules).toContain("prototype-pollution-unsafe-merge-js");
    });

    it("flags lodash merge fed request body", () => {
      const rules = scan(`_.merge(config, req.body);`, "javascript");
      expect(rules).toContain("prototype-pollution-lodash-merge-request-js");
    });

    it("flags _.set with a request path", () => {
      const rules = scan(`_.set(state, req.params.path, value);`, "javascript");
      expect(rules).toContain("prototype-pollution-lodash-merge-request-js");
    });

    it("flags Object.assign of req.body into a target", () => {
      const rules = scan(`Object.assign(settings, req.body);`, "javascript");
      expect(rules).toContain("prototype-pollution-request-spread-js");
    });

    it("flags a request body spread into a config object", () => {
      const rules = scan(`const config = { ...req.query };`, "typescript");
      expect(rules).toContain("prototype-pollution-request-spread-js");
    });
  });

  describe("negatives", () => {
    it("does not flag a normal property assignment", () => {
      const rules = scan(`obj["name"] = "alice";`, "javascript");
      expect(rules).toEqual([]);
    });

    it("does not flag a guarded merge function", () => {
      const src = `function deepMerge(target, source) {
  for (const key in source) {
    if (key === "__proto__" || key === "constructor") continue;
    target[key] = source[key];
  }
  return target;
}`;
      const rules = scan(src, "javascript");
      expect(rules).not.toContain("prototype-pollution-unsafe-merge-js");
    });

    it("does not flag lodash merge of validated input", () => {
      const rules = scan(`_.merge(config, validated);`, "javascript");
      expect(rules).not.toContain("prototype-pollution-lodash-merge-request-js");
    });

    it("does not flag a comparison against __proto__", () => {
      const rules = scan(`if (key === "__proto__") { throw new Error("nope"); }`, "javascript");
      expect(rules).toEqual([]);
    });
  });
});
