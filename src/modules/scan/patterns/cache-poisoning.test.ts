import { describe, expect, it } from "vitest";
import { runPatterns } from "../engine.js";
import type { Language } from "../languages.js";
import { CACHE_POISONING_PATTERNS } from "./cache-poisoning.js";

function scan(source: string, language: Language): readonly string[] {
  return runPatterns(CACHE_POISONING_PATTERNS, { source, language }).map((f) => f.rule);
}

describe("cache-poisoning patterns - pattern ids", () => {
  it("has unique rule ids", () => {
    const ids = CACHE_POISONING_PATTERNS.map((p) => p.id);
    expect(new Set(ids).size).toBe(ids.length);
  });

  it("every pattern carries a CWE and a reference", () => {
    for (const p of CACHE_POISONING_PATTERNS) {
      expect(p.cwe.length).toBeGreaterThan(0);
      expect(p.references.length).toBeGreaterThan(0);
    }
  });
});

describe("cache-poisoning patterns - unkeyed header reflection", () => {
  describe("positives", () => {
    it("flags reading X-Forwarded-Host in JS", () => {
      const rules = scan(`const h = req.headers["x-forwarded-host"];`, "javascript");
      expect(rules).toContain("cache-poisoning-reflect-unkeyed-header-js");
    });

    it("flags req.get('X-Original-URL')", () => {
      const rules = scan(`const u = req.get("X-Original-URL");`, "javascript");
      expect(rules).toContain("cache-poisoning-reflect-unkeyed-header-js");
    });

    it("flags reading X-Forwarded-Host in Python", () => {
      const rules = scan(`h = request.headers.get("X-Forwarded-Host")`, "python");
      expect(rules).toContain("cache-poisoning-reflect-unkeyed-header-py");
    });
  });

  describe("negatives", () => {
    it("does not flag a normal Accept header read", () => {
      const rules = scan(`const a = req.headers["accept"];`, "javascript");
      expect(rules).not.toContain("cache-poisoning-reflect-unkeyed-header-js");
    });

    it("does not flag a Python Content-Type read", () => {
      const rules = scan(`ct = request.headers.get("Content-Type")`, "python");
      expect(rules).not.toContain("cache-poisoning-reflect-unkeyed-header-py");
    });
  });
});

describe("cache-poisoning patterns - public caching of request data", () => {
  describe("positives", () => {
    it("flags public Cache-Control near req.query usage", () => {
      const rules = scan(
        `res.set("Cache-Control", "public, max-age=60");\nres.send(render(req.query.name));`,
        "javascript",
      );
      expect(rules).toContain("cache-poisoning-public-cache-on-request-data-js");
    });

    it("flags s-maxage Cache-Control near request.args in Python", () => {
      const rules = scan(
        `response.headers["Cache-Control"] = "public, s-maxage=300"\nbody = render(request.args.get("q"))`,
        "python",
      );
      expect(rules).toContain("cache-poisoning-public-cache-on-request-data-py");
    });
  });

  describe("negatives", () => {
    it("does not flag private no-store caching", () => {
      const rules = scan(
        `res.set("Cache-Control", "private, no-store");\nres.send(render(req.query.name));`,
        "javascript",
      );
      expect(rules).not.toContain("cache-poisoning-public-cache-on-request-data-js");
    });

    it("does not flag public caching of static content", () => {
      const rules = scan(`res.set("Cache-Control", "public, max-age=3600");`, "javascript");
      expect(rules).not.toContain("cache-poisoning-public-cache-on-request-data-js");
    });
  });
});

describe("cache-poisoning patterns - missing Vary header", () => {
  it("flags a cacheable response that uses req.headers with no Vary", () => {
    const rules = scan(
      `const lang = req.headers["accept-language"];\nres.setHeader("Cache-Control", "public, max-age=600");\nres.send(translate(lang));`,
      "javascript",
    );
    expect(rules).toContain("cache-poisoning-missing-vary-on-header-dependence-js");
  });

  it("does not flag when a Vary header is present", () => {
    const rules = scan(
      `const lang = req.headers["accept-language"];\nres.setHeader("Vary", "Accept-Language");\nres.setHeader("Cache-Control", "public, max-age=600");`,
      "javascript",
    );
    expect(rules).not.toContain("cache-poisoning-missing-vary-on-header-dependence-js");
  });

  it("does not flag a cacheable response that does not touch req.headers", () => {
    const rules = scan(
      `res.setHeader("Cache-Control", "public, max-age=600");\nres.send("static");`,
      "javascript",
    );
    expect(rules).not.toContain("cache-poisoning-missing-vary-on-header-dependence-js");
  });
});
