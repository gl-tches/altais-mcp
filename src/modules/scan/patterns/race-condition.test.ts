import { describe, expect, it } from "vitest";
import { runPatterns } from "../engine.js";
import type { Language } from "../languages.js";
import { RACE_CONDITION_PATTERNS } from "./race-condition.js";

function scan(source: string, language: Language): readonly string[] {
  return runPatterns(RACE_CONDITION_PATTERNS, { source, language }).map((f) => f.rule);
}

describe("race-condition patterns", () => {
  it("has unique pattern ids", () => {
    const ids = RACE_CONDITION_PATTERNS.map((p) => p.id);
    expect(new Set(ids).size).toBe(ids.length);
  });

  describe("positives", () => {
    it("flags fs.existsSync check followed by fs.readFile (JS)", () => {
      const src = `if (fs.existsSync(path)) {
  const data = fs.readFile(path, cb);
}`;
      const rules = scan(src, "javascript");
      expect(rules).toContain("race-toctou-fs-check-use-js");
    });

    it("flags fs.access check followed by fs.writeFile (JS)", () => {
      const src = `fs.access(target, (err) => {
  fs.writeFile(target, content, done);
});`;
      const rules = scan(src, "typescript");
      expect(rules).toContain("race-toctou-fs-check-use-js");
    });

    it("flags os.path.exists check followed by open (Python)", () => {
      const src = `if os.path.exists(p):
    f = open(p, "r")`;
      const rules = scan(src, "python");
      expect(rules).toContain("race-toctou-os-path-check-use-py");
    });

    it("flags tempfile.mktemp usage (Python)", () => {
      const rules = scan(`name = tempfile.mktemp()`, "python");
      expect(rules).toContain("race-insecure-mktemp-py");
    });

    it("flags os.Stat followed by os.Open (Go)", () => {
      const src = `_, err := os.Stat(name)
if err == nil {
    f, _ := os.Open(name)
}`;
      const rules = scan(src, "go");
      expect(rules).toContain("race-toctou-os-stat-open-go");
    });

    it("flags a goroutine capturing the loop variable (Go)", () => {
      const src = `for _, v := range items {
    go func() {
        process(v)
    }()
}`;
      const rules = scan(src, "go");
      expect(rules).toContain("race-goroutine-loop-var-capture-go");
    });
  });

  describe("negatives", () => {
    it("does not flag a direct fs.readFile without a pre-check (JS)", () => {
      const rules = scan(`fs.readFile(path, cb);`, "javascript");
      expect(rules).toEqual([]);
    });

    it("does not flag a direct open without a pre-check (Python)", () => {
      const rules = scan(`with open(p, "r") as f:\n    data = f.read()`, "python");
      expect(rules).toEqual([]);
    });

    it("does not flag tempfile.mkstemp (Python)", () => {
      const rules = scan(`fd, name = tempfile.mkstemp()`, "python");
      expect(rules).toEqual([]);
    });

    it("does not flag a goroutine passing the loop variable as an argument (Go)", () => {
      const src = `for _, v := range items {
    go func(item string) {
        process(item)
    }(v)
}`;
      const rules = scan(src, "go");
      expect(rules).not.toContain("race-goroutine-loop-var-capture-go");
    });
  });
});
