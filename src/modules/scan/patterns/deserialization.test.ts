import { describe, expect, it } from "vitest";
import { runPatterns } from "../engine.js";
import type { Language } from "../languages.js";
import { DESERIALIZATION_PATTERNS } from "./deserialization.js";

function scan(source: string, language: Language): readonly string[] {
  return runPatterns(DESERIALIZATION_PATTERNS, { source, language }).map((f) => f.rule);
}

describe("deserialization patterns", () => {
  it("has unique pattern ids", () => {
    const ids = DESERIALIZATION_PATTERNS.map((p) => p.id);
    expect(new Set(ids).size).toBe(ids.length);
  });

  describe("positives", () => {
    it("flags pickle.loads (Python)", () => {
      const rules = scan(`obj = pickle.loads(data)`, "python");
      expect(rules).toContain("deserialization-pickle-py");
    });

    it("flags pickle.load from a file (Python)", () => {
      const rules = scan(`obj = pickle.load(f)`, "python");
      expect(rules).toContain("deserialization-pickle-py");
    });

    it("flags yaml.load without a loader (Python)", () => {
      const rules = scan(`cfg = yaml.load(raw)`, "python");
      expect(rules).toContain("deserialization-yaml-unsafe-load-py");
    });

    it("flags yaml.load with FullLoader (Python)", () => {
      const rules = scan(`cfg = yaml.load(raw, Loader=yaml.FullLoader)`, "python");
      expect(rules).toContain("deserialization-yaml-unsafe-load-py");
    });

    it("flags marshal.loads (Python)", () => {
      const rules = scan(`code = marshal.loads(blob)`, "python");
      expect(rules).toContain("deserialization-marshal-dill-py");
    });

    it("flags dill.loads (Python)", () => {
      const rules = scan(`obj = dill.loads(blob)`, "python");
      expect(rules).toContain("deserialization-marshal-dill-py");
    });

    it("flags jsonpickle.decode (Python)", () => {
      const rules = scan(`obj = jsonpickle.decode(payload)`, "python");
      expect(rules).toContain("deserialization-marshal-dill-py");
    });

    it("flags node-serialize unserialize (JS)", () => {
      const rules = scan(`const obj = unserialize(req.body.payload);`, "javascript");
      expect(rules).toContain("deserialization-node-serialize-js");
    });

    it("flags funcster.deepDeserialize (JS)", () => {
      const rules = scan(`const fns = funcster.deepDeserialize(input);`, "typescript");
      expect(rules).toContain("deserialization-node-serialize-js");
    });

    it("flags gob.NewDecoder on a connection (Go)", () => {
      const rules = scan(`dec := gob.NewDecoder(conn)`, "go");
      expect(rules).toContain("deserialization-go-gob-decoder");
    });
  });

  describe("negatives", () => {
    it("does not flag yaml.safe_load (Python)", () => {
      const rules = scan(`cfg = yaml.safe_load(raw)`, "python");
      expect(rules).toEqual([]);
    });

    it("does not flag yaml.load with SafeLoader (Python)", () => {
      const rules = scan(`cfg = yaml.load(raw, Loader=yaml.SafeLoader)`, "python");
      expect(rules).not.toContain("deserialization-yaml-unsafe-load-py");
    });

    it("does not flag json.loads (Python)", () => {
      const rules = scan(`obj = json.loads(data)`, "python");
      expect(rules).toEqual([]);
    });

    it("does not flag JSON.parse (JS)", () => {
      const rules = scan(`const obj = JSON.parse(req.body.payload);`, "javascript");
      expect(rules).toEqual([]);
    });
  });
});
