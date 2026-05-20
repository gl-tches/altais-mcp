import { describe, expect, it } from "vitest";
import { runPatterns } from "../engine.js";
import type { Language } from "../languages.js";
import { EXCEPTIONAL_CONDITIONS_PATTERNS } from "./exceptional-conditions.js";

function scan(source: string, language: Language): readonly string[] {
  return runPatterns(EXCEPTIONAL_CONDITIONS_PATTERNS, { source, language }).map((f) => f.rule);
}

describe("Exceptional conditions patterns", () => {
  describe("positives", () => {
    it("flags empty catch block", () => {
      expect(scan(`try { doStuff(); } catch (e) {}`, "javascript")).toContain("empty-catch-js");
    });

    it("flags empty .catch() promise handler", () => {
      expect(scan(`fetch(url).catch(() => {});`, "javascript")).toContain("empty-promise-catch-js");
    });

    it("flags res.send(err.stack)", () => {
      expect(scan(`res.send(err.stack);`, "javascript")).toContain("stack-trace-response-js");
    });

    it("flags catch block returning true (fail-open)", () => {
      expect(
        scan(
          `function check(x) { try { return validate(x); } catch (e) { return true; } }`,
          "javascript",
        ),
      ).toContain("fail-open-truthy-catch-js");
    });

    it("flags Python `except: pass`", () => {
      expect(scan(`try:\n    x = f()\nexcept:\n    pass`, "python")).toContain("empty-except-py");
    });

    it("flags Python except returning True", () => {
      expect(
        scan(
          `def check():\n    try:\n        return real_check()\n    except Exception:\n        return True`,
          "python",
        ),
      ).toContain("fail-open-except-true-py");
    });

    it("flags Python returning traceback.format_exc()", () => {
      expect(
        scan(
          `def handler():\n    try:\n        do()\n    except Exception:\n        return traceback.format_exc()`,
          "python",
        ),
      ).toContain("stack-trace-response-py");
    });
  });

  describe("negatives", () => {
    it("does not flag catch with a logger call", () => {
      expect(
        scan(`try { f(); } catch (e) { log.error("failed", e); }`, "javascript").filter((r) =>
          r.startsWith("empty-catch"),
        ),
      ).toEqual([]);
    });

    it("does not flag catch that re-throws", () => {
      expect(
        scan(`try { f(); } catch (e) { throw new Error("rethrow"); }`, "javascript").filter(
          (r) => r.startsWith("empty-catch") || r.startsWith("fail-open"),
        ),
      ).toEqual([]);
    });

    it("does not flag generic error response", () => {
      expect(
        scan(`res.status(500).send({ error: "internal" });`, "javascript").filter((r) =>
          r.startsWith("stack-trace"),
        ),
      ).toEqual([]);
    });

    it("does not flag Python except with logging", () => {
      expect(
        scan(
          `try:\n    x = f()\nexcept Exception:\n    logger.exception("failed")`,
          "python",
        ).filter((r) => r.startsWith("empty-except")),
      ).toEqual([]);
    });

    it("does not flag returning a sanitized error message in Python", () => {
      expect(
        scan(
          `def handler():\n    try:\n        do()\n    except Exception:\n        return "internal error"`,
          "python",
        ).filter((r) => r.startsWith("stack-trace")),
      ).toEqual([]);
    });
  });

  describe("Go positives", () => {
    it("flags an error discarded to the blank identifier", () => {
      expect(scan(`val, _ := strconv.Atoi(input)`, "go")).toContain("discarded-error-go");
    });

    it("flags a leading `_ = call()` discard", () => {
      expect(scan(`_ = json.Unmarshal(data, &out)`, "go")).toContain("discarded-error-go");
    });

    it("flags panic() in non-test code", () => {
      expect(scan(`if cfg == nil { panic("missing config") }`, "go")).toContain("panic-go");
    });

    it("flags an empty error check block", () => {
      expect(scan(`v, err := load()\nif err != nil {}`, "go")).toContain("empty-error-check-go");
    });
  });

  describe("Go negatives", () => {
    it("does not flag a handled error", () => {
      expect(
        scan(`v, err := load()\nif err != nil {\n    return err\n}`, "go").filter((r) =>
          r.startsWith("empty-error-check"),
        ),
      ).toEqual([]);
    });

    it("does not flag a non-discarded assignment", () => {
      expect(
        scan(`val := strconv.Itoa(42)`, "go").filter((r) => r.startsWith("discarded-error")),
      ).toEqual([]);
    });

    it("does not flag panic inside a comment", () => {
      expect(
        scan(`// panic("old code")\nv := 1`, "go").filter((r) => r.startsWith("panic-")),
      ).toEqual([]);
    });
  });

  describe("Rust positives", () => {
    it("flags .unwrap() on a Result", () => {
      expect(scan(`let v = parse(input).unwrap();`, "rust")).toContain("unwrap-expect-rust");
    });

    it("flags .expect() with a message", () => {
      expect(scan(`let v = env::var("KEY").expect("missing");`, "rust")).toContain(
        "unwrap-expect-rust",
      );
    });

    it("flags panic! macro", () => {
      expect(scan(`if bad { panic!("unexpected: {}", x); }`, "rust")).toContain("panic-macro-rust");
    });

    it("flags unreachable! macro", () => {
      expect(scan(`match k { 0 => a(), _ => unreachable!() }`, "rust")).toContain(
        "panic-macro-rust",
      );
    });
  });

  describe("Rust negatives", () => {
    it("does not flag the `?` operator", () => {
      expect(
        scan(`let v = parse(input)?;`, "rust").filter((r) => r.startsWith("unwrap-expect")),
      ).toEqual([]);
    });

    it("does not flag a match on the Result", () => {
      expect(
        scan(`match parse(input) { Ok(v) => v, Err(e) => return Err(e) }`, "rust").filter((r) =>
          r.startsWith("unwrap-expect"),
        ),
      ).toEqual([]);
    });

    it("does not flag panic! inside a comment", () => {
      expect(
        scan(`// panic!("old code")\nlet v = 1;`, "rust").filter((r) => r.startsWith("panic-")),
      ).toEqual([]);
    });
  });
});
