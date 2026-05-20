import { describe, expect, it } from "vitest";
import { FuzzConfigError, generateFuzzConfig } from "./fuzz.js";

describe("generateFuzzConfig — defaults", () => {
  it("picks cargo-fuzz as the default fuzzer for Rust", () => {
    const r = generateFuzzConfig({ language: "rust" });
    expect(r.fuzzer).toBe("cargo-fuzz");
    expect(r.harness.filename).toContain("fuzz_targets");
  });

  it("picks atheris as the default fuzzer for Python", () => {
    const r = generateFuzzConfig({ language: "python" });
    expect(r.fuzzer).toBe("atheris");
    expect(r.harness.code).toContain("atheris.Fuzz()");
  });

  it("uses the default target function name when none is given", () => {
    const r = generateFuzzConfig({ language: "go" });
    expect(r.target_function).toBe("parse_input");
  });
});

describe("generateFuzzConfig — content", () => {
  it("embeds the supplied target function in the C harness", () => {
    const r = generateFuzzConfig({ language: "c", target_function: "decode_packet" });
    expect(r.harness.code).toContain("LLVMFuzzerTestOneInput");
    expect(r.harness.code).toContain("decode_packet");
  });

  it("recommends ASan and UBSan for C/C++ targets", () => {
    const r = generateFuzzConfig({ language: "cpp" });
    const joined = r.sanitizers.recommended.join(" ");
    expect(joined).toContain("AddressSanitizer");
    expect(joined).toContain("UndefinedBehaviorSanitizer");
  });

  it("recommends the race detector for Go targets", () => {
    const r = generateFuzzConfig({ language: "go" });
    expect(r.sanitizers.recommended.join(" ")).toContain("race detector");
  });

  it("produces a runner script and corpus + dictionary guidance", () => {
    const r = generateFuzzConfig({ language: "java" });
    expect(r.runner.content.length).toBeGreaterThan(20);
    expect(r.corpus.guidance.length).toBeGreaterThan(0);
    expect(r.dictionary.guidance.length).toBeGreaterThan(0);
    expect(r.references.length).toBeGreaterThan(0);
  });

  it("honors an explicit fuzzer override", () => {
    const r = generateFuzzConfig({ language: "c", fuzzer: "afl++" });
    expect(r.fuzzer).toBe("afl++");
    expect(r.runner.content).toContain("afl-fuzz");
  });
});

describe("generateFuzzConfig — validation and determinism", () => {
  it("rejects an invalid target function identifier", () => {
    expect(() => generateFuzzConfig({ language: "c", target_function: "bad name" })).toThrow(
      FuzzConfigError,
    );
  });

  it("is deterministic for the same input", () => {
    const a = generateFuzzConfig({ language: "rust", target_function: "parse" });
    const b = generateFuzzConfig({ language: "rust", target_function: "parse" });
    expect(JSON.stringify(a)).toBe(JSON.stringify(b));
  });
});
