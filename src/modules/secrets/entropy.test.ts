import { describe, expect, it } from "vitest";
import {
  DEFAULT_THRESHOLDS,
  classifyCharset,
  findHighEntropyTokens,
  scanEntropy,
  shannonEntropy,
} from "./entropy.js";

describe("shannonEntropy", () => {
  it("returns 0 for empty string", () => {
    expect(shannonEntropy("")).toBe(0);
  });

  it("returns 0 for a single repeated character", () => {
    expect(shannonEntropy("aaaaa")).toBe(0);
  });

  it("returns 1 bit/char for two equally probable symbols", () => {
    expect(shannonEntropy("abababab")).toBeCloseTo(1, 5);
  });

  it("returns 2 bits/char for four equally probable symbols", () => {
    expect(shannonEntropy("abcdabcd")).toBeCloseTo(2, 5);
  });

  it("returns ~log2(n) for n distinct uniform characters", () => {
    expect(shannonEntropy("0123456789abcdef")).toBeCloseTo(4, 5);
  });
});

describe("classifyCharset", () => {
  it("classifies pure hex", () => {
    expect(classifyCharset("deadbeefcafebabe")).toBe("hex");
  });

  it("classifies base32-shaped strings as base64", () => {
    expect(classifyCharset("AKIAIOSFODNN7EXAMPLE")).toBe("base64");
  });

  it("classifies base64 with + / =", () => {
    expect(classifyCharset("abc+def/ghi=")).toBe("base64");
  });

  it("returns other for strings with whitespace or punctuation", () => {
    expect(classifyCharset("hello world")).toBe("other");
  });
});

// 35 distinct chars over a 35-char string -> entropy ~log2(35) ≈ 5.13 bits/char,
// safely above the 5.0 base64 threshold.
const HIGH_ENTROPY = "Z9pK3mB7cR2vQjL8nF6tH4wY1dXuM5iE0oP";

describe("findHighEntropyTokens", () => {
  it("flags a high-entropy random token", () => {
    const tokens = findHighEntropyTokens(`const k = ${HIGH_ENTROPY};`, DEFAULT_THRESHOLDS);
    expect(tokens.find((t) => t.token === HIGH_ENTROPY)).toBeDefined();
  });

  it("does not flag the AKIA AWS example (low entropy by itself)", () => {
    // The pattern engine catches AKIA via prefix; entropy alone is ~3.8 bits/char.
    const tokens = findHighEntropyTokens("AKIAIOSFODNN7EXAMPLE", DEFAULT_THRESHOLDS);
    expect(tokens).toEqual([]);
  });

  it("does not flag low-entropy long tokens", () => {
    const tokens = findHighEntropyTokens("x".repeat(40), DEFAULT_THRESHOLDS);
    expect(tokens).toEqual([]);
  });

  it("skips tokens shorter than the minimum length", () => {
    const tokens = findHighEntropyTokens("abc123xyz", DEFAULT_THRESHOLDS);
    expect(tokens).toEqual([]);
  });

  it("respects a custom minTokenLength", () => {
    const tokens = findHighEntropyTokens("0123456789abcdef", {
      ...DEFAULT_THRESHOLDS,
      minTokenLength: 8,
    });
    // 16 distinct hex chars over length 16 → max entropy 4.0; threshold default 4.5 → not flagged.
    expect(tokens).toEqual([]);
  });
});

describe("scanEntropy", () => {
  it("produces a Finding with correct location and tags", () => {
    const findings = scanEntropy(
      { source: `let k = ${HIGH_ENTROPY};\n`, file: "a.ts" },
      DEFAULT_THRESHOLDS,
    );
    expect(findings).toHaveLength(1);
    const f = findings[0];
    expect(f?.module).toBe("secrets");
    expect(f?.rule).toMatch(/^entropy-/);
    expect(f?.location?.file).toBe("a.ts");
    expect(f?.location?.line_start).toBe(1);
    expect(f?.tags).toContain("secret");
    expect(f?.tags).toContain("entropy");
  });

  it("redacts the literal secret in evidence", () => {
    const findings = scanEntropy({ source: `let k = ${HIGH_ENTROPY};` }, DEFAULT_THRESHOLDS);
    const evidence = findings[0]?.evidence ?? "";
    expect(evidence).not.toContain(HIGH_ENTROPY);
    expect(evidence).toMatch(/len=35/);
  });
});
