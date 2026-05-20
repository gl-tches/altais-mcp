import { describe, expect, it } from "vitest";
import { checkMemorySafety, type MemorySafetyLanguage } from "./memory-safety.js";

const has = (source: string, language: MemorySafetyLanguage, rule: string): boolean =>
  checkMemorySafety({ source, language }).some((f) => f.rule === rule);

describe("checkMemorySafety — C/C++ unbounded operations", () => {
  it("flags strcpy", () => {
    expect(has("strcpy(dst, src);\n", "c", "unbounded-string-copy")).toBe(true);
  });

  it("flags gets", () => {
    expect(has("gets(buf);\n", "c", "unbounded-string-copy")).toBe(true);
  });

  it('flags scanf("%s")', () => {
    expect(has('scanf("%s", buf);\n', "c", "scanf-unbounded-string")).toBe(true);
  });

  it("flags alloca", () => {
    expect(has("char *p = alloca(n);\n", "c", "alloca-use")).toBe(true);
  });

  it("does not flag snprintf", () => {
    expect(has('snprintf(buf, sizeof(buf), "%s", src);\n', "c", "unbounded-string-copy")).toBe(
      false,
    );
  });
});

describe("checkMemorySafety — allocation and copy", () => {
  it("flags an allocation result used without a NULL check", () => {
    expect(has("char *p = malloc(64);\n", "c", "unchecked-alloc-result")).toBe(true);
  });

  it("flags memcpy with a variable size", () => {
    expect(has("memcpy(dst, src, len);\n", "c", "memcpy-unchecked-size")).toBe(true);
  });

  it("does not flag memcpy with a sizeof constant", () => {
    expect(has("memcpy(dst, src, sizeof(int));\n", "c", "memcpy-unchecked-size")).toBe(false);
  });
});

describe("checkMemorySafety — free misuse", () => {
  it("flags a double free of the same pointer", () => {
    const src = "free(p);\nfree(p);\n";
    expect(has(src, "c", "double-free")).toBe(true);
  });

  it("flags use-after-free", () => {
    const src = 'free(p);\nprintf("%d", p->id);\n';
    expect(has(src, "c", "use-after-free")).toBe(true);
  });

  it("does not flag a single free", () => {
    expect(has("free(p);\n", "c", "double-free")).toBe(false);
  });

  it("does not flag a free after re-assignment", () => {
    const src = "free(p);\np = malloc(8);\nfree(p);\n";
    expect(has(src, "c", "double-free")).toBe(false);
  });
});

describe("checkMemorySafety — Rust", () => {
  it("flags get_unchecked", () => {
    expect(has("let v = s.get_unchecked(i);\n", "rust", "rust-get-unchecked")).toBe(true);
  });

  it("flags from_raw_parts", () => {
    expect(has("let s = slice::from_raw_parts(p, n);\n", "rust", "rust-from-raw-parts")).toBe(true);
  });

  it("flags set_len", () => {
    expect(has("v.set_len(n);\n", "rust", "rust-set-len")).toBe(true);
  });

  it("does not flag safe Rust", () => {
    expect(checkMemorySafety({ source: "let x = vec.get(0);\n", language: "rust" })).toHaveLength(
      0,
    );
  });
});

describe("checkMemorySafety — finding shape", () => {
  it("produces deterministic finding IDs across runs", () => {
    const src = "strcpy(dst, src);\nchar *p = malloc(8);\n";
    const a = checkMemorySafety({ source: src, language: "c", filename: "m.c" });
    const b = checkMemorySafety({ source: src, language: "c", filename: "m.c" });
    expect(a.map((f) => f.id)).toEqual(b.map((f) => f.id));
  });

  it("tags every finding with the code module and a CWE", () => {
    const findings = checkMemorySafety({ source: "strcpy(dst, src);\n", language: "c" });
    expect(findings.length).toBeGreaterThan(0);
    for (const f of findings) {
      expect(f.module).toBe("code");
      expect(f.tags).toContain("code");
      expect(f.cwe?.length ?? 0).toBeGreaterThan(0);
    }
  });
});
