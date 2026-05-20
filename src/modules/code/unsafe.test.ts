import { describe, expect, it } from "vitest";
import { auditUnsafe } from "./unsafe.js";

const has = (source: string, rule: string): boolean =>
  auditUnsafe({ source }).some((f) => f.rule === rule);

describe("auditUnsafe — SAFETY comments", () => {
  it("flags an unsafe block with no SAFETY comment", () => {
    expect(has("unsafe {\n  do_it();\n}\n", "unsafe-missing-safety-comment")).toBe(true);
  });

  it("accepts an unsafe block with a preceding SAFETY comment", () => {
    const src = "// SAFETY: index is checked above\nunsafe {\n  do_it();\n}\n";
    expect(has(src, "unsafe-missing-safety-comment")).toBe(false);
  });

  it("flags an unsafe fn with no SAFETY comment", () => {
    expect(has("unsafe fn raw() {}\n", "unsafe-missing-safety-comment")).toBe(true);
  });
});

describe("auditUnsafe — unsound operations", () => {
  it("flags mem::transmute", () => {
    expect(has("let x = std::mem::transmute(y);\n", "unsafe-transmute")).toBe(true);
  });

  it("flags static mut", () => {
    expect(has("static mut COUNTER: u32 = 0;\n", "unsafe-static-mut")).toBe(true);
  });

  it("flags get_unchecked", () => {
    expect(has("let v = slice.get_unchecked(i);\n", "unsafe-get-unchecked")).toBe(true);
  });

  it("flags slice::from_raw_parts", () => {
    expect(has("let s = slice::from_raw_parts(ptr, len);\n", "unsafe-from-raw-parts")).toBe(true);
  });

  it("flags Vec::set_len", () => {
    expect(has("v.set_len(new_len);\n", "unsafe-set-len")).toBe(true);
  });

  it("flags MaybeUninit::assume_init", () => {
    expect(has("let v = buf.assume_init();\n", "unsafe-uninitialized")).toBe(true);
  });

  it("flags ptr::read", () => {
    expect(has("let v = ptr::read(src);\n", "unsafe-ptr-read-write")).toBe(true);
  });

  it("flags a raw pointer dereference", () => {
    expect(has("let v = *raw_ptr;\n", "unsafe-raw-pointer-deref")).toBe(true);
  });
});

describe("auditUnsafe — negative cases", () => {
  it("does not flag safe Rust code", () => {
    const findings = auditUnsafe({ source: "fn add(a: u32, b: u32) -> u32 {\n  a + b\n}\n" });
    expect(findings).toHaveLength(0);
  });

  it("does not flag transmute mentioned in a comment", () => {
    expect(has("// avoid std::mem::transmute here\n", "unsafe-transmute")).toBe(false);
  });
});

describe("auditUnsafe — finding shape", () => {
  it("produces deterministic finding IDs across runs", () => {
    const src = "unsafe {\n  let x = std::mem::transmute(y);\n}\n";
    const a = auditUnsafe({ source: src, filename: "lib.rs" });
    const b = auditUnsafe({ source: src, filename: "lib.rs" });
    expect(a.map((f) => f.id)).toEqual(b.map((f) => f.id));
  });

  it("tags every finding with the code module and a CWE", () => {
    const findings = auditUnsafe({ source: "static mut X: u8 = 0;\n" });
    expect(findings.length).toBeGreaterThan(0);
    for (const f of findings) {
      expect(f.module).toBe("code");
      expect(f.tags).toContain("code");
      expect(f.cwe?.length ?? 0).toBeGreaterThan(0);
    }
  });
});
