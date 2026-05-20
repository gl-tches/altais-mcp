// Rust `unsafe` auditor (altais_audit_unsafe).
//
// Scans Rust source for `unsafe` blocks / functions and for the specific
// operations that make `unsafe` unsound when used carelessly. The audit is
// textual — line-by-line scanning and brace tracking — it never compiles
// or runs the target code.

import type { Finding, Severity } from "../../core/types.js";
import { buildCodeFinding } from "./finding.js";

export interface UnsafeAuditInput {
  readonly source: string;
  readonly filename?: string;
}

const REFS = [
  "https://doc.rust-lang.org/nomicon/",
  "https://doc.rust-lang.org/reference/unsafety.html",
  "https://cwe.mitre.org/data/definitions/119.html",
];

interface OpDetector {
  readonly rule: string;
  readonly severity: Severity;
  readonly title: string;
  readonly description: string;
  readonly remediation: string;
  readonly cwe: readonly string[];
  readonly tags: readonly string[];
  readonly regex: RegExp;
}

const OP_DETECTORS: readonly OpDetector[] = [
  {
    rule: "unsafe-transmute",
    severity: "high",
    title: "`std::mem::transmute` reinterprets memory between types",
    description:
      "`transmute` bypasses the type system and copies bits from one type to another. A size or validity mismatch is instant undefined behaviour — it is one of the most dangerous functions in Rust.",
    remediation:
      "Prefer a safe conversion: `as` casts for numbers, `from_ne_bytes` / `to_ne_bytes` for byte reinterpretation, or `bytemuck` for plain-old-data. If `transmute` is unavoidable, prove the layouts and validity invariants match.",
    cwe: ["CWE-704", "CWE-843"],
    tags: ["rust", "unsafe", "transmute"],
    regex: /\b(?:std::|core::)?mem::transmute(?:_copy)?\b/,
  },
  {
    rule: "unsafe-static-mut",
    severity: "high",
    title: "`static mut` is a mutable global with no synchronization",
    description:
      "Every access to a `static mut` is `unsafe` because nothing prevents a data race. Concurrent reads and writes are undefined behaviour.",
    remediation:
      "Replace `static mut` with an interior-mutability type that enforces synchronization: `AtomicUsize`/`AtomicBool`, `Mutex`, `RwLock`, or `OnceLock` for one-time init.",
    cwe: ["CWE-362", "CWE-665"],
    tags: ["rust", "unsafe", "concurrency"],
    regex: /\bstatic\s+mut\s+\w+/,
  },
  {
    rule: "unsafe-raw-pointer-deref",
    severity: "high",
    title: "Raw pointer dereference",
    description:
      "Dereferencing a `*const` / `*mut` raw pointer is unchecked: a dangling, null, misaligned, or aliasing pointer causes undefined behaviour with no diagnostic.",
    remediation:
      "Where possible use references, slices, or `NonNull` with documented invariants. Before dereferencing, prove the pointer is non-null, aligned, and points to a live, correctly-typed value.",
    cwe: ["CWE-476", "CWE-825"],
    tags: ["rust", "unsafe", "pointer"],
    regex: /(?:^|[^&\w])\*\s*(?:const\s+|mut\s+)?(?:\(\s*\*?\s*)?\w*ptr\w*/i,
  },
  {
    rule: "unsafe-get-unchecked",
    severity: "high",
    title: "`get_unchecked` skips bounds checking",
    description:
      "`get_unchecked` / `get_unchecked_mut` index a slice without a bounds check. An out-of-range index reads or writes out of bounds — a memory-safety violation.",
    remediation:
      "Use the checked `[]` indexing operator or `.get()` / `.get_mut()`. Reserve `get_unchecked` for hot paths where the index was already proven in-bounds, and document that proof.",
    cwe: ["CWE-125", "CWE-787"],
    tags: ["rust", "unsafe", "memory-safety"],
    regex: /\bget_unchecked(?:_mut)?\s*\(/,
  },
  {
    rule: "unsafe-from-raw-parts",
    severity: "high",
    title: "`slice::from_raw_parts` builds a slice from a pointer and length",
    description:
      "`from_raw_parts` / `from_raw_parts_mut` construct a slice with no verification that the pointer is valid for the given length. A wrong length yields out-of-bounds access.",
    remediation:
      "Ensure the pointer points to `len` contiguous, initialized, correctly-aligned elements that outlive the slice, and that no aliasing `&mut` exists. Prefer safe slice APIs where the data is already owned.",
    cwe: ["CWE-125", "CWE-805"],
    tags: ["rust", "unsafe", "memory-safety"],
    regex: /\b(?:slice::)?from_raw_parts(?:_mut)?\s*\(/,
  },
  {
    rule: "unsafe-set-len",
    severity: "high",
    title: "`Vec::set_len` changes the length without initializing elements",
    description:
      "`set_len` declares a `Vec` longer (or shorter) without touching its buffer. Growing the length over uninitialized memory means later reads observe uninitialized data — undefined behaviour.",
    remediation:
      "Use `resize`, `extend`, `push`, or `Vec::with_capacity` plus `MaybeUninit` patterns. Only call `set_len` after the new elements have been fully initialized.",
    cwe: ["CWE-457", "CWE-908"],
    tags: ["rust", "unsafe", "uninitialized"],
    regex: /\.set_len\s*\(/,
  },
  {
    rule: "unsafe-uninitialized",
    severity: "high",
    title: "Use of uninitialized memory",
    description:
      "`mem::uninitialized` (deprecated) and `MaybeUninit::assume_init` produce a value the compiler believes is initialized. Reading it before real initialization is undefined behaviour.",
    remediation:
      "Use `MaybeUninit` and only call `assume_init` after every byte of the value has been written. Never use `mem::uninitialized` — it is unsound for most types.",
    cwe: ["CWE-457", "CWE-908"],
    tags: ["rust", "unsafe", "uninitialized"],
    regex: /\b(?:mem::uninitialized|assume_init)\s*(?:\(|::)/,
  },
  {
    rule: "unsafe-ptr-read-write",
    severity: "medium",
    title: "`ptr::read` / `ptr::write` performs an unchecked memory access",
    description:
      "`ptr::read`, `ptr::write`, and their volatile/unaligned variants move values through a raw pointer with no aliasing or validity checks. Misuse causes double-drops, use-after-free, or torn reads.",
    remediation:
      "Confirm the pointer is valid and aligned, and reason carefully about ownership: `ptr::read` produces an owned value, so the source must not be dropped again. Prefer safe assignment where possible.",
    cwe: ["CWE-416", "CWE-787"],
    tags: ["rust", "unsafe", "pointer"],
    regex: /\bptr::(?:read|write)(?:_volatile|_unaligned)?\s*\(/,
  },
];

/** Strip a trailing `//` comment so detectors do not match commented code. */
function stripLineComment(line: string): string {
  const s = line.indexOf("//");
  return s >= 0 ? line.slice(0, s) : line;
}

/** True if any line within `lookback` lines above `idx` carries a SAFETY note. */
function hasSafetyComment(lines: readonly string[], idx: number): boolean {
  const SAFETY_RE = /\/\/[/!]?\s*SAFETY\s*:/i;
  for (let j = idx - 1; j >= 0 && j >= idx - 6; j--) {
    const prev = (lines[j] ?? "").trim();
    if (SAFETY_RE.test(prev)) return true;
    // Stop at a blank line or a non-comment line — the justification, if
    // any, must directly precede the `unsafe` construct.
    if (prev === "") return false;
    if (!prev.startsWith("//")) return false;
  }
  return false;
}

const UNSAFE_RE = /\bunsafe\s+(?:fn\b|\{|impl\b|extern\b)/;

export function auditUnsafe(input: UnsafeAuditInput): readonly Finding[] {
  const { source } = input;
  const filename = input.filename;
  const findings: Finding[] = [];
  const lines = source.split(/\r?\n/);

  for (let idx = 0; idx < lines.length; idx++) {
    const raw = lines[idx] ?? "";
    const code = stripLineComment(raw);
    if (code.trim() === "") continue;

    // ── Undocumented `unsafe` construct ─────────────────────────────────
    const unsafeMatch = UNSAFE_RE.exec(code);
    if (unsafeMatch !== null && !hasSafetyComment(lines, idx)) {
      findings.push(
        buildCodeFinding(
          {
            rule: "unsafe-missing-safety-comment",
            severity: "medium",
            title: "`unsafe` block or function has no `// SAFETY:` justification",
            description:
              "An `unsafe` construct shifts a soundness obligation onto the author. Without a `// SAFETY:` comment stating which invariants make it sound, reviewers cannot verify it and future edits can silently break it.",
            remediation:
              "Add a `// SAFETY:` comment directly above the `unsafe` block or function that explains precisely why every operation inside it upholds Rust's safety invariants.",
            cwe: ["CWE-758", "CWE-1059"],
            references: REFS,
            evidence: code.trim().slice(0, 200),
            tags: ["rust", "unsafe", "documentation"],
            line: idx + 1,
          },
          filename,
        ),
      );
    }

    // ── Specific unsound operations ─────────────────────────────────────
    for (const det of OP_DETECTORS) {
      const m = det.regex.exec(code);
      if (m === null) continue;
      findings.push(
        buildCodeFinding(
          {
            rule: det.rule,
            severity: det.severity,
            title: det.title,
            description: det.description,
            remediation: det.remediation,
            cwe: det.cwe,
            references: REFS,
            evidence: m[0].trim().slice(0, 200),
            tags: det.tags,
            line: idx + 1,
          },
          filename,
        ),
      );
    }
  }

  return findings;
}
