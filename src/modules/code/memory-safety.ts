// Memory-safety reviewer (altais_check_memory_safety).
//
// Detects memory-safety defects in C / C++ (unbounded string functions,
// unchecked allocations and copies, double-free, use-after-free) and the
// memory-unsafe Rust operations. The analysis is purely textual.

import type { Finding, Severity } from "../../core/types.js";
import { buildCodeFinding } from "./finding.js";

export type MemorySafetyLanguage = "c" | "cpp" | "rust";

export interface MemorySafetyInput {
  readonly source: string;
  readonly language: MemorySafetyLanguage;
  readonly filename?: string;
}

const REFS = [
  "https://wiki.sei.cmu.edu/confluence/display/c",
  "https://cwe.mitre.org/data/definitions/119.html",
  "https://doc.rust-lang.org/nomicon/",
];

interface LineDetector {
  readonly rule: string;
  readonly severity: Severity;
  readonly title: string;
  readonly description: string;
  readonly remediation: string;
  readonly cwe: readonly string[];
  readonly tags: readonly string[];
  readonly regex: RegExp;
}

// ── C / C++ unbounded and unchecked operations ──────────────────────────

const C_DETECTORS: readonly LineDetector[] = [
  {
    rule: "unbounded-string-copy",
    severity: "high",
    title: "Unbounded string function can overflow the destination buffer",
    description:
      "`strcpy`, `strcat`, `sprintf`, and `gets` copy until a terminator with no destination-size limit. If the source is longer than the destination, the write runs past the buffer — a classic stack or heap overflow.",
    remediation:
      "Use the size-bounded variants (`strlcpy`/`strncpy`, `strlcat`/`strncat`, `snprintf`) and pass the real destination size. Replace `gets` with `fgets`.",
    cwe: ["CWE-120", "CWE-787"],
    tags: ["memory-safety", "buffer-overflow", "cert-c"],
    regex: /\b(?:strcpy|strcat|sprintf|gets)\s*\(/,
  },
  {
    rule: "scanf-unbounded-string",
    severity: "high",
    title: '`scanf("%s")` reads input without a field-width limit',
    description:
      "`%s` in a `scanf`-family format with no field width reads characters until whitespace, with no regard for the destination buffer size — a buffer overflow driven directly by input.",
    remediation:
      "Specify a field width that matches the buffer (`%63s` for a 64-byte buffer), or use `fgets` and parse the result.",
    cwe: ["CWE-120", "CWE-787"],
    tags: ["memory-safety", "buffer-overflow", "cert-c"],
    regex: /\b(?:f|s)?scanf\s*\([^;]*%s/,
  },
  {
    rule: "unchecked-alloc-result",
    severity: "medium",
    title: "Allocation result used without a NULL check",
    description:
      "`malloc` / `calloc` / `realloc` return `NULL` on failure. The result is assigned and used without a NULL check, so an allocation failure leads to a NULL-pointer dereference.",
    remediation:
      "Check the returned pointer against `NULL` immediately after the allocation and handle the failure before any dereference.",
    cwe: ["CWE-476", "CWE-252"],
    tags: ["memory-safety", "null-deref", "cert-c"],
    regex: /\b\w+\s*=\s*(?:\([^)]*\)\s*)?(?:malloc|calloc|realloc)\s*\(/,
  },
  {
    rule: "memcpy-unchecked-size",
    severity: "medium",
    title: "`memcpy` / `memmove` with a non-constant, unchecked size",
    description:
      "A `memcpy` or `memmove` whose length is a variable or expression can overflow the destination if that length is attacker-influenced or simply larger than the buffer.",
    remediation:
      "Bound the copy length to the destination buffer size before the call; prefer `memcpy_s` or an explicit `min(len, capacity)` guard.",
    cwe: ["CWE-120", "CWE-787"],
    tags: ["memory-safety", "buffer-overflow", "cert-c"],
    regex: /\b(?:memcpy|memmove)\s*\([^;]*,[^;]*,\s*(?!sizeof\b)[A-Za-z_]\w*[^;]*\)/,
  },
  {
    rule: "alloca-use",
    severity: "medium",
    title: "`alloca` allocates on the stack with no failure path",
    description:
      "`alloca` grows the stack frame and cannot report failure. A large or input-derived size silently overruns the stack, corrupting the frame.",
    remediation:
      "Use a fixed-size automatic array for small bounded sizes, or `malloc`/`free` (with a NULL check) for variable sizes.",
    cwe: ["CWE-770", "CWE-789"],
    tags: ["memory-safety", "cert-c"],
    regex: /\balloca\s*\(/,
  },
  {
    rule: "double-free",
    severity: "high",
    title: "Pointer is freed more than once",
    description:
      "The same pointer variable is passed to `free` twice without an intervening re-assignment. A double free corrupts allocator metadata and is exploitable for arbitrary code execution.",
    remediation:
      "Free each allocation exactly once and set the pointer to `NULL` immediately after `free` so a second `free(NULL)` is a no-op.",
    cwe: ["CWE-415"],
    tags: ["memory-safety", "cert-c"],
    // Detected at whole-source level; this entry is documentation only.
    regex: /\bfree\s*\(/,
  },
  {
    rule: "use-after-free",
    severity: "high",
    title: "Pointer is used after it was freed",
    description:
      "A pointer variable is dereferenced or passed onward after a `free` of the same variable, with no re-assignment in between. The memory may have been recycled, so the access reads or writes an unrelated object.",
    remediation:
      "After `free`, set the pointer to `NULL` and never dereference it again. Re-architect so ownership and lifetimes are unambiguous.",
    cwe: ["CWE-416"],
    tags: ["memory-safety", "cert-c"],
    // Detected at whole-source level; this entry is documentation only.
    regex: /\bfree\s*\(/,
  },
];

// ── Rust memory-unsafe operations ───────────────────────────────────────

const RUST_DETECTORS: readonly LineDetector[] = [
  {
    rule: "rust-get-unchecked",
    severity: "high",
    title: "`get_unchecked` skips bounds checking",
    description:
      "`get_unchecked` / `get_unchecked_mut` index a slice without a bounds check. An out-of-range index is an out-of-bounds read or write.",
    remediation:
      "Use checked indexing (`[]`) or `.get()` / `.get_mut()`. Reserve `get_unchecked` for paths where the index is already proven in-bounds.",
    cwe: ["CWE-125", "CWE-787"],
    tags: ["memory-safety", "rust"],
    regex: /\bget_unchecked(?:_mut)?\s*\(/,
  },
  {
    rule: "rust-from-raw-parts",
    severity: "high",
    title: "`slice::from_raw_parts` builds a slice from a pointer and length",
    description:
      "`from_raw_parts` constructs a slice with no verification that the pointer is valid for the given length, so a wrong length causes out-of-bounds access.",
    remediation:
      "Guarantee the pointer covers `len` initialized, aligned elements that outlive the slice, with no aliasing `&mut`. Prefer safe slice APIs.",
    cwe: ["CWE-125", "CWE-805"],
    tags: ["memory-safety", "rust"],
    regex: /\b(?:slice::)?from_raw_parts(?:_mut)?\s*\(/,
  },
  {
    rule: "rust-set-len",
    severity: "high",
    title: "`Vec::set_len` changes length without initializing elements",
    description:
      "`set_len` extends a `Vec` over uninitialized memory; later reads observe uninitialized bytes — undefined behaviour.",
    remediation:
      "Use `resize` / `extend` / `push`, and only call `set_len` after every new element is fully initialized.",
    cwe: ["CWE-457", "CWE-908"],
    tags: ["memory-safety", "rust"],
    regex: /\.set_len\s*\(/,
  },
  {
    rule: "rust-uninitialized",
    severity: "high",
    title: "Use of uninitialized memory",
    description:
      "`mem::uninitialized` and `MaybeUninit::assume_init` yield a value the compiler treats as initialized; reading it before real initialization is undefined behaviour.",
    remediation:
      "Use `MaybeUninit` and call `assume_init` only after fully initializing the value. Never use the deprecated `mem::uninitialized`.",
    cwe: ["CWE-457", "CWE-908"],
    tags: ["memory-safety", "rust"],
    regex: /\b(?:mem::uninitialized|assume_init)\s*(?:\(|::)/,
  },
];

/** Strip a trailing `//` comment so detectors do not match commented code. */
function stripLineComment(line: string): string {
  const s = line.indexOf("//");
  return s >= 0 ? line.slice(0, s) : line;
}

/** The variable name passed to `free(...)` on this line, if any. */
function freedVariable(line: string): string | undefined {
  const m = /\bfree\s*\(\s*([A-Za-z_]\w*)\s*\)/.exec(line);
  return m?.[1];
}

/**
 * Whole-source pass for C/C++ that tracks freed pointers to flag a second
 * `free` of the same variable (double free) and a later use of a freed
 * variable (use-after-free). A re-assignment of the variable clears it.
 */
function detectFreeMisuse(
  lines: readonly string[],
  filename: string | undefined,
): readonly Finding[] {
  const findings: Finding[] = [];
  const dfDet = C_DETECTORS.find((d) => d.rule === "double-free");
  const uafDet = C_DETECTORS.find((d) => d.rule === "use-after-free");
  if (dfDet === undefined || uafDet === undefined) return findings;

  /** Variables currently in the "freed, not re-assigned" state. */
  const freed = new Map<string, number>();

  for (let idx = 0; idx < lines.length; idx++) {
    const line = stripLineComment(lines[idx] ?? "");
    if (line.trim() === "") continue;

    const freedVar = freedVariable(line);

    // Re-assignment clears the freed state for that variable.
    const assignMatch = /^\s*([A-Za-z_]\w*)\s*=(?!=)/.exec(line);
    const assigned = assignMatch?.[1];
    if (assigned !== undefined && freed.has(assigned) && assigned !== freedVar) {
      freed.delete(assigned);
    }

    if (freedVar !== undefined) {
      if (freed.has(freedVar)) {
        findings.push(mk(dfDet, idx + 1, line.trim().slice(0, 200), filename));
      } else {
        freed.set(freedVar, idx + 1);
      }
      continue;
    }

    // Use of a freed variable: a dereference / member access / call arg.
    for (const [name] of freed) {
      const useRe = new RegExp(
        `\\*\\s*${name}\\b|\\b${name}\\s*(?:->|\\[)|\\b\\w+\\s*\\(\\s*${name}\\b`,
      );
      if (useRe.test(line)) {
        findings.push(mk(uafDet, idx + 1, line.trim().slice(0, 200), filename));
        freed.delete(name);
      }
    }
  }
  return findings;
}

function mk(
  det: LineDetector,
  line: number,
  evidence: string,
  filename: string | undefined,
): Finding {
  return buildCodeFinding(
    {
      rule: det.rule,
      severity: det.severity,
      title: det.title,
      description: det.description,
      remediation: det.remediation,
      cwe: det.cwe,
      references: REFS,
      evidence,
      tags: det.tags,
      line,
    },
    filename,
  );
}

export function checkMemorySafety(input: MemorySafetyInput): readonly Finding[] {
  const { source, language } = input;
  const filename = input.filename;
  const findings: Finding[] = [];
  const lines = source.split(/\r?\n/);

  if (language === "rust") {
    for (let idx = 0; idx < lines.length; idx++) {
      const line = stripLineComment(lines[idx] ?? "");
      if (line.trim() === "") continue;
      for (const det of RUST_DETECTORS) {
        const m = det.regex.exec(line);
        if (m === null) continue;
        findings.push(mk(det, idx + 1, m[0].trim().slice(0, 200), filename));
      }
    }
    return findings;
  }

  // C / C++ line detectors (excluding the free-tracking rules).
  const lineDetectors = C_DETECTORS.filter(
    (d) => d.rule !== "double-free" && d.rule !== "use-after-free",
  );
  for (let idx = 0; idx < lines.length; idx++) {
    const line = stripLineComment(lines[idx] ?? "");
    if (line.trim() === "") continue;
    for (const det of lineDetectors) {
      const m = det.regex.exec(line);
      if (m === null) continue;
      findings.push(mk(det, idx + 1, m[0].trim().slice(0, 200), filename));
    }
  }

  findings.push(...detectFreeMisuse(lines, filename));
  return findings;
}
