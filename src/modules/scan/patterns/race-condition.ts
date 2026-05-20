// Race-condition patterns: time-of-check / time-of-use (TOCTOU) file access
// and goroutine loop-variable capture.
//
// CWE-362: Concurrent Execution using Shared Resource with Improper Synchronization.
// CWE-367: Time-of-check Time-of-use (TOCTOU) Race Condition.

import type { Pattern, PatternMatch } from "./types.js";

const REFS_RACE = [
  "https://cwe.mitre.org/data/definitions/362.html",
  "https://cwe.mitre.org/data/definitions/367.html",
];

/**
 * Reports a finding when a `check` regex matches a line and a `use` regex
 * matches a later line within `window` lines. Used for TOCTOU detection where
 * an existence check is followed by an unguarded file operation.
 */
function toctou(
  checkRe: RegExp,
  useRe: RegExp,
  window: number,
): (ctx: { readonly lines: readonly string[] }) => readonly PatternMatch[] {
  return (ctx): readonly PatternMatch[] => {
    const out: PatternMatch[] = [];
    const lines = ctx.lines;
    for (let i = 0; i < lines.length; i++) {
      const checkLine = lines[i];
      if (checkLine === undefined) continue;
      const cm = new RegExp(checkRe.source).exec(checkLine);
      if (cm === null) continue;
      const end = Math.min(lines.length, i + 1 + window);
      for (let j = i + 1; j < end; j++) {
        const useLine = lines[j];
        if (useLine === undefined) continue;
        if (new RegExp(useRe.source).test(useLine)) {
          out.push({
            line_start: i + 1,
            line_end: j + 1,
            column: cm.index + 1,
            evidence: `${checkLine.trim()} … ${useLine.trim()}`.slice(0, 160),
          });
          break;
        }
      }
    }
    return out;
  };
}

export const RACE_CONDITION_PATTERNS: readonly Pattern[] = [
  {
    id: "race-toctou-fs-check-use-js",
    category: "race-condition",
    title: "TOCTOU: fs existence check followed by file operation",
    description:
      "An `fs.exists`/`fs.existsSync`/`fs.access` check is followed by `fs.readFile`/`fs.writeFile`/`fs.open` on the same path. An attacker can swap the file (e.g. via a symlink) between the check and the use.",
    severity: "medium",
    cwe: ["CWE-362", "CWE-367"],
    remediation:
      "Drop the pre-check and operate directly on the file, handling the error from the operation. Open with the appropriate exclusive flags (`wx`) and operate on the file descriptor.",
    references: REFS_RACE,
    languages: ["javascript", "typescript"],
    matcher: {
      type: "function",
      fn: toctou(
        /\bfs\.(?:existsSync|exists|accessSync|access)\s*\(/,
        /\bfs\.(?:readFile|readFileSync|writeFile|writeFileSync|open|openSync|appendFile)\s*\(/,
        8,
      ),
    },
  },
  {
    id: "race-toctou-os-path-check-use-py",
    category: "race-condition",
    title: "TOCTOU: os.path.exists/os.access then open() (Python)",
    description:
      "An `os.path.exists` or `os.access` check is followed by an `open()` on the same path. The file can be replaced between the check and the open, defeating the guard.",
    severity: "medium",
    cwe: ["CWE-362", "CWE-367"],
    remediation:
      "Use EAFP: call `open()` directly and catch `FileNotFoundError`/`PermissionError`. For exclusive creation use the `'x'` mode. Do not rely on `os.access` for security decisions.",
    references: REFS_RACE,
    languages: ["python"],
    matcher: {
      type: "function",
      fn: toctou(/\bos\.(?:path\.exists|access)\s*\(/, /(?:^|[^.\w])open\s*\(/, 8),
    },
  },
  {
    id: "race-insecure-mktemp-py",
    category: "race-condition",
    title: "Insecure temporary file via tempfile.mktemp()",
    description:
      "`tempfile.mktemp()` only returns a name; the file is created later, leaving a window where an attacker can pre-create it as a symlink. This is a classic TOCTOU temp-file race.",
    severity: "high",
    cwe: ["CWE-362", "CWE-367"],
    remediation:
      "Use `tempfile.mkstemp()` or `tempfile.NamedTemporaryFile()`, which atomically create the file with safe permissions and return an open handle.",
    references: REFS_RACE,
    languages: ["python"],
    matcher: {
      type: "regex",
      regex: /\btempfile\.mktemp\s*\(/,
    },
  },
  {
    id: "race-toctou-os-stat-open-go",
    category: "race-condition",
    title: "TOCTOU: os.Stat/os.Lstat followed by os.Open/os.Create (Go)",
    description:
      "An `os.Stat`/`os.Lstat` check is followed by `os.Open`/`os.Create`/`os.OpenFile` on the same path. The filesystem entry can change between the stat and the open.",
    severity: "medium",
    cwe: ["CWE-362", "CWE-367"],
    remediation:
      "Open the file first and inspect it via the returned `*os.File` (`f.Stat()`). Use `O_EXCL`/`O_NOFOLLOW` flags with `os.OpenFile` when creating or to refuse symlinks.",
    references: REFS_RACE,
    languages: ["go"],
    matcher: {
      type: "function",
      fn: toctou(/\bos\.(?:Stat|Lstat)\s*\(/, /\bos\.(?:Open|OpenFile|Create)\s*\(/, 8),
    },
  },
  {
    id: "race-goroutine-loop-var-capture-go",
    category: "race-condition",
    title: "Goroutine inside a for loop closing over the loop variable",
    description:
      "A `go func() { ... }()` is launched inside a `for` loop and references the loop variable by closure. Before Go 1.22 all iterations share one variable, so the goroutines observe a racing, often final, value.",
    severity: "medium",
    cwe: ["CWE-362"],
    remediation:
      "Pass the loop variable as an argument to the goroutine (`go func(v T) { ... }(v)`), or shadow it inside the loop body (`v := v`). On Go 1.22+ confirm the module's `go` directive.",
    references: REFS_RACE,
    languages: ["go"],
    matcher: {
      type: "function",
      fn: (ctx): readonly PatternMatch[] => {
        const lines = ctx.lines;
        const out: PatternMatch[] = [];
        for (let i = 0; i < lines.length; i++) {
          const line = lines[i];
          if (line === undefined) continue;
          if (!/\bfor\b[^\n]*\{/.test(line)) continue;
          const end = Math.min(lines.length, i + 1 + 12);
          for (let j = i + 1; j < end; j++) {
            const inner = lines[j];
            if (inner === undefined) continue;
            // A goroutine spawned with a closure that takes no arguments.
            if (/\bgo\s+func\s*\(\s*\)\s*\{/.test(inner)) {
              out.push({
                line_start: i + 1,
                line_end: j + 1,
                column: 1,
                evidence: `${line.trim()} … ${inner.trim()}`.slice(0, 160),
              });
              break;
            }
          }
        }
        return out;
      },
    },
  },
];
