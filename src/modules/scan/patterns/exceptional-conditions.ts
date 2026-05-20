// Exceptional-conditions patterns: OWASP A10:2025.
// Covers fail-open empty catch blocks and stack-trace leakage.

import type { Pattern } from "./types.js";

const REFS_EC = [
  "https://cwe.mitre.org/data/definitions/703.html",
  "https://cwe.mitre.org/data/definitions/755.html",
  "OWASP Top 10 2025 A10",
];
const REFS_LEAK = ["https://cwe.mitre.org/data/definitions/209.html", "OWASP Top 10 2025 A02"];
const REFS_UNCHECKED = [
  "https://cwe.mitre.org/data/definitions/390.html",
  "https://cwe.mitre.org/data/definitions/703.html",
  "OWASP Top 10 2025 A10",
];
const REFS_PANIC = [
  "https://cwe.mitre.org/data/definitions/248.html",
  "https://cwe.mitre.org/data/definitions/617.html",
  "OWASP Top 10 2025 A10",
];

export const EXCEPTIONAL_CONDITIONS_PATTERNS: readonly Pattern[] = [
  {
    id: "empty-catch-js",
    category: "exceptional-conditions",
    title: "Empty catch block silently swallows errors",
    description:
      "A `catch` block with no body suppresses every exception with no observability. Failures become invisible and can leave the program in an inconsistent state.",
    severity: "medium",
    cwe: ["CWE-755"],
    remediation:
      "At minimum, log the error with context. Decide what state to restore on failure. If the error is genuinely safe to ignore, leave a comment that explains why.",
    references: REFS_EC,
    languages: ["javascript", "typescript"],
    matcher: {
      type: "regex",
      regex: /\bcatch\s*(?:\([^)]*\))?\s*\{\s*\}/,
    },
  },
  {
    id: "empty-promise-catch-js",
    category: "exceptional-conditions",
    title: "Promise `.catch()` with empty handler",
    description:
      "A promise chain catches errors with an empty handler, hiding rejections. Async failures will not surface in logs or monitoring.",
    severity: "medium",
    cwe: ["CWE-755"],
    remediation:
      "Replace the empty handler with a logger call. If swallowing is intentional, leave a comment justifying it.",
    references: REFS_EC,
    languages: ["javascript", "typescript"],
    matcher: {
      type: "regex",
      regex:
        /\.catch\s*\(\s*(?:\([^)]*\)\s*=>\s*\{\s*\}|\(\s*\)\s*=>\s*undefined|function\s*\([^)]*\)\s*\{\s*\}|\(\s*\)\s*=>\s*\{\s*\})\s*\)/,
    },
  },
  {
    id: "stack-trace-response-js",
    category: "exceptional-conditions",
    title: "Stack trace returned in HTTP response",
    description:
      "An HTTP response includes `err.stack` or `error.stack`. Stack traces leak file paths, library versions, and internal call structure to clients.",
    severity: "medium",
    cwe: ["CWE-209"],
    remediation:
      "Log the stack server-side with a correlation ID; return a sanitized error envelope with that ID. Disable framework-default error pages in production.",
    references: REFS_LEAK,
    languages: ["javascript", "typescript"],
    matcher: {
      type: "regex",
      regex: /(res|response|reply)\.(send|json|write|end)\s*\([^)]*\b(?:err|error|e)\.stack\b/,
    },
  },
  {
    id: "fail-open-truthy-catch-js",
    category: "exceptional-conditions",
    title: "Catch block returns truthy / `true` (fail-open)",
    description:
      "A catch block returns `true` (or another truthy literal) on error, effectively making the function 'succeed' on failure. Permission checks, validations, and feature flags written this way fail open.",
    severity: "high",
    cwe: ["CWE-755", "CWE-693"],
    remediation:
      "Default to the safe state on error (false / closed / 403). Surface unexpected failures; do not pretend the operation succeeded.",
    references: REFS_EC,
    languages: ["javascript", "typescript"],
    matcher: {
      type: "regex",
      regex: /\bcatch\s*(?:\([^)]*\))?\s*\{\s*return\s+true\s*;?\s*\}/,
    },
  },
  {
    id: "empty-except-py",
    category: "exceptional-conditions",
    title: "`except: pass` swallows every exception",
    description:
      "A bare `except: pass` (or `except Exception: pass`) silences errors without observability. This includes `KeyboardInterrupt` and `SystemExit` for bare `except`.",
    severity: "medium",
    cwe: ["CWE-755"],
    remediation:
      "Catch specific exception classes. At minimum, `log.exception(...)` so the failure is visible. If swallowing is intentional, leave a justifying comment.",
    references: REFS_EC,
    languages: ["python"],
    matcher: {
      type: "regex",
      regex: /\bexcept\b[^\n:]*:\s*(?:pass|\.\.\.)\b/,
    },
  },
  {
    id: "fail-open-except-true-py",
    category: "exceptional-conditions",
    title: "`except` block returns `True` (fail-open)",
    description:
      "An `except` block returns `True` on error. Functions like permission checks written this way grant access on every unexpected condition.",
    severity: "high",
    cwe: ["CWE-755", "CWE-693"],
    remediation:
      "Return `False` (or raise) on unexpected errors. Never default to the permissive answer in an except handler.",
    references: REFS_EC,
    languages: ["python"],
    matcher: {
      type: "regex",
      regex: /\bexcept\b[^\n:]*:\s*(?:#[^\n]*\n\s*)?return\s+True\b/,
    },
  },
  {
    id: "stack-trace-response-py",
    category: "exceptional-conditions",
    title: "Stack trace returned in HTTP response (Python)",
    description:
      "A handler returns `traceback.format_exc()` or `str(e)` combined with traceback data. This leaks file paths, library versions, and internal call structure.",
    severity: "medium",
    cwe: ["CWE-209"],
    remediation:
      "Log full tracebacks server-side; return a generic error envelope with a correlation ID. Disable framework debug modes in production.",
    references: REFS_LEAK,
    languages: ["python"],
    matcher: {
      type: "regex",
      regex: /\breturn\s+traceback\.format_exc\s*\(/,
    },
  },
  {
    id: "discarded-error-go",
    category: "exceptional-conditions",
    title: "Error return value explicitly discarded (Go)",
    description:
      "An error returned by a call is assigned to the blank identifier `_` (either as `_ = call(...)` or `, _ :=`). The failure is silently dropped, so the program may continue in an inconsistent state.",
    severity: "medium",
    cwe: ["CWE-390"],
    remediation:
      "Check the returned error: `if err != nil { return err }` (or log it with context). Only discard an error to `_` when you have documented why it is safe.",
    references: REFS_UNCHECKED,
    languages: ["go"],
    matcher: {
      type: "regex",
      regex: /(?:^|[;{}\s])_\s*(?::?=)\s*[A-Za-z_][\w.]*\s*\(|,\s*_\s*:?=\s*[A-Za-z_][\w.]*\s*\(/m,
    },
  },
  {
    id: "panic-go",
    category: "exceptional-conditions",
    title: "panic() used for error handling (Go)",
    description:
      "`panic(...)` aborts the goroutine and, if unrecovered, crashes the process. Using it for ordinary error handling turns recoverable conditions into denial-of-service.",
    severity: "medium",
    cwe: ["CWE-703"],
    remediation:
      "Return an `error` value instead of calling `panic`. Reserve `panic` for truly unrecoverable programmer errors, and `recover` at goroutine boundaries.",
    references: REFS_UNCHECKED,
    languages: ["go"],
    matcher: {
      type: "regex",
      regex: /(?<![.\w])panic\s*\(/,
    },
  },
  {
    id: "empty-error-check-go",
    category: "exceptional-conditions",
    title: "Empty `if err != nil {}` block (Go)",
    description:
      "An `if err != nil { }` block has no body, so a detected error is recognized and then ignored. This is functionally the same as discarding the error.",
    severity: "medium",
    cwe: ["CWE-755"],
    remediation:
      "Handle the error inside the block: return it, wrap it with context, or log it. An empty error branch should never ship.",
    references: REFS_EC,
    languages: ["go"],
    matcher: {
      type: "regex",
      regex: /\bif\s+err\s*!=\s*nil\s*\{\s*\}/,
    },
  },
  {
    id: "unwrap-expect-rust",
    category: "exceptional-conditions",
    title: "`.unwrap()` / `.expect()` panics on Err/None (Rust)",
    description:
      "`.unwrap()` and `.expect(...)` on a `Result` or `Option` panic when the value is `Err`/`None`. If the value can be influenced by input, this is a remotely triggerable denial-of-service.",
    severity: "medium",
    cwe: ["CWE-248"],
    remediation:
      "Propagate the error with `?`, or handle both arms with `match`/`if let`. Reserve `.unwrap()`/`.expect()` for cases that are provably infallible.",
    references: REFS_PANIC,
    languages: ["rust"],
    matcher: {
      type: "regex",
      regex: /\.(unwrap|expect)\s*\(/,
    },
  },
  {
    id: "panic-macro-rust",
    category: "exceptional-conditions",
    title: "`panic!` / `unreachable!` reachable from input (Rust)",
    description:
      "`panic!`, `unreachable!`, and `unimplemented!` abort the current thread. When reachable from user input, they convert recoverable conditions into a crash or denial-of-service.",
    severity: "medium",
    cwe: ["CWE-617"],
    remediation:
      "Return a `Result::Err` for recoverable conditions. Reserve `panic!`/`unreachable!` for invariants that cannot be violated by external input.",
    references: REFS_PANIC,
    languages: ["rust"],
    matcher: {
      type: "regex",
      regex: /(?<![.\w])(?:panic|unreachable|unimplemented)!\s*[([{]/,
    },
  },
];
