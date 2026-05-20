// Error-handling reviewer (altais_check_error_handling).
//
// Detects error handling that leaks sensitive information to clients
// (stack traces, exception messages, debug mode) or that silently
// swallows errors. The analysis is purely textual.

import type { Finding, Severity } from "../../core/types.js";
import { buildCodeFinding } from "./finding.js";

export type ErrorHandlingLanguage =
  | "c"
  | "cpp"
  | "java"
  | "python"
  | "javascript"
  | "typescript"
  | "go";

export interface ErrorHandlingInput {
  readonly source: string;
  readonly language: ErrorHandlingLanguage;
  readonly filename?: string;
}

const REFS = [
  "https://cwe.mitre.org/data/definitions/209.html",
  "https://owasp.org/www-community/Improper_Error_Handling",
  "https://owasp.org/Top10/A05_2021-Security_Misconfiguration/",
];

interface LineDetector {
  readonly rule: string;
  readonly severity: Severity;
  readonly title: string;
  readonly description: string;
  readonly remediation: string;
  readonly cwe: readonly string[];
  readonly tags: readonly string[];
  readonly languages: ReadonlySet<ErrorHandlingLanguage>;
  readonly regex: RegExp;
}

const JS_TS: ReadonlySet<ErrorHandlingLanguage> = new Set(["javascript", "typescript"]);
const PY: ReadonlySet<ErrorHandlingLanguage> = new Set(["python"]);
const JAVA: ReadonlySet<ErrorHandlingLanguage> = new Set(["java"]);
const ALL_LANGS: ReadonlySet<ErrorHandlingLanguage> = new Set([
  "c",
  "cpp",
  "java",
  "python",
  "javascript",
  "typescript",
  "go",
]);

const DETECTORS: readonly LineDetector[] = [
  {
    rule: "stack-trace-in-response",
    severity: "high",
    title: "Stack trace returned to the client",
    description:
      "An exception's `.stack` property is written into an HTTP response. A stack trace exposes file paths, framework versions, and internal call structure, giving an attacker a precise map of the application.",
    remediation:
      "Return a generic error message and a correlation ID to the client. Log the full stack trace server-side only.",
    cwe: ["CWE-209", "CWE-497"],
    tags: ["error-handling", "info-leak"],
    languages: JS_TS,
    regex: /\bres\.(?:send|write|end|json)\s*\(\s*[^)]*\berr(?:or)?\.stack\b/,
  },
  {
    rule: "exception-message-in-response",
    severity: "high",
    title: "Raw exception message returned to the client",
    description:
      "An exception's `.message` is sent in the response body. Database driver and library error strings often disclose query fragments, table names, and internal paths.",
    remediation:
      "Map errors to safe, generic client messages. Send the detailed message only to the server log.",
    cwe: ["CWE-209"],
    tags: ["error-handling", "info-leak"],
    languages: JS_TS,
    regex: /\bres\.(?:send|write|end|json)\s*\(\s*[^)]*\berr(?:or)?\.message\b/,
  },
  {
    rule: "print-stack-trace",
    severity: "medium",
    title: "`printStackTrace()` writes a stack trace to an output stream",
    description:
      "`Throwable.printStackTrace()` dumps the full stack trace, by default to `System.err`. If that stream is reachable by clients, or if the trace is later surfaced, it leaks internal structure.",
    remediation:
      "Use a logging framework with controlled appenders. Never include the trace in a response sent to the client.",
    cwe: ["CWE-209"],
    tags: ["error-handling", "info-leak"],
    languages: JAVA,
    regex: /\.printStackTrace\s*\(/,
  },
  {
    rule: "traceback-in-response",
    severity: "high",
    title: "Python traceback returned to the client",
    description:
      "`traceback.format_exc()` / `str(e)` is placed into an HTTP response. The traceback exposes source paths, local variables in some frameworks, and the application's internal control flow.",
    remediation:
      "Return a generic error response. Log the traceback server-side with the standard `logging` module, and disable framework debug pages in production.",
    cwe: ["CWE-209"],
    tags: ["error-handling", "info-leak"],
    languages: PY,
    regex:
      /\b(?:return|response|jsonify|abort|HttpResponse(?:ServerError)?)\b[^\n]*\b(?:traceback\.format_exc|str\s*\(\s*e\s*\))/,
  },
  {
    rule: "swallowed-exception-empty-catch",
    severity: "low",
    title: "Empty catch block swallows the error",
    description:
      "A `catch` block with no body discards the exception. The failure becomes invisible, masking bugs and security-relevant errors and leaving the program running on bad state.",
    remediation:
      "At minimum, log the caught error. If the error is truly recoverable, add a comment explaining why it is safe to ignore.",
    cwe: ["CWE-390", "CWE-391"],
    tags: ["error-handling", "swallowed-error"],
    languages: new Set(["java", "javascript", "typescript", "cpp"]),
    regex: /\bcatch\s*(?:\([^)]*\))?\s*\{\s*\}/,
  },
  {
    rule: "swallowed-exception-pass",
    severity: "low",
    title: "`except` block silently passes",
    description:
      "An `except: pass` (especially a bare `except`) discards every error, including `KeyboardInterrupt`-style control signals and genuine bugs, leaving the program in an unknown state.",
    remediation:
      "Catch a specific exception type and handle it — log it, retry, or re-raise. Never write a bare `except: pass`.",
    cwe: ["CWE-390", "CWE-391"],
    tags: ["error-handling", "swallowed-error"],
    languages: PY,
    regex: /\bexcept\b[^\n:]*:\s*pass\b/,
  },
  {
    rule: "broad-exception-catch",
    severity: "low",
    title: "Overly broad exception handler",
    description:
      "Catching `Exception` / `Throwable` / `Error` (or a bare `except`) hides unexpected failures and can mask security errors. The handler runs for conditions it was never designed to recover from.",
    remediation:
      "Catch the narrowest exception type that the block can actually handle. Let unexpected errors propagate to a single top-level handler.",
    cwe: ["CWE-396"],
    tags: ["error-handling", "broad-catch"],
    languages: new Set(["java", "python"]),
    regex: /\bcatch\s*\(\s*(?:java\.lang\.)?(?:Exception|Throwable|Error)\b|\bexcept\s*:/,
  },
  {
    rule: "debug-mode-enabled",
    severity: "medium",
    title: "Debug mode appears to be enabled",
    description:
      "A debug flag is turned on. Framework debug modes serve interactive tracebacks, disable security checks, and can expose an interactive console — all unacceptable outside development.",
    remediation:
      "Drive the debug setting from an environment variable that defaults to off, and ensure it is disabled in every production deployment.",
    cwe: ["CWE-489", "CWE-215"],
    tags: ["error-handling", "misconfiguration"],
    languages: ALL_LANGS,
    regex:
      /\b(?:app\.debug\s*=\s*True|app\.debug\s*=\s*true|DEBUG\s*=\s*True|debug\s*[:=]\s*true|app\.run\s*\([^)]*debug\s*=\s*True)/,
  },
];

/** Strip a trailing line comment so detectors do not match commented code. */
function stripLineComment(line: string, language: ErrorHandlingLanguage): string {
  if (language === "python") {
    const h = line.indexOf("#");
    return h >= 0 ? line.slice(0, h) : line;
  }
  const s = line.indexOf("//");
  return s >= 0 ? line.slice(0, s) : line;
}

export function checkErrorHandling(input: ErrorHandlingInput): readonly Finding[] {
  const { source, language } = input;
  const filename = input.filename;
  const findings: Finding[] = [];
  const lines = source.split(/\r?\n/);

  for (let idx = 0; idx < lines.length; idx++) {
    const raw = lines[idx] ?? "";
    const line = stripLineComment(raw, language);
    if (line.trim() === "") continue;
    for (const det of DETECTORS) {
      if (!det.languages.has(language)) continue;
      const m = det.regex.exec(line);
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
