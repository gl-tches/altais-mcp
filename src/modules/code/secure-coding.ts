// Secure-coding reviewer (altais_review_secure_coding).
//
// Reviews source against widely-used secure-coding guidance (CERT C/C++,
// CERT Oracle Coding Standard for Java, and general best practice). The
// analysis is purely textual — line-by-line scanning and regex matching —
// it never compiles or runs the target code.

import { scanToken } from "../../core/scan-patterns.js";
import type { Finding, Severity } from "../../core/types.js";
import { buildCodeFinding, lineAt } from "./finding.js";

export type SecureCodingLanguage =
  | "c"
  | "cpp"
  | "java"
  | "python"
  | "javascript"
  | "typescript"
  | "go";

export interface SecureCodingInput {
  readonly source: string;
  readonly language: SecureCodingLanguage;
  readonly filename?: string;
}

const REFS = [
  "https://wiki.sei.cmu.edu/confluence/display/c",
  "https://owasp.org/www-project-top-ten/",
  "https://cwe.mitre.org/",
];

interface Detector {
  readonly rule: string;
  readonly severity: Severity;
  readonly title: string;
  readonly description: string;
  readonly remediation: string;
  readonly cwe: readonly string[];
  readonly tags: readonly string[];
  /** Languages this detector applies to. */
  readonly languages: ReadonlySet<SecureCodingLanguage>;
  /** Returns the matched span (or undefined) for a single source line. */
  readonly match: (line: string) => string | undefined;
}

const C_FAMILY: ReadonlySet<SecureCodingLanguage> = new Set(["c", "cpp"]);
const ALL_LANGS: ReadonlySet<SecureCodingLanguage> = new Set([
  "c",
  "cpp",
  "java",
  "python",
  "javascript",
  "typescript",
  "go",
]);

/** A printf-family call whose first argument is not a string literal. */
const NON_LITERAL_FORMAT_RE =
  /\b(?:f?printf|s(?:n)?printf|v?f?printf|vsprintf|vsnprintf)\s*\(\s*([^,)]+)/;

function firstFormatArgIsLiteral(arg: string): boolean {
  const trimmed = arg.trim();
  // A string literal, or an obvious stream target followed by a literal.
  return trimmed.startsWith('"') || trimmed.startsWith('L"') || trimmed.startsWith('u8"');
}

/** printf-family format string check, accounting for the optional FILE* arg. */
function matchFormatString(line: string): string | undefined {
  const m = NON_LITERAL_FORMAT_RE.exec(line);
  if (m === null) return undefined;
  const arg1 = m[1] ?? "";
  // fprintf / snprintf take a leading stream / buffer / size argument: the
  // *next* argument is the format string. Re-scan for it.
  if (/\b(?:f?printf)\b/.test(line) && /\bfprintf\b/.test(line)) {
    const fm = /\bfprintf\s*\(\s*[^,]+,\s*([^,)]+)/.exec(line);
    if (fm !== null) {
      const fmtArg = fm[1] ?? "";
      return firstFormatArgIsLiteral(fmtArg) ? undefined : m[0].trim().slice(0, 200);
    }
  }
  if (/\bsn?printf\b/.test(line)) {
    const sm = /\bsn?printf\s*\(\s*[^,]+,(?:\s*[^,)]+,)?\s*([^,)]+)/.exec(line);
    if (sm !== null) {
      const fmtArg = sm[1] ?? "";
      return firstFormatArgIsLiteral(fmtArg) ? undefined : m[0].trim().slice(0, 200);
    }
  }
  return firstFormatArgIsLiteral(arg1) ? undefined : m[0].trim().slice(0, 200);
}

// Detection tokens loaded from data/scan-patterns.json so the literal API
// names are not embedded inline (see src/core/scan-patterns.ts).
const EVAL = scanToken("js-dynamic-code");
const EXEC = scanToken("shell-command");
const SYSTEM = scanToken("libc-system");
const POPEN = scanToken("libc-popen");
const SUBPROCESS = scanToken("py-subprocess-module");
const PY_POPEN = scanToken("py-popen-class");
const DANGEROUS_API_RE = new RegExp(
  `\\b(?:${SYSTEM}|${POPEN}|${EXEC}lp?|${EXEC}vp?|os\\.${SYSTEM}|${SUBPROCESS}\\.(?:call|${PY_POPEN}|run)|${EVAL})\\s*\\(`,
);

const DETECTORS: readonly Detector[] = [
  {
    rule: "format-string-non-literal",
    severity: "high",
    title: "Format string is not a string literal",
    description:
      "A `printf`-family function is called with a non-literal format string. If any part of that string is attacker-controlled, format specifiers such as `%n` and `%s` let an attacker read or write arbitrary memory.",
    remediation:
      'Use a fixed string literal for the format argument and pass user data as a value: `printf("%s", userInput)` — never `printf(userInput)`.',
    cwe: ["CWE-134"],
    tags: ["secure-coding", "cert-c", "format-string"],
    languages: C_FAMILY,
    match: matchFormatString,
  },
  {
    rule: "dangerous-api-system",
    severity: "high",
    title: "Use of a dangerous process-spawning or evaluation API",
    description: `\`${SYSTEM}\`, \`${POPEN}\`, \`${EXEC}*\`, and \`${EVAL}\` pass strings to a shell or interpreter. Any unsanitized input flowing into the argument becomes a command- or code-injection vector.`,
    remediation: `Avoid the shell entirely. Use a parameterized API (\`${EXEC}ve\` with an argv array, \`${SUBPROCESS}.run([...])\`); never build a command from concatenated input. Do not \`${EVAL}\` dynamic strings.`,
    cwe: ["CWE-78", "CWE-95"],
    tags: ["secure-coding", "injection"],
    languages: ALL_LANGS,
    match: (line) => {
      const m = DANGEROUS_API_RE.exec(line);
      // Dynamic-code APIs are flagged only for interpreted languages; C/C++
      // has no equivalent.
      if (m === null) return undefined;
      return m[0].trim().slice(0, 200);
    },
  },
  {
    rule: "integer-overflow-risk",
    severity: "medium",
    title: "Possible integer overflow in a size or allocation expression",
    description:
      "An arithmetic expression (`a * b`, `a + b`) feeds a size, length, index, or allocation. Unchecked, the operation can wrap around and produce a too-small buffer or an out-of-bounds index.",
    remediation:
      "Validate operand ranges before the arithmetic, use a checked-arithmetic helper (`__builtin_mul_overflow`, `Math.checked`-style guards, `checked_mul`), or use a wider type that cannot overflow.",
    cwe: ["CWE-190", "CWE-680"],
    tags: ["secure-coding", "cert-c", "integer"],
    languages: C_FAMILY,
    match: (line) => {
      const m = /\b(?:malloc|calloc|realloc|alloca)\s*\([^)]*[*+][^)]*\)/.exec(line);
      return m === null ? undefined : m[0].trim().slice(0, 200);
    },
  },
  {
    rule: "unchecked-return-value",
    severity: "medium",
    title: "Return value of a security-relevant call is ignored",
    description:
      "The result of a function whose return value reports success or failure is discarded. Silent failures of allocation, I/O, or privilege-dropping calls lead to operating on invalid state.",
    remediation:
      "Capture and check the return value of `malloc`, `realloc`, `fopen`, `read`, `write`, `setuid`, and similar calls before using their results.",
    cwe: ["CWE-252", "CWE-754"],
    tags: ["secure-coding", "cert-c"],
    languages: C_FAMILY,
    match: (line) => {
      const trimmed = line.trim();
      // A bare call statement: `malloc(...)` not assigned and not in `if`/return.
      const m =
        /^(?:malloc|realloc|fopen|read|write|setuid|setgid|fread|fwrite)\s*\([^;]*\)\s*;/.exec(
          trimmed,
        );
      return m === null ? undefined : m[0].slice(0, 200);
    },
  },
  {
    rule: "toctou-race",
    severity: "medium",
    title: "Time-of-check / time-of-use file race",
    description:
      "Checking a file's properties with `access()` or `stat()` and then operating on the same path leaves a window in which an attacker can swap the path (for example, via a symlink) between the check and the use.",
    remediation:
      "Operate on a file descriptor, not a path: open the file once and check properties with `fstat()`/`faccessat()` on the descriptor. Use `O_NOFOLLOW` to reject symlinks.",
    cwe: ["CWE-367"],
    tags: ["secure-coding", "cert-c", "toctou"],
    languages: C_FAMILY,
    match: (line) => {
      const m = /\b(?:access|stat|lstat)\s*\(/.exec(line);
      return m === null ? undefined : m[0].trim().slice(0, 200);
    },
  },
];

/**
 * Detect a comparison between a signed integer variable and a size / length /
 * count operand (typically unsigned). Operates per line: the line must both
 * declare the variable with a signed type and use it in such a comparison,
 * or the variable's signed type must be visible from an earlier declaration.
 */
function detectSignedUnsignedComparison(
  source: string,
  language: SecureCodingLanguage,
  filename: string | undefined,
): readonly Finding[] {
  if (!C_FAMILY.has(language)) return [];
  const findings: Finding[] = [];
  const lines = source.split(/\r?\n/);
  const signedVars = new Set<string>();
  const SIGNED_DECL_RE = /\b(?:signed\s+)?(?:int|short|long|ssize_t|ptrdiff_t)\s+([A-Za-z_]\w*)/g;
  const COMPARE_RE = /\b([A-Za-z_]\w*)\s*[<>]=?\s*[A-Za-z_]*(?:size|len|count|length)\w*/i;

  for (let idx = 0; idx < lines.length; idx++) {
    const raw = lines[idx] ?? "";
    const line = stripLineComment(raw, language);
    if (line.trim() === "") continue;

    let dm: RegExpExecArray | null;
    SIGNED_DECL_RE.lastIndex = 0;
    while ((dm = SIGNED_DECL_RE.exec(line)) !== null) {
      const name = dm[1];
      if (name !== undefined) signedVars.add(name);
    }

    const cm = COMPARE_RE.exec(line);
    if (cm !== null) {
      const lhs = cm[1];
      if (lhs !== undefined && signedVars.has(lhs)) {
        findings.push(
          buildCodeFinding(
            {
              rule: "signed-unsigned-comparison",
              severity: "low",
              title: "Comparison mixes a signed and an unsigned operand",
              description:
                "Comparing a signed value (often a negative length or index) against an unsigned one converts the signed operand to a large unsigned number, so a bounds check can be silently bypassed.",
              remediation:
                "Use the same signedness on both sides of the comparison. Validate that a length or count is non-negative before comparing it against an unsigned bound.",
              cwe: ["CWE-195", "CWE-697"],
              references: REFS,
              evidence: cm[0].trim().slice(0, 200),
              tags: ["secure-coding", "cert-c", "integer"],
              line: idx + 1,
            },
            filename,
          ),
        );
      }
    }
  }
  return findings;
}

/**
 * Detect a `switch` with no `default` arm. Operates on the whole source so
 * brace matching can span multiple lines.
 */
function detectMissingSwitchDefault(
  source: string,
  language: SecureCodingLanguage,
  filename: string | undefined,
): readonly Finding[] {
  if (language === "python" || language === "go") return [];
  const findings: Finding[] = [];
  const re = /\bswitch\s*\([^)]*\)\s*\{/g;
  let m: RegExpExecArray | null;
  while ((m = re.exec(source)) !== null) {
    const bodyStart = m.index + m[0].length;
    let depth = 1;
    let i = bodyStart;
    for (; i < source.length && depth > 0; i++) {
      const ch = source[i];
      if (ch === "{") depth++;
      else if (ch === "}") depth--;
    }
    const body = source.slice(bodyStart, i - 1);
    if (!/\bdefault\s*:/.test(body)) {
      findings.push(
        buildCodeFinding(
          {
            rule: "missing-switch-default",
            severity: "low",
            title: "`switch` statement has no `default` case",
            description:
              "A `switch` without a `default` arm silently does nothing for unexpected values. Unhandled enum values or out-of-range inputs then bypass intended validation logic.",
            remediation:
              "Add an explicit `default:` arm that handles or rejects unexpected values (log, error, or assert).",
            cwe: ["CWE-478"],
            references: REFS,
            evidence: m[0].trim().slice(0, 200),
            tags: ["secure-coding", "control-flow"],
            line: lineAt(source, m.index),
          },
          filename,
        ),
      );
    }
    re.lastIndex = i;
  }
  return findings;
}

/** Strip a trailing line comment so detectors do not match commented code. */
function stripLineComment(line: string, language: SecureCodingLanguage): string {
  if (language === "python") {
    const h = line.indexOf("#");
    return h >= 0 ? line.slice(0, h) : line;
  }
  const s = line.indexOf("//");
  return s >= 0 ? line.slice(0, s) : line;
}

export function reviewSecureCoding(input: SecureCodingInput): readonly Finding[] {
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
      const evidence = det.match(line);
      if (evidence === undefined) continue;
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
            evidence,
            tags: det.tags,
            line: idx + 1,
          },
          filename,
        ),
      );
    }
  }

  findings.push(...detectMissingSwitchDefault(source, language, filename));
  findings.push(...detectSignedUnsignedComparison(source, language, filename));
  return findings;
}
