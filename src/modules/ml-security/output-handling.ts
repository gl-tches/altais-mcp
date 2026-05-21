// LLM output-handling auditor (altais_audit_output_handling).
//
// Verifies that LLM output is sanitized before it reaches a downstream
// interpreter. Maps to OWASP LLM05 Improper Output Handling: model output
// flowing unsanitized into HTML/DOM (XSS), SQL (SQLi), a shell (command
// injection), dynamic code execution (code injection), or a file path
// (traversal).

import { scanToken } from "../../core/scan-patterns.js";
import type { Finding } from "../../core/types.js";
import { buildMlSecurityFinding, scanWithPatterns } from "./finding.js";
import type { SourcePattern } from "./finding.js";

export interface OutputHandlingConfig {
  /** Whether model output is HTML-encoded before rendering. */
  readonly html_encoded?: boolean;
  /** Whether model output that reaches SQL is parameterized. */
  readonly sql_parameterized?: boolean;
  /** Whether model output is kept out of shell / exec calls. */
  readonly shell_safe?: boolean;
  /** Whether model output is validated against a schema before use. */
  readonly schema_validated?: boolean;
  /** Whether model output is treated as trusted when returned to the user. */
  readonly treated_as_trusted?: boolean;
}

export interface OutputHandlingInput {
  readonly source?: string;
  readonly config?: OutputHandlingConfig;
  readonly filename?: string;
}

const REFS = [
  "https://genai.owasp.org/llmrisk/llm05-improper-output-handling/",
  "https://owasp.org/www-project-top-10-for-large-language-model-applications/",
  "https://cwe.mitre.org/data/definitions/79.html",
];

// Detection tokens loaded from data/scan-patterns.json so the literal API
// names are not embedded inline (see src/core/scan-patterns.ts).
const EVAL = scanToken("js-dynamic-code");
const FUNC = scanToken("js-function-constructor");
const EXEC = scanToken("shell-command");
const EXEC_SYNC = scanToken("shell-command-sync");
const SPAWN = scanToken("process-launch");
const SYSTEM = scanToken("libc-system");
const CHILD_PROCESS = scanToken("node-process-module");
const SUBPROCESS = scanToken("py-subprocess-module");
const PY_POPEN = scanToken("py-popen-class");

// A variable holding a model result. Used as the left side of every sink
// pattern so only LLM-derived data flowing into a sink is flagged.
const OUTPUT_VAR =
  "(?:completion|response|llm_?(?:output|response|result|reply)|model_?(?:output|response)|answer|generated_?\\w*|ai_?(?:output|reply|message)|gpt_?\\w*)";

const SOURCE_PATTERNS: readonly SourcePattern[] = [
  {
    rule: "output-handling-into-html",
    regex: new RegExp(
      `(?:\\.innerHTML|\\.outerHTML|insertAdjacentHTML\\s*\\([^)]*|dangerouslySetInnerHTML\\s*[=:][^;]*|document\\.write\\s*\\()[^;\\n]*\\b${OUTPUT_VAR}\\b`,
      "i",
    ),
    severity: "high",
    title: "LLM output written into the DOM without sanitization",
    description:
      "A model-derived value flows into `innerHTML` / `document.write` / `dangerouslySetInnerHTML`. LLM output is untrusted; rendered as HTML it executes attacker-controlled script (XSS, OWASP LLM05, CWE-79).",
    remediation:
      "Insert LLM output as text (`textContent`) or sanitize it with a vetted HTML sanitizer before rendering. Never assign raw model output to an HTML sink.",
    cwe: ["CWE-79"],
    tags: ["output-handling", "xss"],
  },
  {
    rule: "output-handling-into-sql",
    regex: new RegExp(
      `(?:execute|query|raw|exec_?sql|cursor\\.execute)\\s*\\(\\s*(?:f["'\`]|["'\`])[^"'\`\\n]*(?:\\{|\\$\\{|["'\`]\\s*\\+\\s*)[^}\\n]*\\b${OUTPUT_VAR}\\b`,
      "i",
    ),
    severity: "high",
    title: "LLM output interpolated into a SQL query",
    description:
      "A model-derived value is concatenated or interpolated into a SQL string. Untrusted LLM output in a query is a SQL-injection sink (OWASP LLM05, CWE-89).",
    remediation:
      "Use parameterized queries / prepared statements and pass LLM output strictly as a bound parameter, never as query text.",
    cwe: ["CWE-89"],
    tags: ["output-handling", "sql-injection"],
  },
  {
    rule: "output-handling-into-shell",
    regex: new RegExp(
      `(?:os\\.${SYSTEM}|${SUBPROCESS}\\.(?:run|call|${PY_POPEN}|check_output)|${CHILD_PROCESS}\\.(?:${EXEC}|${EXEC_SYNC})|${EXEC}\\s*\\(|${SPAWN}\\s*\\()[^;\\n]*\\b${OUTPUT_VAR}\\b`,
      "i",
    ),
    severity: "critical",
    title: "LLM output passed into a shell / process execution",
    description: `A model-derived value reaches \`os.${SYSTEM}\` / \`${SUBPROCESS}\` / \`${CHILD_PROCESS}.${EXEC}\`. Untrusted LLM output in a shell command is a command-injection sink and yields remote code execution (OWASP LLM05, CWE-78).`,
    remediation: `Never pass LLM output to a shell. If a process must be spawned, use an explicit argv array (\`${EXEC}File\` / \`${SUBPROCESS}.run([...])\`) with a fixed command and validated, whitelisted arguments.`,
    cwe: ["CWE-78"],
    tags: ["output-handling", "command-injection"],
  },
  {
    rule: `output-handling-into-${EVAL}`,
    regex: new RegExp(
      `(?:\\b${EVAL}\\s*\\(|new\\s+${FUNC}\\s*\\(|\\b${EXEC}\\s*\\(|setTimeout\\s*\\(\\s*["'\`])[^;\\n]*\\b${OUTPUT_VAR}\\b`,
      "i",
    ),
    severity: "critical",
    title: `LLM output passed into \`${EVAL}\` / \`${FUNC}\``,
    description: `A model-derived value reaches \`${EVAL}\` / \`new ${FUNC}\` / \`${EXEC}\`. Evaluating untrusted LLM output as code is a direct code-injection sink (OWASP LLM05, CWE-95).`,
    remediation:
      "Never evaluate LLM output as code. Parse it as data (e.g. strict JSON parsing) against a schema and act on the validated structure instead.",
    cwe: ["CWE-95", "CWE-94"],
    tags: ["output-handling", "code-injection"],
  },
  {
    rule: "output-handling-into-file-path",
    regex: new RegExp(
      `(?:open\\s*\\(|readFile(?:Sync)?\\s*\\(|writeFile(?:Sync)?\\s*\\(|fs\\.\\w+\\s*\\(|path\\.join\\s*\\([^)]*)[^;\\n]*\\b${OUTPUT_VAR}\\b`,
      "i",
    ),
    severity: "high",
    title: "LLM output used to build a file system path",
    description:
      "A model-derived value flows into a file open / read / write call. Untrusted LLM output in a path enables directory traversal and arbitrary file access (OWASP LLM05, CWE-22).",
    remediation:
      "Do not build file paths from LLM output. Map model output to a fixed allow-list of paths, and canonicalize with `path.resolve()` and verify containment before any file operation.",
    cwe: ["CWE-22"],
    tags: ["output-handling", "path-traversal"],
  },
];

function mk(
  rule: string,
  severity: Finding["severity"],
  title: string,
  description: string,
  remediation: string,
  cwe: readonly string[],
  evidence: string,
  filename: string | undefined,
  tags: readonly string[],
): Finding {
  return buildMlSecurityFinding(
    { rule, severity, title, description, remediation, cwe, references: REFS, evidence, tags },
    filename,
  );
}

export function auditOutputHandling(input: OutputHandlingInput): readonly Finding[] {
  const findings: Finding[] = [];

  if (input.source !== undefined) {
    findings.push(...scanWithPatterns(input.source, SOURCE_PATTERNS, REFS, input.filename));
  }

  const c = input.config;
  if (c !== undefined) {
    if (c.html_encoded === false) {
      findings.push(
        mk(
          "output-handling-no-html-encoding",
          "high",
          "LLM output is not HTML-encoded before rendering",
          "Rendering LLM output without context-aware encoding lets a model-emitted `<script>` or event handler execute in the user's browser (XSS, OWASP LLM05, CWE-79).",
          "Render LLM output as text or run it through a vetted HTML sanitizer; apply context-aware output encoding everywhere it is displayed.",
          ["CWE-79"],
          "html_encoded=false",
          input.filename,
          ["output-handling", "xss"],
        ),
      );
    }

    if (c.sql_parameterized === false) {
      findings.push(
        mk(
          "output-handling-no-sql-parameterization",
          "high",
          "LLM output reaches SQL without parameterization",
          "When LLM output is concatenated into SQL it is a SQL-injection sink. Model output must be treated as untrusted input (OWASP LLM05, CWE-89).",
          "Use parameterized queries and bind LLM output as a parameter; never interpolate it into the query string.",
          ["CWE-89"],
          "sql_parameterized=false",
          input.filename,
          ["output-handling", "sql-injection"],
        ),
      );
    }

    if (c.shell_safe === false) {
      findings.push(
        mk(
          "output-handling-shell-unsafe",
          "critical",
          "LLM output flows into shell / process execution",
          "Passing LLM output to a shell command is a command-injection sink yielding remote code execution (OWASP LLM05, CWE-78).",
          "Never pass LLM output to a shell. Use an explicit argv array with a fixed command and validated arguments.",
          ["CWE-78"],
          "shell_safe=false",
          input.filename,
          ["output-handling", "command-injection"],
        ),
      );
    }

    if (c.schema_validated === false) {
      findings.push(
        mk(
          "output-handling-no-schema-validation",
          "medium",
          "LLM output is not validated against a schema before use",
          "Without schema validation, malformed or hijacked model output is consumed directly by downstream code, which can crash or be exploited (OWASP LLM05).",
          "Validate LLM output against a strict schema before acting on it; reject or quarantine output that does not conform.",
          ["CWE-20"],
          "schema_validated=false",
          input.filename,
          ["output-handling"],
        ),
      );
    }

    if (c.treated_as_trusted === true) {
      findings.push(
        mk(
          "output-handling-treated-as-trusted",
          "high",
          "LLM output is returned to the user as trusted content",
          "Treating model output as trusted ignores that it can be manipulated by prompt injection or simply hallucinated. Trusted output bypasses every downstream control (OWASP LLM05).",
          "Treat all LLM output as untrusted: sanitize, encode, and validate it before display or use, regardless of how the prompt was constructed.",
          ["CWE-79", "CWE-345"],
          "treated_as_trusted=true",
          input.filename,
          ["output-handling"],
        ),
      );
    }
  }

  return findings;
}
