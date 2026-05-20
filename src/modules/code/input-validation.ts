// Input-validation reviewer (altais_check_input_validation).
//
// Verifies that request / external input is validated before use. Detects
// untrusted input consumed without a recognized validator, `parseInt`
// without a radix, and unbounded regular expressions applied to user data.
// The analysis is purely textual.

import type { Finding, Severity } from "../../core/types.js";
import { buildCodeFinding } from "./finding.js";

export type InputValidationLanguage =
  | "c"
  | "cpp"
  | "java"
  | "python"
  | "javascript"
  | "typescript"
  | "go";

export interface InputValidationInput {
  readonly source: string;
  readonly language: InputValidationLanguage;
  readonly filename?: string;
}

const REFS = [
  "https://cwe.mitre.org/data/definitions/20.html",
  "https://owasp.org/www-project-proactive-controls/v3/en/c5-validate-inputs",
  "https://owasp.org/Top10/A03_2021-Injection/",
];

/** Request-input accessors per language, used to detect untrusted sources. */
const REQUEST_INPUT_RE =
  /\b(?:req\.(?:body|query|params|cookies)|request\.(?:form|args|json|values|GET|POST)|os\.Args)\b/;

/** Names of recognized validation libraries / helpers. */
const VALIDATOR_RE =
  /z\.(?:object|string|number|parse|safeParse)|Joi\.|\.validate(?:Async|Sync)?\s*\(|yup\.|express-validator|\bcheck\s*\(|\bbody\s*\(|\bvalidationResult\b|\bpydantic\b|\bBaseModel\b|\.validator\b|class-validator/;

interface LineDetector {
  readonly rule: string;
  readonly severity: Severity;
  readonly title: string;
  readonly description: string;
  readonly remediation: string;
  readonly cwe: readonly string[];
  readonly tags: readonly string[];
  readonly regex: RegExp;
  /** Returns true when `line` should be flagged for this detector. */
  readonly extra?: (line: string) => boolean;
}

const DETECTORS: readonly LineDetector[] = [
  {
    rule: "parseint-missing-radix",
    severity: "low",
    title: "`parseInt` called without an explicit radix",
    description:
      "`parseInt(str)` infers the radix from the string. A leading `0x` triggers hexadecimal parsing and a leading `0` is engine-dependent, so attacker-controlled input can be parsed into an unexpected number.",
    remediation:
      "Always pass the radix explicitly: `parseInt(value, 10)`. For strict numeric parsing prefer `Number(value)` and validate the result.",
    cwe: ["CWE-20", "CWE-704"],
    tags: ["input-validation", "parsing"],
    regex: /\bparseInt\s*\(\s*[^,)]+\)/,
  },
  {
    rule: "unbounded-regex-on-input",
    severity: "medium",
    title: "Regular expression applied to user input without a length bound",
    description:
      "Running a regular expression against unbounded user input risks catastrophic backtracking (ReDoS): a crafted string makes the matcher run for an extremely long time, stalling the process.",
    remediation:
      "Cap the input length before matching, use a linear-time regex engine, or rewrite the pattern to remove nested / overlapping quantifiers.",
    cwe: ["CWE-1333", "CWE-400"],
    tags: ["input-validation", "redos"],
    regex:
      /\b(?:req\.(?:body|query|params)|request\.(?:form|args))[^\n;]*\.(?:match|test|search|exec)\s*\(/,
  },
];

/** Strip a trailing line comment so detectors do not match commented code. */
function stripLineComment(line: string, language: InputValidationLanguage): string {
  if (language === "python") {
    const h = line.indexOf("#");
    return h >= 0 ? line.slice(0, h) : line;
  }
  const s = line.indexOf("//");
  return s >= 0 ? line.slice(0, s) : line;
}

export function checkInputValidation(input: InputValidationInput): readonly Finding[] {
  const { source, language } = input;
  const filename = input.filename;
  const findings: Finding[] = [];
  const lines = source.split(/\r?\n/);

  let usesRequestInput = false;
  let hasValidator = false;
  let firstRequestLine = -1;
  let firstRequestEvidence = "";

  for (let idx = 0; idx < lines.length; idx++) {
    const raw = lines[idx] ?? "";
    const line = stripLineComment(raw, language);
    if (line.trim() === "") continue;

    const reqMatch = REQUEST_INPUT_RE.exec(line);
    if (reqMatch !== null) {
      if (!usesRequestInput) {
        usesRequestInput = true;
        firstRequestLine = idx + 1;
        firstRequestEvidence = line.trim().slice(0, 200);
      }
    }
    if (VALIDATOR_RE.test(line)) hasValidator = true;

    for (const det of DETECTORS) {
      const m = det.regex.exec(line);
      if (m === null) continue;
      if (det.extra !== undefined && !det.extra(line)) continue;
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

  // ── Request input consumed with no recognized validator anywhere ──────
  if (usesRequestInput && !hasValidator) {
    findings.push(
      buildCodeFinding(
        {
          rule: "unvalidated-request-input",
          severity: "high",
          title: "Request input is used without a recognized validation layer",
          description:
            "The code reads request input (body / query / params or process arguments) but no validation library or schema (Zod, Joi, yup, express-validator, pydantic) is present. Unvalidated input feeds directly into application logic, enabling injection, type confusion, and bypass of business rules.",
          remediation:
            "Validate and coerce every external input against an explicit schema at the trust boundary — define allowed types, lengths, ranges, and formats — and reject anything that does not match before the value is used.",
          cwe: ["CWE-20", "CWE-1284"],
          references: REFS,
          evidence: firstRequestEvidence,
          tags: ["input-validation", "missing-validation"],
          ...(firstRequestLine > 0 ? { line: firstRequestLine } : {}),
        },
        filename,
      ),
    );
  }

  return findings;
}
