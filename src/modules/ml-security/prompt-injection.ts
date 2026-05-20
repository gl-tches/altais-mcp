// Prompt-injection auditor (altais_audit_prompt_injection).
//
// Analyzes how an LLM application builds prompts and consumes tool /
// retrieval output, flagging the patterns that enable direct and indirect
// prompt injection (OWASP LLM01, CWE-1427): untrusted input concatenated
// into a prompt string, no separation of instructions from data, and
// unsanitized tool / RAG output fed back to the model.

import type { Finding } from "../../core/types.js";
import { buildMlSecurityFinding, scanWithPatterns } from "./finding.js";
import type { SourcePattern } from "./finding.js";

export interface PromptInjectionConfig {
  /** Whether system instructions are kept separate from user data. */
  readonly instruction_data_separation?: boolean;
  /** Whether user input is filtered before reaching the model. */
  readonly input_filtering?: boolean;
  /** Whether model output is validated before being acted on. */
  readonly output_validation?: boolean;
  /** Whether tool / retrieval output is sanitized before being fed back. */
  readonly tool_output_sanitized?: boolean;
}

export interface PromptInjectionInput {
  readonly source?: string;
  readonly config?: PromptInjectionConfig;
  readonly filename?: string;
}

const REFS = [
  "https://genai.owasp.org/llmrisk/llm01-prompt-injection/",
  "https://owasp.org/www-project-top-10-for-large-language-model-applications/",
  "https://cwe.mitre.org/data/definitions/1427.html",
];

const SOURCE_PATTERNS: readonly SourcePattern[] = [
  {
    rule: "prompt-injection-fstring-interpolation",
    regex:
      /f["'`][^"'`\n]*\{[^}\n]*\b(?:user|input|request|query|message|user_input|prompt_input|content)\b[^}\n]*\}/i,
    severity: "high",
    title: "Untrusted input interpolated into a prompt f-string",
    description:
      "An f-string builds a prompt directly from a user / request variable. The untrusted text is concatenated into the instruction context with no boundary, so it can override the model's instructions (OWASP LLM01, CWE-1427).",
    remediation:
      "Pass user input as a clearly delimited, separate message (e.g. a `user` role turn), never interpolated into the system instruction string. Add input filtering and output validation.",
    cwe: ["CWE-1427"],
    tags: ["prompt-injection"],
  },
  {
    rule: "prompt-injection-template-literal",
    regex:
      /`[^`\n]*\$\{[^}\n]*\b(?:user|input|request|query|message|userInput|promptInput|content)\b[^}\n]*\}[^`\n]*`/i,
    severity: "high",
    title: "Untrusted input interpolated into a prompt template literal",
    description:
      "A template literal builds a prompt from a user / request variable. Attacker-controlled text lands inside the instruction string with no separation, enabling prompt injection (OWASP LLM01, CWE-1427).",
    remediation:
      "Keep system instructions and user data in separate message turns; do not interpolate user input into the instruction template. Filter input and validate output.",
    cwe: ["CWE-1427"],
    tags: ["prompt-injection"],
  },
  {
    rule: "prompt-injection-string-concat",
    regex:
      /\b(?:system_?prompt|prompt|instructions?|template)[\w.]*\s*\+\s*\w*(?:user|input|request|query|message)\w*/i,
    severity: "high",
    title: "Untrusted input concatenated onto a prompt with `+`",
    description:
      "String concatenation appends a user / request variable directly onto a prompt or instruction string. There is no trust boundary between the model's instructions and the attacker-controlled text (OWASP LLM01, CWE-1427).",
    remediation:
      "Do not concatenate user input into the instruction string. Use distinct message roles for instructions vs. user data, and apply input filtering.",
    cwe: ["CWE-1427"],
    tags: ["prompt-injection"],
  },
  {
    rule: "prompt-injection-unsanitized-tool-output",
    regex:
      /\b(?:tool_?(?:result|output|response)|retriev\w*|search_?results?|rag_?(?:context|result)|document)[\w.]*\s*(?:\+|,)\s*\w*(?:prompt|messages?|context)\w*/i,
    severity: "high",
    title: "Tool / retrieval output fed back to the model without sanitization",
    description:
      "Output from a tool call or retrieval step is concatenated into the prompt or message list with no sanitization. Retrieved content is attacker-influenceable and enables indirect prompt injection (OWASP LLM01).",
    remediation:
      "Treat tool and retrieval output as untrusted: place it in a clearly delimited data block, strip instruction-like content, and never let it occupy the system-instruction role.",
    cwe: ["CWE-1427"],
    tags: ["prompt-injection", "indirect-injection"],
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

export function auditPromptInjection(input: PromptInjectionInput): readonly Finding[] {
  const findings: Finding[] = [];

  if (input.source !== undefined) {
    findings.push(...scanWithPatterns(input.source, SOURCE_PATTERNS, REFS, input.filename));
  }

  const c = input.config;
  if (c !== undefined) {
    if (c.instruction_data_separation === false) {
      findings.push(
        mk(
          "prompt-injection-no-instruction-separation",
          "high",
          "System instructions are not separated from user data",
          "When instructions and untrusted input share the same context with no boundary, the model cannot tell which text it must obey. This is the root cause of prompt injection (OWASP LLM01, CWE-1427).",
          "Place system instructions in a dedicated system message and user input in a separate user turn; delimit any embedded data and instruct the model to treat it as data only.",
          ["CWE-1427"],
          "instruction_data_separation=false",
          input.filename,
          ["prompt-injection"],
        ),
      );
    }

    if (c.input_filtering === false) {
      findings.push(
        mk(
          "prompt-injection-no-input-filtering",
          "medium",
          "User input is not filtered before reaching the model",
          'Without input filtering, known injection phrasings ("ignore previous instructions", role-play jailbreaks, encoded payloads) reach the model unchecked (OWASP LLM01).',
          "Add an input-filtering / classification layer that detects and blocks injection attempts before the prompt is built.",
          ["CWE-20"],
          "input_filtering=false",
          input.filename,
          ["prompt-injection"],
        ),
      );
    }

    if (c.output_validation === false) {
      findings.push(
        mk(
          "prompt-injection-no-output-validation",
          "medium",
          "Model output is not validated before it is acted on",
          "Even with input controls, a successful injection manifests in the output. Without output validation a hijacked response is consumed as if trusted (OWASP LLM01 / LLM05).",
          "Validate model output against the expected schema and policy before acting on it; reject or quarantine output that violates constraints.",
          ["CWE-20"],
          "output_validation=false",
          input.filename,
          ["prompt-injection"],
        ),
      );
    }

    if (c.tool_output_sanitized === false) {
      findings.push(
        mk(
          "prompt-injection-unsanitized-tool-output-config",
          "high",
          "Tool / retrieval output is not sanitized before being fed back to the model",
          "Content returned by tools or retrieved from documents is attacker-influenceable. Feeding it back to the model unsanitized enables indirect prompt injection (OWASP LLM01).",
          "Sanitize and delimit tool / retrieval output, strip instruction-like content, and keep it out of the system-instruction role.",
          ["CWE-1427"],
          "tool_output_sanitized=false",
          input.filename,
          ["prompt-injection", "indirect-injection"],
        ),
      );
    }
  }

  return findings;
}
