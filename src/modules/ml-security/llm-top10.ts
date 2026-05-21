// OWASP LLM Top 10 (2025) coverage checker (altais_check_llm_top10).
//
// Walks the ten OWASP Top 10 for LLM Applications categories (LLM01-LLM10)
// and, for each, reports whether the supplied controls cover it. Source
// patterns supply extra evidence for prompt-injection and output-handling
// gaps. Every category needing review yields a Finding.

import { scanToken } from "../../core/scan-patterns.js";
import type { Finding } from "../../core/types.js";
import { buildMlSecurityFinding } from "./finding.js";
import { auditOutputHandling } from "./output-handling.js";
import { auditPromptInjection } from "./prompt-injection.js";

// Dynamic code-execution API name, loaded from data/scan-patterns.json.
const EVAL = scanToken("js-dynamic-code");

export interface LlmTop10Config {
  /** Whether untrusted input is separated from system instructions (LLM01). */
  readonly prompt_injection_defenses?: boolean;
  /** Whether model output is filtered for sensitive data before return (LLM02). */
  readonly output_pii_filtering?: boolean;
  /** Whether models / plugins / datasets are supply-chain verified (LLM03). */
  readonly supply_chain_verified?: boolean;
  /** Whether training / fine-tuning data is validated (LLM04). */
  readonly data_validation?: boolean;
  /** Whether LLM output is sanitized before downstream use (LLM05). */
  readonly output_sanitization?: boolean;
  /** Whether agent tool permissions are minimized and gated (LLM06). */
  readonly agency_limited?: boolean;
  /** Whether the system prompt is protected from leakage (LLM07). */
  readonly system_prompt_protected?: boolean;
  /** Whether the vector store / RAG inputs are access-controlled (LLM08). */
  readonly vector_store_secured?: boolean;
  /** Whether output is grounded / fact-checked to limit misinformation (LLM09). */
  readonly grounding_enabled?: boolean;
  /** Whether token / cost / request consumption is bounded (LLM10). */
  readonly consumption_limited?: boolean;
}

export interface LlmTop10Input {
  readonly source?: string;
  readonly config?: LlmTop10Config;
  readonly filename?: string;
}

const REFS = [
  "https://genai.owasp.org/llm-top-10/",
  "https://owasp.org/www-project-top-10-for-large-language-model-applications/",
];

export type CoverageStatus = "covered" | "needs_review";

export interface LlmTop10CategoryResult {
  readonly id: string;
  readonly name: string;
  readonly status: CoverageStatus;
  readonly detection_hint: string;
}

interface CategorySpec {
  readonly id: string;
  readonly rule: string;
  readonly name: string;
  readonly severity: Finding["severity"];
  readonly cwe: readonly string[];
  readonly detection_hint: string;
  readonly description: string;
  readonly remediation: string;
  readonly covered: (c: LlmTop10Config) => boolean | undefined;
}

const CATEGORIES: readonly CategorySpec[] = [
  {
    id: "LLM01",
    rule: "llm01-prompt-injection",
    name: "Prompt Injection",
    severity: "high",
    cwe: ["CWE-1427"],
    detection_hint:
      "Look for untrusted input concatenated into prompts and missing instruction / data separation.",
    description:
      "Attacker-controlled text overrides the model's instructions. Direct and indirect (retrieved-content) injection both apply.",
    remediation:
      "Separate system instructions from user data, constrain model privileges, filter inputs, and validate outputs.",
    covered: (c) => c.prompt_injection_defenses,
  },
  {
    id: "LLM02",
    rule: "llm02-sensitive-information-disclosure",
    name: "Sensitive Information Disclosure",
    severity: "high",
    cwe: ["CWE-200"],
    detection_hint:
      "Check whether model output is scanned for PII / secrets before being returned.",
    description:
      "The model reveals secrets, PII, or proprietary data from its context, training data, or other users' sessions.",
    remediation:
      "Apply output PII / secret filtering, scope context to the current user, and minimize sensitive data in prompts and training data.",
    covered: (c) => c.output_pii_filtering,
  },
  {
    id: "LLM03",
    rule: "llm03-supply-chain",
    name: "Supply Chain",
    severity: "high",
    cwe: ["CWE-1357"],
    detection_hint:
      "Check that base models, adapters, plugins, and datasets are signed, pinned, and vetted.",
    description:
      "A compromised model, LoRA adapter, plugin, or dataset introduces vulnerabilities or backdoors into the application.",
    remediation:
      "Verify and pin model / plugin / dataset provenance, sign artifacts, and scan third-party components.",
    covered: (c) => c.supply_chain_verified,
  },
  {
    id: "LLM04",
    rule: "llm04-data-and-model-poisoning",
    name: "Data and Model Poisoning",
    severity: "high",
    cwe: ["CWE-1395"],
    detection_hint:
      "Check whether training / fine-tuning / RAG data is validated and provenance-tracked.",
    description:
      "Tampered training, fine-tuning, or embedding data installs backdoors or biases into the model's behavior.",
    remediation:
      "Validate and track provenance for all training and RAG data, and detect anomalous samples before ingestion.",
    covered: (c) => c.data_validation,
  },
  {
    id: "LLM05",
    rule: "llm05-improper-output-handling",
    name: "Improper Output Handling",
    severity: "high",
    cwe: ["CWE-79"],
    detection_hint: `Look for model output passed unsanitized into HTML, SQL, shells, ${EVAL}, or file paths.`,
    description:
      "LLM output is treated as trusted and flows into downstream interpreters, causing XSS, SQLi, SSRF, or RCE.",
    remediation: `Treat LLM output as untrusted: context-encode for HTML, parameterize SQL, never pass output to a shell or ${EVAL}.`,
    covered: (c) => c.output_sanitization,
  },
  {
    id: "LLM06",
    rule: "llm06-excessive-agency",
    name: "Excessive Agency",
    severity: "high",
    cwe: ["CWE-269"],
    detection_hint:
      "Check the agent's tool count, permission scopes, and human-approval gates on high-impact actions.",
    description:
      "An LLM agent has excessive functionality, permissions, or autonomy, so an injection or error causes damaging actions.",
    remediation:
      "Minimize tools and scopes, require human approval for high-impact actions, and avoid full autonomy for risky operations.",
    covered: (c) => c.agency_limited,
  },
  {
    id: "LLM07",
    rule: "llm07-system-prompt-leakage",
    name: "System Prompt Leakage",
    severity: "medium",
    cwe: ["CWE-200"],
    detection_hint:
      "Check whether secrets or access-control logic live in the system prompt and can be extracted.",
    description:
      "The system prompt is leaked to the user, exposing instructions, secrets, or guardrail logic embedded in it.",
    remediation:
      "Never put secrets or sole access-control logic in the system prompt; enforce controls outside the model.",
    covered: (c) => c.system_prompt_protected,
  },
  {
    id: "LLM08",
    rule: "llm08-vector-and-embedding-weaknesses",
    name: "Vector and Embedding Weaknesses",
    severity: "high",
    cwe: ["CWE-285"],
    detection_hint:
      "Check whether RAG vector stores enforce per-user access control and validate ingested content.",
    description:
      "Weaknesses in how embeddings / vector stores are generated, stored, or retrieved enable data leakage or indirect injection.",
    remediation:
      "Enforce tenant / user access control on vector stores, validate ingested documents, and isolate per-customer indexes.",
    covered: (c) => c.vector_store_secured,
  },
  {
    id: "LLM09",
    rule: "llm09-misinformation",
    name: "Misinformation",
    severity: "medium",
    cwe: ["CWE-345"],
    detection_hint:
      "Check whether output is grounded in retrieved sources and high-stakes claims are verified.",
    description:
      "The model produces confident but false output (hallucination) that users over-rely on for important decisions.",
    remediation:
      "Ground responses with retrieval, cite sources, verify high-stakes output, and communicate confidence to users.",
    covered: (c) => c.grounding_enabled,
  },
  {
    id: "LLM10",
    rule: "llm10-unbounded-consumption",
    name: "Unbounded Consumption",
    severity: "medium",
    cwe: ["CWE-770"],
    detection_hint: "Check for rate limits and token / cost caps on model calls.",
    description:
      "Unrestricted inference (token, request, or cost volume) enables denial-of-service, denial-of-wallet, and model extraction.",
    remediation:
      "Enforce per-user rate limits, token / output caps, and cost budgets; monitor for abusive usage.",
    covered: (c) => c.consumption_limited,
  },
];

export interface LlmTop10Result {
  readonly categories: readonly LlmTop10CategoryResult[];
  readonly findings: readonly Finding[];
}

export function checkLlmTop10(input: LlmTop10Input): LlmTop10Result {
  const c = input.config ?? {};
  const src = input.source;
  const categories: LlmTop10CategoryResult[] = [];
  const findings: Finding[] = [];

  // Source evidence can downgrade an unset/covered verdict to needs_review.
  // The dedicated auditors carry the precise patterns; reuse their verdicts.
  const promptInjectionSeen = src !== undefined && auditPromptInjection({ source: src }).length > 0;
  const outputSinkSeen = src !== undefined && auditOutputHandling({ source: src }).length > 0;

  for (const spec of CATEGORIES) {
    let covered = spec.covered(c) === true;
    if (spec.id === "LLM01" && promptInjectionSeen) {
      covered = false;
    }
    if (spec.id === "LLM05" && outputSinkSeen) {
      covered = false;
    }
    const status: CoverageStatus = covered ? "covered" : "needs_review";
    categories.push({
      id: spec.id,
      name: spec.name,
      status,
      detection_hint: spec.detection_hint,
    });
    if (!covered) {
      findings.push(
        buildMlSecurityFinding(
          {
            rule: spec.rule,
            severity: spec.severity,
            title: `${spec.id} ${spec.name}: coverage not confirmed`,
            description: `${spec.description} Detection hint: ${spec.detection_hint}`,
            remediation: spec.remediation,
            cwe: spec.cwe,
            references: REFS,
            evidence: `${spec.id} status=needs_review`,
            tags: ["owasp-llm", spec.id.toLowerCase()],
          },
          input.filename,
        ),
      );
    }
  }

  return { categories, findings };
}
