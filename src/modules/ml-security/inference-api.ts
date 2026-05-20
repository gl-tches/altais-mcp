// Inference-API auditor (altais_audit_inference_api).
//
// Checks a model-serving API for the controls that defend against model
// extraction / theft (OWASP ML05), model inversion (ML03), membership
// inference (ML04), and adversarial evasion (ML01): rate limiting,
// authentication, restraint about confidence scores / logits, input
// validation, and abuse monitoring.

import type { Finding } from "../../core/types.js";
import { buildMlSecurityFinding, scanWithPatterns } from "./finding.js";
import type { SourcePattern } from "./finding.js";

export interface InferenceApiConfig {
  /** Whether the prediction endpoint is rate limited / quota'd per caller. */
  readonly rate_limited?: boolean;
  /** Whether callers must authenticate. */
  readonly authentication?: boolean;
  /** Whether responses include per-class confidence / probability scores. */
  readonly returns_confidence_scores?: boolean;
  /** Whether responses include raw logits. */
  readonly returns_logits?: boolean;
  /** Whether inference inputs are validated / bounded. */
  readonly input_validation?: boolean;
  /** Whether a batch / bulk prediction endpoint is exposed. */
  readonly batch_endpoint?: boolean;
  /** Whether the API has abuse / anomaly monitoring. */
  readonly monitoring?: boolean;
  /** Whether queries are logged for forensic analysis. */
  readonly query_logging?: boolean;
}

export interface InferenceApiInput {
  readonly source?: string;
  readonly config?: InferenceApiConfig;
  readonly filename?: string;
}

const REFS = [
  "https://owasp.org/www-project-machine-learning-security-top-10/",
  "https://owasp.org/www-project-machine-learning-security-top-10/docs/ML05_2023-Model_Theft",
  "https://cwe.mitre.org/data/definitions/770.html",
];

const SOURCE_PATTERNS: readonly SourcePattern[] = [
  {
    rule: "inference-api-returns-logits-source",
    regex: /\b(?:return_dict\s*=\s*True[^)]*logits|["'`]logits["'`]\s*:|\.logits\b)/,
    severity: "medium",
    title: "Inference response appears to expose raw logits",
    description:
      "Returning raw logits hands an attacker the model's full pre-softmax output. This dramatically accelerates model-extraction and model-inversion attacks compared with a top-1 label alone.",
    remediation:
      "Return only the final label (and at most a coarse-grained confidence band). Never expose logits or full probability vectors on a public endpoint.",
    cwe: ["CWE-200"],
    tags: ["model-extraction"],
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

export function auditInferenceApi(input: InferenceApiInput): readonly Finding[] {
  const findings: Finding[] = [];

  if (input.source !== undefined) {
    findings.push(...scanWithPatterns(input.source, SOURCE_PATTERNS, REFS, input.filename));
  }

  const c = input.config;
  if (c !== undefined) {
    if (c.rate_limited === false) {
      findings.push(
        mk(
          "inference-api-no-rate-limiting",
          "high",
          "Inference endpoint has no rate limiting",
          "Without per-caller rate limits an attacker can issue unlimited prediction queries and reconstruct a near-equivalent surrogate model (model extraction / theft — OWASP ML05). Unbounded querying is also a cost and availability risk (CWE-770).",
          "Enforce per-API-key rate limits and quotas; throttle or block callers whose query volume or input diversity matches an extraction pattern.",
          ["CWE-770"],
          "rate_limited=false",
          input.filename,
          ["model-extraction"],
        ),
      );
    }

    if (c.authentication === false) {
      findings.push(
        mk(
          "inference-api-no-authentication",
          "high",
          "Inference endpoint requires no authentication",
          "An unauthenticated prediction endpoint lets anyone query the model anonymously, removing all accountability and the ability to rate-limit or attribute extraction attacks (CWE-306).",
          "Require authentication (API keys or OAuth) on every prediction route and attribute every request to an identity for quota enforcement and abuse tracing.",
          ["CWE-306"],
          "authentication=false",
          input.filename,
          ["access-control"],
        ),
      );
    }

    if (c.returns_logits === true) {
      findings.push(
        mk(
          "inference-api-exposes-logits",
          "high",
          "Inference responses expose raw logits",
          "Raw logits reveal the model's full pre-softmax decision surface, which makes model extraction and model inversion (recovering training data) markedly easier (OWASP ML03 / ML05).",
          "Return only the predicted label, optionally with a coarse confidence band. Strip logits and full probability vectors from API responses.",
          ["CWE-200"],
          "returns_logits=true",
          input.filename,
          ["model-extraction", "model-inversion"],
        ),
      );
    }

    if (c.returns_confidence_scores === true) {
      findings.push(
        mk(
          "inference-api-exposes-confidence-scores",
          "medium",
          "Inference responses expose precise confidence scores",
          "Precise per-class probabilities give an attacker a strong training signal for surrogate models and enable membership-inference attacks that test whether a specific record was in the training set (OWASP ML04 / ML05).",
          "Return only the top label, or quantize confidence into a few coarse buckets. Avoid returning full-precision probability vectors on public endpoints.",
          ["CWE-200"],
          "returns_confidence_scores=true",
          input.filename,
          ["membership-inference", "model-extraction"],
        ),
      );
    }

    if (c.input_validation === false) {
      findings.push(
        mk(
          "inference-api-no-input-validation",
          "medium",
          "Inference inputs are not validated",
          "Unvalidated inputs let an attacker submit adversarial or out-of-distribution examples crafted to evade the model (OWASP ML01 Input Manipulation). Malformed payloads can also crash the serving process.",
          "Validate input shape, type, and value ranges; reject out-of-distribution inputs and consider adversarial-input detection for high-risk models.",
          ["CWE-20"],
          "input_validation=false",
          input.filename,
          ["adversarial-evasion"],
        ),
      );
    }

    if (c.monitoring === false) {
      findings.push(
        mk(
          "inference-api-no-abuse-monitoring",
          "medium",
          "Inference API has no abuse / anomaly monitoring",
          "Without monitoring, an extraction or evasion campaign — characterized by high query volume or unusual input distributions — runs undetected (OWASP ML05).",
          "Monitor per-caller query volume, input diversity, and confidence distributions; alert on patterns consistent with extraction or adversarial probing.",
          ["CWE-778"],
          "monitoring=false",
          input.filename,
          ["observability"],
        ),
      );
    }

    if (c.batch_endpoint === true && c.rate_limited !== true) {
      findings.push(
        mk(
          "inference-api-unthrottled-batch",
          "medium",
          "Batch inference endpoint is exposed without rate limiting",
          "A batch / bulk prediction endpoint amplifies model-extraction throughput: one request yields many predictions. Without throttling it is an efficient extraction channel (OWASP ML05).",
          "Apply per-call and per-caller limits on batch size and batch frequency, and monitor batch endpoints for extraction patterns.",
          ["CWE-770"],
          "batch_endpoint=true, rate_limited=false",
          input.filename,
          ["model-extraction"],
        ),
      );
    }

    if (c.query_logging === false) {
      findings.push(
        mk(
          "inference-api-no-query-logging",
          "low",
          "Inference queries are not logged",
          "Without query logging there is no forensic trail to reconstruct an extraction or evasion attack after the fact.",
          "Log queries (or privacy-preserving summaries) with caller identity and timestamps, retained long enough to investigate abuse.",
          ["CWE-778"],
          "query_logging=false",
          input.filename,
          ["observability"],
        ),
      );
    }
  }

  return findings;
}
