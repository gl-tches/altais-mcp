// OWASP ML Security Top 10 coverage checker (altais_check_owasp_ml).
//
// Walks the ten OWASP Machine Learning Security categories (ML01-ML10) and,
// for each, reports whether the supplied controls cover it or whether it
// still needs review. Every category needing review yields a Finding with
// detection hints.

import type { Finding } from "../../core/types.js";
import { buildMlSecurityFinding } from "./finding.js";

export interface OwaspMlConfig {
  /** Whether inference inputs are validated against adversarial / OOD examples. */
  readonly input_validation?: boolean;
  /** Whether training data is validated and provenance-tracked (ML02). */
  readonly data_validation?: boolean;
  /** Whether model-inversion defenses (output coarsening, DP) are applied (ML03). */
  readonly inversion_defenses?: boolean;
  /** Whether membership-inference defenses (DP, regularization) are applied (ML04). */
  readonly membership_inference_defenses?: boolean;
  /** Whether model-theft controls (rate limiting, watermarking) exist (ML05). */
  readonly model_theft_controls?: boolean;
  /** Whether the AI supply chain is verified (signing, pinning, scanning) (ML06). */
  readonly supply_chain_verified?: boolean;
  /** Whether transfer-learning / pretrained-model risk is assessed (ML07). */
  readonly transfer_learning_reviewed?: boolean;
  /** Whether model skewing / feedback-loop poisoning is monitored (ML08). */
  readonly skewing_monitored?: boolean;
  /** Whether model output integrity is verified downstream (ML09). */
  readonly output_integrity_verified?: boolean;
  /** Whether the training process itself is access-controlled and audited (ML10). */
  readonly training_access_controlled?: boolean;
}

export interface OwaspMlInput {
  readonly config?: OwaspMlConfig;
  readonly filename?: string;
}

const REFS = ["https://owasp.org/www-project-machine-learning-security-top-10/"];

export type CoverageStatus = "covered" | "needs_review";

export interface OwaspMlCategoryResult {
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
  readonly covered: (c: OwaspMlConfig) => boolean | undefined;
}

const CATEGORIES: readonly CategorySpec[] = [
  {
    id: "ML01",
    rule: "owasp-ml01-input-manipulation",
    name: "Input Manipulation Attack",
    severity: "high",
    cwe: ["CWE-20"],
    detection_hint:
      "Look for unvalidated inference inputs and missing adversarial / out-of-distribution detection.",
    description:
      "Adversarial inputs crafted to evade or mislead the model. Without input validation and adversarial-input detection the model can be fooled at inference time.",
    remediation:
      "Validate input shape and ranges, add adversarial-input detection, and apply adversarial training or input preprocessing for high-risk models.",
    covered: (c) => c.input_validation,
  },
  {
    id: "ML02",
    rule: "owasp-ml02-data-poisoning",
    name: "Data Poisoning Attack",
    severity: "high",
    cwe: ["CWE-1395"],
    detection_hint:
      "Check whether training data is validated and provenance-tracked before training.",
    description:
      "Tampered training data installs backdoors or degrades accuracy. Untrusted, unvalidated data sources are the attack surface.",
    remediation:
      "Validate and outlier-filter training data, track provenance, and source data only from vetted, access-controlled stores.",
    covered: (c) => c.data_validation,
  },
  {
    id: "ML03",
    rule: "owasp-ml03-model-inversion",
    name: "Model Inversion Attack",
    severity: "high",
    cwe: ["CWE-200"],
    detection_hint:
      "Check whether the model returns logits / full probabilities that enable reconstruction of training data.",
    description:
      "An attacker reconstructs sensitive training data by probing the model. Rich output (logits, full probabilities) accelerates this.",
    remediation:
      "Coarsen model output, train with differential privacy, and limit query access to reduce inversion leakage.",
    covered: (c) => c.inversion_defenses,
  },
  {
    id: "ML04",
    rule: "owasp-ml04-membership-inference",
    name: "Membership Inference Attack",
    severity: "medium",
    cwe: ["CWE-200"],
    detection_hint:
      "Check for differential-privacy training or regularization that limits memorization of individual records.",
    description:
      "An attacker determines whether a specific record was in the training set, a privacy breach for sensitive datasets.",
    remediation:
      "Train with differential privacy, regularize to reduce overfitting, and coarsen confidence outputs.",
    covered: (c) => c.membership_inference_defenses,
  },
  {
    id: "ML05",
    rule: "owasp-ml05-model-theft",
    name: "Model Theft",
    severity: "high",
    cwe: ["CWE-770"],
    detection_hint:
      "Check for rate limiting, query monitoring, and watermarking on the inference API.",
    description:
      "An attacker reconstructs an equivalent model by querying the API at scale. Unbounded query access enables extraction.",
    remediation:
      "Rate-limit and authenticate the inference API, monitor for extraction patterns, and watermark the model.",
    covered: (c) => c.model_theft_controls,
  },
  {
    id: "ML06",
    rule: "owasp-ml06-ai-supply-chain",
    name: "AI Supply Chain Attacks",
    severity: "high",
    cwe: ["CWE-1357"],
    detection_hint:
      "Check that models, datasets, and dependencies are signed, pinned, and scanned.",
    description:
      "A compromised third-party model, dataset, or package enters the pipeline. Unverified supply-chain artifacts carry backdoors.",
    remediation:
      "Sign and verify model artifacts, pin immutable revisions and dependency hashes, and scan artifacts before use.",
    covered: (c) => c.supply_chain_verified,
  },
  {
    id: "ML07",
    rule: "owasp-ml07-transfer-learning-attack",
    name: "Transfer Learning Attack",
    severity: "medium",
    cwe: ["CWE-829"],
    detection_hint:
      "Check whether pretrained base models are vetted before fine-tuning on top of them.",
    description:
      "A malicious pretrained model carries a backdoor that survives fine-tuning, compromising every derived model.",
    remediation:
      "Use pretrained models only from trusted publishers, evaluate them for backdoors, and pin a verified revision before fine-tuning.",
    covered: (c) => c.transfer_learning_reviewed,
  },
  {
    id: "ML08",
    rule: "owasp-ml08-model-skewing",
    name: "Model Skewing",
    severity: "medium",
    cwe: ["CWE-1395"],
    detection_hint:
      "Check whether feedback / online-learning loops are monitored for distribution drift and manipulation.",
    description:
      "An attacker feeds biased data through a feedback or online-learning loop to skew model behavior over time.",
    remediation:
      "Monitor feedback-loop input distributions, validate online-learning data, and gate retraining on anomaly checks.",
    covered: (c) => c.skewing_monitored,
  },
  {
    id: "ML09",
    rule: "owasp-ml09-output-integrity",
    name: "Output Integrity Attack",
    severity: "high",
    cwe: ["CWE-345"],
    detection_hint:
      "Check whether model outputs are verified / signed before downstream systems act on them.",
    description:
      "An attacker tampers with model output in transit so downstream systems act on a falsified prediction.",
    remediation:
      "Authenticate and integrity-protect the inference channel, and verify output provenance before acting on predictions.",
    covered: (c) => c.output_integrity_verified,
  },
  {
    id: "ML10",
    rule: "owasp-ml10-model-poisoning",
    name: "Model Poisoning",
    severity: "high",
    cwe: ["CWE-913"],
    detection_hint:
      "Check whether the training process and model parameters are access-controlled and audited.",
    description:
      "An attacker with access to the training process or model parameters directly alters model weights to embed malicious behavior.",
    remediation:
      "Access-control and audit the training environment and model registry; verify model parameters with signed checkpoints.",
    covered: (c) => c.training_access_controlled,
  },
];

export interface OwaspMlResult {
  readonly categories: readonly OwaspMlCategoryResult[];
  readonly findings: readonly Finding[];
}

export function checkOwaspMl(input: OwaspMlInput): OwaspMlResult {
  const c = input.config ?? {};
  const categories: OwaspMlCategoryResult[] = [];
  const findings: Finding[] = [];

  for (const spec of CATEGORIES) {
    const covered = spec.covered(c) === true;
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
            tags: ["owasp-ml", spec.id.toLowerCase()],
          },
          input.filename,
        ),
      );
    }
  }

  return { categories, findings };
}
