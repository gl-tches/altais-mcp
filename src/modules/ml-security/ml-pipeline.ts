// ML training-pipeline auditor (altais_audit_ml_pipeline).
//
// Audits a machine-learning training pipeline for the failure modes that
// turn a model into an attack vector: data poisoning from untrusted or
// unvalidated training data, insecure deserialization of model files,
// unsigned models, credentials embedded in notebooks, unpinned
// dependencies, and absent data lineage / provenance.

import type { Finding } from "../../core/types.js";
import { buildMlSecurityFinding, scanWithPatterns } from "./finding.js";
import type { SourcePattern } from "./finding.js";

export interface MlPipelineConfig {
  /** Where the training data comes from, e.g. "internal", "public", "scraped", "unknown". */
  readonly training_data_source?: string;
  /** Whether training data is validated / sanitized before use. */
  readonly data_validation?: boolean;
  /** Whether data provenance is tracked end-to-end. */
  readonly data_provenance_tracked?: boolean;
  /** Serialized model format, e.g. "pickle", "joblib", "safetensors", "onnx". */
  readonly model_format?: string;
  /** Whether the produced model artifact is cryptographically signed. */
  readonly model_signed?: boolean;
  /** Whether build / training dependencies are pinned to exact versions. */
  readonly pinned_dependencies?: boolean;
  /** Whether secrets / credentials appear in notebooks. */
  readonly secrets_in_notebooks?: boolean;
  /** Whether data and model lineage is tracked. */
  readonly lineage_tracked?: boolean;
}

export interface MlPipelineInput {
  readonly source?: string;
  readonly config?: MlPipelineConfig;
  readonly filename?: string;
}

const REFS = [
  "https://owasp.org/www-project-machine-learning-security-top-10/",
  "https://genai.owasp.org/llmrisk/llm042025-data-and-model-poisoning/",
  "https://cwe.mitre.org/data/definitions/502.html",
];

const TRUSTED_SOURCES = new Set(["internal", "first-party", "curated", "vetted", "trusted"]);

const SOURCE_PATTERNS: readonly SourcePattern[] = [
  {
    rule: "ml-pipeline-pickle-load",
    regex: /\b(?:pickle|cPickle|_pickle)\s*\.\s*loads?\s*\(/,
    severity: "high",
    title: "Insecure deserialization via `pickle.load`",
    description:
      "`pickle` executes arbitrary code on load via `__reduce__`. Loading a pickled model or dataset from any source you do not fully control is a remote-code-execution sink — a poisoned checkpoint runs attacker code in the training or inference process.",
    remediation:
      "Use a non-executable format: `safetensors` for weights, or a strict schema for data. If pickle is unavoidable, only load artifacts whose integrity you have verified with a signature or checksum.",
    cwe: ["CWE-502"],
    tags: ["data-poisoning", "deserialization"],
  },
  {
    rule: "ml-pipeline-joblib-load",
    regex: /\bjoblib\s*\.\s*load\s*\(/,
    severity: "high",
    title: "Insecure deserialization via `joblib.load`",
    description:
      "`joblib.load` is pickle-based and executes arbitrary code embedded in the artifact. A malicious scikit-learn / numpy dump runs code in your process on load.",
    remediation:
      "Prefer `safetensors` or ONNX for model exchange. Only `joblib.load` artifacts you produced or whose checksum / signature you have verified.",
    cwe: ["CWE-502"],
    tags: ["data-poisoning", "deserialization"],
  },
  {
    rule: "ml-pipeline-torch-load-unsafe",
    regex: /\btorch\s*\.\s*load\s*\((?![^)]*weights_only\s*=\s*True)[^)]*\)/,
    severity: "high",
    title: "`torch.load` called without `weights_only=True`",
    description:
      "By default `torch.load` unpickles the checkpoint, so a crafted `.pt` / `.pth` file executes arbitrary code on load. This is the canonical PyTorch supply-chain RCE.",
    remediation:
      "Pass `weights_only=True` to `torch.load` (PyTorch 2.6+ makes this the default), or load weights from `safetensors`. Verify checkpoint integrity before loading.",
    cwe: ["CWE-502"],
    tags: ["data-poisoning", "deserialization"],
  },
  {
    rule: "ml-pipeline-remote-data-read",
    regex: /\b(?:pd|pandas)\s*\.\s*read_\w+\s*\(\s*["'`]https?:\/\/[^"'`]+["'`]/,
    severity: "medium",
    title: "Training data loaded directly from a remote URL",
    description:
      "Reading a dataset straight from an `http(s)` URL pulls untrusted, mutable content into the pipeline with no integrity check. A hijacked or tampered source silently poisons the model (CWE-1395 / OWASP ML02).",
    remediation:
      "Download the dataset to a vetted, versioned store, verify a known checksum, and validate the schema and value ranges before training.",
    cwe: ["CWE-1395", "CWE-829"],
    tags: ["data-poisoning"],
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

export function auditMlPipeline(input: MlPipelineInput): readonly Finding[] {
  const findings: Finding[] = [];

  if (input.source !== undefined) {
    findings.push(...scanWithPatterns(input.source, SOURCE_PATTERNS, REFS, input.filename));
  }

  const c = input.config;
  if (c !== undefined) {
    const src = c.training_data_source;
    if (src !== undefined && !TRUSTED_SOURCES.has(src.trim().toLowerCase())) {
      findings.push(
        mk(
          "ml-pipeline-untrusted-training-data",
          "high",
          `Training data comes from an untrusted source: \`${src}\``,
          "Training data from a public, scraped, third-party, or unknown source is attacker-influenceable. Poisoned samples can install backdoors, skew predictions, or degrade accuracy (OWASP ML02 Data Poisoning, CWE-1395).",
          "Source training data from vetted, access-controlled stores; apply outlier / anomaly detection and provenance checks before incorporating any external data.",
          ["CWE-1395"],
          `training_data_source=${src}`,
          input.filename,
          ["data-poisoning"],
        ),
      );
    }

    if (c.data_validation === false) {
      findings.push(
        mk(
          "ml-pipeline-no-data-validation",
          "high",
          "Training data is not validated before use",
          "Without schema, range, and distribution validation, poisoned or malformed samples flow straight into training. Data poisoning attacks rely on exactly this gap (OWASP ML02).",
          "Validate every batch: enforce a schema, bound numeric ranges, detect label-flipping and statistical outliers, and quarantine anomalous data for review.",
          ["CWE-1395", "CWE-20"],
          "data_validation=false",
          input.filename,
          ["data-poisoning"],
        ),
      );
    }

    if (c.data_provenance_tracked === false || c.lineage_tracked === false) {
      findings.push(
        mk(
          "ml-pipeline-no-data-lineage",
          "medium",
          "Data provenance / lineage is not tracked",
          "Without lineage you cannot answer which data trained which model. After a poisoning incident you cannot scope the blast radius or reproduce a clean model.",
          "Track dataset versions, transformations, and model lineage (e.g. with a data-version-control and experiment-tracking tool) so every model is traceable to its exact inputs.",
          ["CWE-778"],
          `data_provenance_tracked=${c.data_provenance_tracked ?? "unset"}, lineage_tracked=${c.lineage_tracked ?? "unset"}`,
          input.filename,
          ["provenance"],
        ),
      );
    }

    const fmt = c.model_format?.trim().toLowerCase();
    if (fmt === "pickle" || fmt === "joblib" || fmt === "pkl" || fmt === "dill") {
      findings.push(
        mk(
          "ml-pipeline-insecure-model-format",
          "high",
          `Model is serialized in an executable format: \`${c.model_format ?? fmt}\``,
          "Pickle-based model formats execute arbitrary code on load. Any consumer of this model artifact is exposed to remote code execution if the file is tampered with (CWE-502).",
          "Serialize models with `safetensors` (weights only) or ONNX. Never distribute pickle artifacts across a trust boundary.",
          ["CWE-502"],
          `model_format=${c.model_format ?? fmt}`,
          input.filename,
          ["deserialization"],
        ),
      );
    }

    if (c.model_signed === false) {
      findings.push(
        mk(
          "ml-pipeline-unsigned-model",
          "medium",
          "Produced model artifact is not signed",
          "An unsigned model cannot be verified by downstream consumers. A tampered or substituted checkpoint is indistinguishable from the genuine one (CWE-347).",
          "Sign model artifacts (e.g. with Sigstore / model signing) and verify the signature before loading in any downstream environment.",
          ["CWE-347"],
          "model_signed=false",
          input.filename,
          ["supply-chain"],
        ),
      );
    }

    if (c.secrets_in_notebooks === true) {
      findings.push(
        mk(
          "ml-pipeline-secrets-in-notebooks",
          "high",
          "Credentials are embedded in notebooks",
          "Hardcoded API keys, tokens, or database credentials in `.ipynb` notebooks are committed to source control and leak to anyone with repo access (CWE-798).",
          "Move secrets to environment variables or a secrets manager; scan notebooks in CI and strip outputs / credentials before commit.",
          ["CWE-798"],
          "secrets_in_notebooks=true",
          input.filename,
          ["secrets"],
        ),
      );
    }

    if (c.pinned_dependencies === false) {
      findings.push(
        mk(
          "ml-pipeline-unpinned-dependencies",
          "medium",
          "Pipeline dependencies are not pinned to exact versions",
          "Unpinned ML dependencies resolve to different versions over time. A compromised or yanked package release silently enters the training environment (OWASP ML06 AI Supply Chain).",
          "Pin exact versions and hashes (e.g. a lockfile with hashes) for all training and serving dependencies; rebuild the environment from the lockfile.",
          ["CWE-1357", "CWE-829"],
          "pinned_dependencies=false",
          input.filename,
          ["supply-chain"],
        ),
      );
    }
  }

  return findings;
}
