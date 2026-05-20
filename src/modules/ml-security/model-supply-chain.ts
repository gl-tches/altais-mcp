// Model supply-chain auditor (altais_audit_model_supply_chain).
//
// Verifies the provenance and integrity of a third-party or internal model
// artifact: serialization format, signature, checksum / revision pinning,
// source trust, and malware scanning. Maps to OWASP ML06 AI Supply Chain.

import type { Finding } from "../../core/types.js";
import { buildMlSecurityFinding } from "./finding.js";

export interface ModelSupplyChainConfig {
  /** Where the model came from, e.g. "huggingface", "internal", "unknown". */
  readonly source?: string;
  /** Serialized model format, e.g. "pickle", "safetensors", "onnx", "gguf". */
  readonly format?: string;
  /** Whether the artifact is cryptographically signed. */
  readonly signed?: boolean;
  /** Whether the artifact's checksum is verified before use. */
  readonly checksum_verified?: boolean;
  /** Whether the artifact has been scanned for malicious payloads. */
  readonly scanned_for_malware?: boolean;
  /** Whether a specific immutable revision / commit is pinned. */
  readonly pinned_revision?: boolean;
}

export interface ModelSupplyChainInput {
  readonly config: ModelSupplyChainConfig;
  readonly filename?: string;
}

const REFS = [
  "https://owasp.org/www-project-machine-learning-security-top-10/",
  "https://owasp.org/www-project-machine-learning-security-top-10/docs/ML06_2023-AI_Supply_Chain_Attacks",
  "https://cwe.mitre.org/data/definitions/1357.html",
];

const TRUSTED_SOURCES = new Set([
  "internal",
  "first-party",
  "vetted",
  "trusted",
  "private-registry",
]);
const UNTRUSTED_SOURCES = new Set(["unknown", "anonymous", "third-party", "scraped", "untrusted"]);
const EXECUTABLE_FORMATS = new Set(["pickle", "pkl", "joblib", "dill", "pt", "pth", "h5", "keras"]);

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

export function auditModelSupplyChain(input: ModelSupplyChainInput): readonly Finding[] {
  const c = input.config;
  const findings: Finding[] = [];

  const fmt = c.format?.trim().toLowerCase();
  if (fmt !== undefined && EXECUTABLE_FORMATS.has(fmt)) {
    findings.push(
      mk(
        "model-supply-chain-executable-format",
        "high",
        `Model is distributed in a code-executing format: \`${c.format ?? fmt}\``,
        "Pickle-derived formats (pickle, joblib, dill, and pickle-backed `.pt` / `.h5` checkpoints) run arbitrary code on load. A malicious or tampered artifact yields remote code execution in the loading process (CWE-502).",
        "Convert to a non-executable format — `safetensors` for weights, ONNX or GGUF for portable models — and reject pickle artifacts at the trust boundary.",
        ["CWE-502"],
        `format=${c.format ?? fmt}`,
        input.filename,
        ["deserialization", "supply-chain"],
      ),
    );
  }

  if (c.signed === false) {
    findings.push(
      mk(
        "model-supply-chain-unsigned",
        "high",
        "Model artifact is not cryptographically signed",
        "Without a signature there is no way to verify the model's author or that it was not modified in transit or at rest. A substituted artifact passes unnoticed (CWE-347).",
        "Require signed model artifacts and verify the signature (e.g. Sigstore / model signing) against a trusted key before loading.",
        ["CWE-347"],
        "signed=false",
        input.filename,
        ["supply-chain", "integrity"],
      ),
    );
  }

  if (c.checksum_verified === false) {
    findings.push(
      mk(
        "model-supply-chain-no-checksum",
        "medium",
        "Model checksum is not verified before use",
        "Without checksum verification a corrupted, truncated, or swapped checkpoint is loaded without detection. Integrity of the artifact is unverified (CWE-1357).",
        "Record a known-good checksum (e.g. SHA-256) for each model version and verify it before every load.",
        ["CWE-1357", "CWE-353"],
        "checksum_verified=false",
        input.filename,
        ["integrity"],
      ),
    );
  }

  if (c.pinned_revision === false) {
    findings.push(
      mk(
        "model-supply-chain-unpinned-revision",
        "medium",
        "Model is not pinned to an immutable revision",
        "Referencing a model by a mutable tag (e.g. `main`) instead of an immutable revision / commit lets the upstream silently change the weights you load (OWASP ML06, CWE-1357).",
        "Pin the model to an immutable revision / commit hash so the exact reviewed weights are always fetched.",
        ["CWE-1357", "CWE-829"],
        "pinned_revision=false",
        input.filename,
        ["supply-chain"],
      ),
    );
  }

  const src = c.source?.trim().toLowerCase();
  if (src !== undefined) {
    if (UNTRUSTED_SOURCES.has(src)) {
      findings.push(
        mk(
          "model-supply-chain-untrusted-source",
          "high",
          `Model originates from an untrusted source: \`${c.source ?? src}\``,
          "A model from an unknown, anonymous, or third-party source may carry a backdoor, a poisoned head, or an embedded RCE payload. The provenance cannot be vouched for (OWASP ML06).",
          "Obtain models only from vetted publishers; verify the publisher identity, scan the artifact, and re-evaluate the model before trusting it.",
          ["CWE-829"],
          `source=${c.source ?? src}`,
          input.filename,
          ["supply-chain", "provenance"],
        ),
      );
    } else if (!TRUSTED_SOURCES.has(src)) {
      findings.push(
        mk(
          "model-supply-chain-external-source",
          "medium",
          `Model originates from an external hub: \`${c.source ?? src}\``,
          "Public model hubs host community-uploaded artifacts; even popular repos have shipped malicious pickles. An external model must be treated as untrusted input (OWASP ML06).",
          "Pin an immutable revision, verify the publisher and checksum, and scan the artifact for malicious payloads before deployment.",
          ["CWE-829"],
          `source=${c.source ?? src}`,
          input.filename,
          ["supply-chain", "provenance"],
        ),
      );
    }
  }

  if (c.scanned_for_malware === false) {
    findings.push(
      mk(
        "model-supply-chain-not-scanned",
        "medium",
        "Model artifact has not been scanned for malicious payloads",
        "Model files can hide executable payloads (malicious pickle opcodes, embedded scripts, manipulated layers). Loading an unscanned artifact runs that payload (OWASP ML06).",
        "Scan model artifacts with a model-security scanner before deployment and quarantine any artifact with unexpected opcodes or embedded code.",
        ["CWE-506"],
        "scanned_for_malware=false",
        input.filename,
        ["supply-chain"],
      ),
    );
  }

  return findings;
}
