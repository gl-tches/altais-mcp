// SLSA v1.2 provenance attestation structural verification.
//
// We parse in-toto Statement / DSSE envelopes and check structural
// expectations (predicateType, builder, materials, build_type). Actual
// cryptographic verification needs trusted keys and live network access,
// which altais-mcp does not perform — the tool reports the structure so
// a human or downstream verifier can act on it.

import type { Finding } from "../../core/types.js";
import { findingId } from "../../core/utils.js";

const SLSA_PREDICATE_TYPES = new Set([
  "https://slsa.dev/provenance/v1",
  "https://slsa.dev/provenance/v1.0",
  "https://slsa.dev/provenance/v0.2",
]);

export interface SlsaAuditResult {
  readonly findings: readonly Finding[];
  readonly summary: {
    readonly predicate_type: string | undefined;
    readonly builder_id: string | undefined;
    readonly build_type: string | undefined;
    readonly subjects: readonly string[];
    readonly slsa_level_estimate: number;
  };
}

interface Statement {
  readonly _type?: string;
  readonly predicateType?: string;
  readonly predicate?: Record<string, unknown>;
  readonly subject?: readonly {
    readonly name?: string;
    readonly digest?: Record<string, string>;
  }[];
}

interface DsseEnvelope {
  readonly payload?: string;
  readonly payloadType?: string;
  readonly signatures?: readonly unknown[];
}

export function verifySlsa(input: string): SlsaAuditResult {
  const findings: Finding[] = [];
  let statement: Statement | null = null;

  let parsed: unknown;
  try {
    parsed = JSON.parse(input);
  } catch {
    findings.push(
      buildFinding(
        "slsa-malformed",
        "high",
        "Provenance payload is not valid JSON",
        "The input could not be parsed as JSON. Provide a DSSE envelope or in-toto Statement.",
        "",
      ),
    );
    return {
      findings,
      summary: {
        predicate_type: undefined,
        builder_id: undefined,
        build_type: undefined,
        subjects: [],
        slsa_level_estimate: 0,
      },
    };
  }

  const env = parsed as DsseEnvelope;
  if (typeof env.payload === "string" && typeof env.payloadType === "string") {
    if (env.payloadType !== "application/vnd.in-toto+json") {
      findings.push(
        buildFinding(
          "slsa-wrong-payload-type",
          "medium",
          `Unexpected DSSE payloadType: ${env.payloadType}`,
          "SLSA provenance payloads should declare `application/vnd.in-toto+json`.",
          env.payloadType,
        ),
      );
    }
    if (!env.signatures || env.signatures.length === 0) {
      findings.push(
        buildFinding(
          "slsa-no-signatures",
          "critical",
          "DSSE envelope has no signatures",
          "Unsigned provenance is meaningless. Re-emit with at least one verifier key.",
          "",
        ),
      );
    }
    try {
      const decoded = Buffer.from(env.payload, "base64").toString("utf8");
      statement = JSON.parse(decoded) as Statement;
    } catch {
      findings.push(
        buildFinding(
          "slsa-malformed",
          "high",
          "DSSE payload does not decode as base64 JSON",
          "Ensure the payload is base64-encoded JSON per the in-toto spec.",
          "",
        ),
      );
    }
  } else if ((parsed as Statement)._type === "https://in-toto.io/Statement/v1") {
    statement = parsed as Statement;
    findings.push(
      buildFinding(
        "slsa-no-envelope",
        "medium",
        "In-toto Statement supplied without a DSSE envelope",
        "Wrap the Statement in a DSSE envelope so signatures can be transported with the payload.",
        "",
      ),
    );
  }

  let predicateType: string | undefined;
  let builderId: string | undefined;
  let buildType: string | undefined;
  let subjects: string[] = [];
  let slsaLevel = 0;

  if (statement) {
    predicateType = statement.predicateType;
    subjects = (statement.subject ?? []).map((s) => s.name ?? "(unnamed)");
    if (!predicateType || !SLSA_PREDICATE_TYPES.has(predicateType)) {
      findings.push(
        buildFinding(
          "slsa-unknown-predicate",
          "medium",
          `Unrecognized predicateType: ${predicateType ?? "(missing)"}`,
          "Use `https://slsa.dev/provenance/v1` for SLSA v1+ provenance.",
          predicateType ?? "",
        ),
      );
    }
    const predicate = statement.predicate ?? {};
    const builder = (predicate as { builder?: { id?: string } }).builder;
    builderId = builder?.id;
    if (!builderId) {
      findings.push(
        buildFinding(
          "slsa-no-builder",
          "high",
          "Provenance has no builder.id",
          "Provenance must identify the builder (a URI such as `https://github.com/actions/runner`).",
          "",
        ),
      );
    } else {
      slsaLevel = 2;
    }
    const buildDefinition = (predicate as { buildDefinition?: { buildType?: string } })
      .buildDefinition;
    buildType = buildDefinition?.buildType;
    if (!buildType) {
      findings.push(
        buildFinding(
          "slsa-no-build-type",
          "medium",
          "Provenance has no buildDefinition.buildType",
          "Declare a buildType URI so verifiers can pick the correct policy.",
          "",
        ),
      );
    }
    if (subjects.length === 0) {
      findings.push(
        buildFinding(
          "slsa-no-subject",
          "high",
          "Provenance lists no subjects",
          "A SLSA provenance must list at least one subject artifact with a digest.",
          "",
        ),
      );
    }
    if (subjects.length > 0 && builderId && buildType) {
      slsaLevel = 3; // structurally consistent — full crypto check still required.
    }
  } else if (findings.length === 0) {
    findings.push(
      buildFinding(
        "slsa-no-statement",
        "high",
        "Input does not contain a recognizable in-toto Statement",
        "Pass a DSSE-wrapped SLSA provenance, or a top-level Statement of type `https://in-toto.io/Statement/v1`.",
        "",
      ),
    );
  }

  return {
    findings,
    summary: {
      predicate_type: predicateType,
      builder_id: builderId,
      build_type: buildType,
      subjects,
      slsa_level_estimate: slsaLevel,
    },
  };
}

function buildFinding(
  rule: string,
  severity: Finding["severity"],
  title: string,
  remediation: string,
  evidence: string,
): Finding {
  return {
    id: findingId("supply_chain", rule, undefined, evidence),
    module: "supply_chain",
    rule,
    severity,
    cwe: ["CWE-345"],
    title,
    description: title,
    ...(evidence ? { evidence } : {}),
    remediation,
    references: ["https://slsa.dev/spec/v1.0/provenance"],
    tags: ["supply-chain", "slsa"],
    status: "open",
  };
}
