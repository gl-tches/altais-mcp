// VEX (Vulnerability Exploitability eXchange) generator.
// Supports OpenVEX 0.2.0 and CycloneDX 1.5 VEX.

import { randomUUID } from "node:crypto";

export type VexFormat = "openvex" | "cyclonedx-vex";

export type VexStatus = "not_affected" | "affected" | "fixed" | "under_investigation";

export interface VexProductRef {
  readonly identifier: string; // PURL or other ref
  readonly subcomponent_identifiers?: readonly string[];
}

export interface VexStatement {
  readonly vulnerability: string;
  readonly products: readonly VexProductRef[];
  readonly status: VexStatus;
  readonly justification?:
    | "component_not_present"
    | "vulnerable_code_not_present"
    | "vulnerable_code_not_in_execute_path"
    | "vulnerable_code_cannot_be_controlled_by_adversary"
    | "inline_mitigations_already_exist";
  readonly impact_statement?: string;
  readonly action_statement?: string;
}

export interface VexGenerateInput {
  readonly format: VexFormat;
  readonly author?: string;
  readonly author_role?: string;
  readonly statements: readonly VexStatement[];
}

export function generateVex(input: VexGenerateInput): unknown {
  if (input.format === "openvex") return openVex(input);
  return cyclonedxVex(input);
}

function openVex(input: VexGenerateInput): unknown {
  const now = new Date().toISOString();
  return {
    "@context": "https://openvex.dev/ns/v0.2.0",
    "@id": `urn:uuid:${randomUUID()}`,
    author: input.author ?? "altais-mcp",
    role: input.author_role ?? "document_creator",
    timestamp: now,
    version: 1,
    statements: input.statements.map((s) => ({
      vulnerability: { name: s.vulnerability },
      products: s.products.map((p) => ({
        "@id": p.identifier,
        ...(p.subcomponent_identifiers !== undefined
          ? { subcomponents: p.subcomponent_identifiers.map((id) => ({ "@id": id })) }
          : {}),
      })),
      status: s.status,
      ...(s.justification !== undefined ? { justification: s.justification } : {}),
      ...(s.impact_statement !== undefined ? { impact_statement: s.impact_statement } : {}),
      ...(s.action_statement !== undefined ? { action_statement: s.action_statement } : {}),
    })),
  };
}

const CYCLONEDX_STATE: Readonly<Record<VexStatus, string>> = {
  not_affected: "not_affected",
  affected: "exploitable",
  fixed: "resolved",
  under_investigation: "in_triage",
};

function cyclonedxVex(input: VexGenerateInput): unknown {
  return {
    bomFormat: "CycloneDX",
    specVersion: "1.5",
    serialNumber: `urn:uuid:${randomUUID()}`,
    version: 1,
    metadata: {
      timestamp: new Date().toISOString(),
      tools: [{ vendor: "altais", name: "altais-mcp" }],
    },
    vulnerabilities: input.statements.map((s) => ({
      id: s.vulnerability,
      affects: s.products.map((p) => ({ ref: p.identifier })),
      analysis: {
        state: CYCLONEDX_STATE[s.status],
        ...(s.justification !== undefined ? { justification: s.justification } : {}),
        ...(s.impact_statement !== undefined ? { detail: s.impact_statement } : {}),
        ...(s.action_statement !== undefined ? { response: [s.action_statement] } : {}),
      },
    })),
  };
}
