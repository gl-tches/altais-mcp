// Threat-model module: STRIDE, DREAD, attack trees, trust boundaries.

import { z } from "zod";
import type { CallToolResult } from "@modelcontextprotocol/sdk/types.js";

import type { FindingStore } from "../../core/report.js";
import type { ModuleDefinition, ToolDefinition } from "../../core/types.js";
import { generateAttackTree } from "./attack-tree.js";
import { scoreDread } from "./dread.js";
import { analyzeStride } from "./stride.js";
import { analyzeTrustBoundaries } from "./trust-boundaries.js";
import { COMPONENT_TYPES, type ComponentType } from "./types.js";

const MODULE_VERSION = "0.2.0";

const COMMON_ANNOTATIONS = {
  readOnlyHint: true,
  destructiveHint: false,
  idempotentHint: true,
  openWorldHint: false,
} as const;

export interface ThreatModelModuleDeps {
  readonly findingStore: FindingStore;
}

function textResult(text: string): CallToolResult {
  return { content: [{ type: "text", text }] };
}

function errorResult(text: string): CallToolResult {
  return { isError: true, content: [{ type: "text", text }] };
}

function jsonText(value: unknown): string {
  return JSON.stringify(value, null, 2);
}

const componentSchema = z.object({
  name: z.string().min(1).max(128),
  type: z
    .enum(COMPONENT_TYPES as readonly [ComponentType, ...ComponentType[]])
    .describe("Component type. Drives the STRIDE knowledge base lookup."),
  description: z.string().max(2048).optional(),
  trust_zone: z.string().min(1).max(64).optional(),
  handles_pii: z.boolean().optional(),
  authenticates_clients: z.boolean().optional(),
});

const dataFlowSchema = z.object({
  from: z.string().min(1).max(128),
  to: z.string().min(1).max(128),
  data: z.string().min(1).max(512).describe("What is sent (e.g. 'auth token', 'order JSON')."),
  protocol: z.string().min(1).max(64).optional(),
  auth: z.string().min(1).max(128).optional(),
  encrypted: z.boolean().optional(),
});

const trustBoundarySchema = z.object({
  name: z.string().min(1).max(128),
  description: z.string().max(1024).optional(),
});

const architectureSchema = z.object({
  components: z.array(componentSchema).min(1).max(64),
  data_flows: z.array(dataFlowSchema).max(256).optional(),
  trust_boundaries: z.array(trustBoundarySchema).max(32).optional(),
});

function buildStrideTool(): ToolDefinition {
  const inputSchema = { architecture: architectureSchema };
  return {
    name: "altais_stride",
    title: "STRIDE analysis from architecture",
    description:
      "Given a structured architecture (components, data flows, trust boundaries), emit a STRIDE breakdown per component using a knowledge base of typical threats for each component type. Returns structured analysis JSON.",
    inputSchema,
    annotations: COMMON_ANNOTATIONS,
    handler: (args) => {
      const parsed = z.object(inputSchema).safeParse(args);
      if (!parsed.success) {
        return errorResult(
          `Invalid input: ${parsed.error.issues
            .map((i) => `${i.path.join(".") || "<root>"}: ${i.message}`)
            .join("; ")}`,
        );
      }
      const result = analyzeStride(parsed.data.architecture);
      return textResult(jsonText(result));
    },
  };
}

function buildDreadTool(): ToolDefinition {
  const score = z.number().min(1).max(10).describe("Subjective rating, 1 (low) – 10 (high).");
  const inputSchema = {
    threat: z.string().min(1).max(512).describe("Short threat description."),
    damage: score,
    reproducibility: score,
    exploitability: score,
    affected_users: score,
    discoverability: score,
    justification: z.string().max(2048).optional(),
  };
  return {
    name: "altais_dread",
    title: "DREAD score a threat",
    description:
      "Compute a DREAD score from five subjective inputs (Damage, Reproducibility, Exploitability, Affected users, Discoverability), each 1–10. Returns the total (5–50), average, and a qualitative rating.",
    inputSchema,
    annotations: COMMON_ANNOTATIONS,
    handler: (args) => {
      const parsed = z.object(inputSchema).safeParse(args);
      if (!parsed.success) {
        return errorResult(
          `Invalid input: ${parsed.error.issues
            .map((i) => `${i.path.join(".") || "<root>"}: ${i.message}`)
            .join("; ")}`,
        );
      }
      return textResult(
        jsonText(
          scoreDread({
            threat: parsed.data.threat,
            damage: parsed.data.damage,
            reproducibility: parsed.data.reproducibility,
            exploitability: parsed.data.exploitability,
            affected_users: parsed.data.affected_users,
            discoverability: parsed.data.discoverability,
            ...(parsed.data.justification !== undefined
              ? { justification: parsed.data.justification }
              : {}),
          }),
        ),
      );
    },
  };
}

function buildAttackTreeTool(): ToolDefinition {
  const inputSchema = {
    goal: z
      .string()
      .min(1)
      .max(256)
      .describe(
        "Attacker's goal in plain text. The tool matches keywords to a known template (account takeover, data exfiltration, RCE, privesc, DoS, supply chain) or falls back to a generic tree.",
      ),
    asset: z
      .string()
      .min(1)
      .max(256)
      .optional()
      .describe("Target asset (e.g. 'customer database')."),
    context: z
      .string()
      .min(1)
      .max(2048)
      .optional()
      .describe("Optional additional context about the system."),
  };
  return {
    name: "altais_attack_tree",
    title: "Generate an attack tree",
    description:
      "Match an attacker goal to a built-in attack-tree template and return a structured tree of attack paths with mitigations and CWE references. Falls back to a generic STRIDE-shaped tree when no template matches.",
    inputSchema,
    annotations: COMMON_ANNOTATIONS,
    handler: (args) => {
      const parsed = z.object(inputSchema).safeParse(args);
      if (!parsed.success) {
        return errorResult(
          `Invalid input: ${parsed.error.issues
            .map((i) => `${i.path.join(".") || "<root>"}: ${i.message}`)
            .join("; ")}`,
        );
      }
      const result = generateAttackTree({
        goal: parsed.data.goal,
        ...(parsed.data.asset !== undefined ? { asset: parsed.data.asset } : {}),
        ...(parsed.data.context !== undefined ? { context: parsed.data.context } : {}),
      });
      return textResult(jsonText(result));
    },
  };
}

function buildTrustBoundariesTool(deps: ThreatModelModuleDeps): ToolDefinition {
  const inputSchema = { architecture: architectureSchema };
  return {
    name: "altais_trust_boundaries",
    title: "Identify trust boundary crossings",
    description:
      "Walk the data flows in a structured architecture and identify flows that cross trust zones. Emits Finding objects for cleartext crossings, unauthenticated crossings, and ingress points that need explicit input validation.",
    inputSchema,
    annotations: COMMON_ANNOTATIONS,
    handler: (args) => {
      const parsed = z.object(inputSchema).safeParse(args);
      if (!parsed.success) {
        return errorResult(
          `Invalid input: ${parsed.error.issues
            .map((i) => `${i.path.join(".") || "<root>"}: ${i.message}`)
            .join("; ")}`,
        );
      }
      const result = analyzeTrustBoundaries(parsed.data.architecture);
      deps.findingStore.addMany(result.findings);
      return textResult(jsonText(result));
    },
  };
}

export function createThreatModelModule(deps: ThreatModelModuleDeps): ModuleDefinition {
  const tools: readonly ToolDefinition[] = [
    buildStrideTool(),
    buildDreadTool(),
    buildAttackTreeTool(),
    buildTrustBoundariesTool(deps),
  ];
  return {
    name: "threat_model",
    description:
      "Structured threat modeling: STRIDE per component, DREAD scoring, attack trees, trust boundary analysis.",
    version: MODULE_VERSION,
    tools,
    init() {
      // No async resources.
    },
  };
}
