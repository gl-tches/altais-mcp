// Secrets module: scan source and git history for credentials.

import { z } from "zod";
import type { CallToolResult } from "@modelcontextprotocol/sdk/types.js";

import type { Config } from "../../config.js";
import type { FindingStore } from "../../core/report.js";
import type { Finding, ModuleDefinition, ToolDefinition } from "../../core/types.js";
import { DEFAULT_THRESHOLDS, type EntropyThresholds, scanEntropy } from "./entropy.js";
import { scanGitSecrets } from "./git-secrets.js";
import { SecretPatternRegistry } from "./patterns.js";

const MODULE_VERSION = "0.1.0";

const COMMON_ANNOTATIONS = {
  readOnlyHint: true,
  destructiveHint: false,
  idempotentHint: true,
  openWorldHint: false,
} as const;

export interface SecretsModuleDeps {
  readonly config: Config;
  readonly findingStore: FindingStore;
  readonly dataDir?: string;
}

interface SecretsState {
  readonly maxSourceBytes: number;
  readonly thresholds: EntropyThresholds;
}

function deriveState(config: Config): SecretsState {
  return {
    maxSourceBytes: config.scan.max_source_bytes,
    thresholds: {
      hex: config.secrets.entropy_min_hex,
      base64: config.secrets.entropy_min_base64,
      minTokenLength: config.secrets.min_token_length,
    },
  };
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

function summarize(findings: readonly Finding[]): {
  total: number;
  by_severity: Record<string, number>;
} {
  const bySeverity: Record<string, number> = {};
  for (const f of findings) bySeverity[f.severity] = (bySeverity[f.severity] ?? 0) + 1;
  return { total: findings.length, by_severity: bySeverity };
}

function buildScanSecretsTool(
  deps: SecretsModuleDeps,
  state: SecretsState,
  getRegistry: () => SecretPatternRegistry,
): ToolDefinition {
  const inputSchema = {
    source: z
      .string()
      .min(1)
      .max(state.maxSourceBytes)
      .describe("Source text to scan for credentials and tokens."),
    filename: z
      .string()
      .min(1)
      .max(512)
      .optional()
      .describe("Optional filename, used for finding location."),
    rules: z
      .array(z.string().min(1).max(128))
      .max(64)
      .optional()
      .describe("Restrict to specific secret-pattern IDs. Empty = all."),
  };
  return {
    name: "altais_scan_secrets",
    title: "Scan for known secret patterns",
    description:
      "Match the input against the bundled secret-pattern database (AWS, GitHub, Slack, Stripe, GCP, JWT, PEM private keys, password-in-config, DB DSNs, and more). Returns one finding per match; the literal secret is redacted in the evidence field.",
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
      const registry = getRegistry();
      const findings = registry.scan(
        {
          source: parsed.data.source,
          ...(parsed.data.filename !== undefined ? { file: parsed.data.filename } : {}),
        },
        parsed.data.rules ? { rules: parsed.data.rules } : {},
      );
      deps.findingStore.addMany(findings);
      deps.findingStore.recordFileScanned();
      return textResult(jsonText({ summary: summarize(findings), findings }));
    },
  };
}

function buildScanEntropyTool(deps: SecretsModuleDeps, state: SecretsState): ToolDefinition {
  const inputSchema = {
    source: z
      .string()
      .min(1)
      .max(state.maxSourceBytes)
      .describe("Source text to scan for high-entropy strings."),
    filename: z
      .string()
      .min(1)
      .max(512)
      .optional()
      .describe("Optional filename, used for finding location."),
    hex_threshold: z
      .number()
      .min(0)
      .max(8)
      .optional()
      .describe("Override hex-charset threshold in bits/char (default from config)."),
    base64_threshold: z
      .number()
      .min(0)
      .max(8)
      .optional()
      .describe("Override base64-charset threshold in bits/char (default from config)."),
    min_token_length: z
      .number()
      .int()
      .min(8)
      .max(256)
      .optional()
      .describe("Override minimum token length to consider (default from config)."),
  };
  return {
    name: "altais_scan_entropy",
    title: "Scan for high-entropy strings",
    description:
      "Compute Shannon entropy on candidate tokens in the source and flag those above the configured threshold (default 4.5 bits/char for hex, 5.0 for base64). Useful for catching random-looking credentials that do not match a known pattern.",
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
      const thresholds: EntropyThresholds = {
        hex: parsed.data.hex_threshold ?? state.thresholds.hex,
        base64: parsed.data.base64_threshold ?? state.thresholds.base64,
        minTokenLength: parsed.data.min_token_length ?? state.thresholds.minTokenLength,
      };
      const findings = scanEntropy(
        {
          source: parsed.data.source,
          ...(parsed.data.filename !== undefined ? { file: parsed.data.filename } : {}),
        },
        thresholds,
      );
      deps.findingStore.addMany(findings);
      deps.findingStore.recordFileScanned();
      return textResult(jsonText({ thresholds, summary: summarize(findings), findings }));
    },
  };
}

function buildScanGitSecretsTool(
  deps: SecretsModuleDeps,
  state: SecretsState,
  getRegistry: () => SecretPatternRegistry,
): ToolDefinition {
  const inputSchema = {
    source: z
      .string()
      .min(1)
      .max(state.maxSourceBytes)
      .describe("Output from `git log -p` or `git diff`."),
  };
  return {
    name: "altais_scan_git_secrets",
    title: "Scan git log / diff for secrets",
    description:
      "Walk `git log -p` or `git diff` output, attribute findings to the originating commit and file, and run both the pattern registry and the entropy detector against each diff line. Use this to find credentials in history, not just the working tree.",
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
      const registry = getRegistry();
      const findings = scanGitSecrets({ source: parsed.data.source }, registry, state.thresholds);
      deps.findingStore.addMany(findings);
      return textResult(jsonText({ summary: summarize(findings), findings }));
    },
  };
}

export function createSecretsModule(deps: SecretsModuleDeps): ModuleDefinition {
  const state = deriveState(deps.config);
  const registryRef: { value: SecretPatternRegistry | null } = { value: null };
  const getRegistry = (): SecretPatternRegistry => {
    if (!registryRef.value) throw new Error("secrets module accessed before init()");
    return registryRef.value;
  };

  // Avoid unused warning while keeping default thresholds reachable.
  void DEFAULT_THRESHOLDS;

  const tools: readonly ToolDefinition[] = [
    buildScanSecretsTool(deps, state, getRegistry),
    buildScanEntropyTool(deps, state),
    buildScanGitSecretsTool(deps, state, getRegistry),
  ];

  return {
    name: "secrets",
    description:
      "Detect credentials in source and git history via known-pattern matching plus Shannon-entropy heuristics.",
    version: MODULE_VERSION,
    tools,
    async init() {
      registryRef.value = await SecretPatternRegistry.load(deps.dataDir);
    },
  };
}
