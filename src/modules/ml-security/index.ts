// ML / LLM security module: 8 auditors for machine-learning and
// large-language-model application security — training-pipeline integrity,
// inference-API hardening, model supply-chain provenance, OWASP ML Top 10
// and OWASP LLM Top 10 coverage, prompt-injection analysis, agent
// excessive-agency review, and LLM output-handling.

import { z } from "zod";
import type { CallToolResult } from "@modelcontextprotocol/sdk/types.js";

import type { FindingStore } from "../../core/report.js";
import { scanToken } from "../../core/scan-patterns.js";
import type { Finding, ModuleDefinition, ToolDefinition } from "../../core/types.js";
import { auditAgentPermissions } from "./agent-permissions.js";
import { auditInferenceApi } from "./inference-api.js";
import { checkLlmTop10 } from "./llm-top10.js";
import { auditMlPipeline } from "./ml-pipeline.js";
import { auditModelSupplyChain } from "./model-supply-chain.js";
import { checkOwaspMl } from "./owasp-ml.js";
import { auditOutputHandling } from "./output-handling.js";
import { auditPromptInjection } from "./prompt-injection.js";

const MODULE_VERSION = "0.5.0";

const COMMON_ANNOTATIONS = {
  readOnlyHint: true,
  destructiveHint: false,
  idempotentHint: true,
  openWorldHint: false,
} as const;

export interface MlSecurityModuleDeps {
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

function summarize(findings: readonly Finding[]): {
  total: number;
  by_severity: Record<string, number>;
} {
  const bySeverity: Record<string, number> = {};
  for (const f of findings) bySeverity[f.severity] = (bySeverity[f.severity] ?? 0) + 1;
  return { total: findings.length, by_severity: bySeverity };
}

function withSummary(findings: readonly Finding[], extra?: Record<string, unknown>): unknown {
  return { summary: summarize(findings), ...(extra ?? {}), findings };
}

function zodParser<T>(
  schema: z.ZodType<T>,
): (args: unknown) => { success: true; data: T } | { success: false; message: string } {
  return (args) => {
    const r = schema.safeParse(args);
    if (r.success) return { success: true, data: r.data };
    return {
      success: false,
      message: r.error.issues
        .map((i) => `${i.path.join(".") || "<root>"}: ${i.message}`)
        .join("; "),
    };
  };
}

function makeRunner<TInput>(
  deps: MlSecurityModuleDeps,
  parser: (args: unknown) => { success: true; data: TInput } | { success: false; message: string },
  run: (data: TInput) => { findings: readonly Finding[]; extra?: Record<string, unknown> },
): (args: unknown) => CallToolResult {
  return (args: unknown) => {
    const parsed = parser(args);
    if (!parsed.success) return errorResult(`Invalid input: ${parsed.message}`);
    const { findings, extra } = run(parsed.data);
    deps.findingStore.addMany(findings);
    return textResult(jsonText(withSummary(findings, extra)));
  };
}

// ─── Shared field builders ─────────────────────────────────────────────────

const filenameField = z
  .string()
  .min(1)
  .max(512)
  .optional()
  .describe("Optional filename used for the finding location.");

const sourceField = z
  .string()
  .min(1)
  .max(512 * 1024)
  .optional()
  .describe("Optional source code to scan for risky patterns.");

const boolOpt = (desc: string): z.ZodOptional<z.ZodBoolean> =>
  z.boolean().optional().describe(desc);

// ─── altais_audit_ml_pipeline ──────────────────────────────────────────────

const mlPipelineSchema = z.object({
  source: sourceField,
  config: z
    .object({
      training_data_source: z.string().min(1).max(256).optional(),
      data_validation: boolOpt("Whether training data is validated before use."),
      data_provenance_tracked: boolOpt("Whether data provenance is tracked."),
      model_format: z.string().min(1).max(64).optional(),
      model_signed: boolOpt("Whether the model artifact is signed."),
      pinned_dependencies: boolOpt("Whether dependencies are pinned to exact versions."),
      secrets_in_notebooks: boolOpt("Whether secrets appear in notebooks."),
      lineage_tracked: boolOpt("Whether data and model lineage is tracked."),
    })
    .strict()
    .optional()
    .describe("Structured description of the training pipeline."),
  filename: filenameField,
});

function buildMlPipelineTool(deps: MlSecurityModuleDeps): ToolDefinition {
  return {
    name: "altais_audit_ml_pipeline",
    title: "Audit an ML training pipeline",
    description:
      "Audit a machine-learning training pipeline for data poisoning (untrusted / unvalidated training data — CWE-1395), insecure deserialization of model files (`pickle.load`, `joblib.load`, `torch.load` without `weights_only=True` — CWE-502), unsigned models, secrets baked into notebooks (CWE-798), unpinned dependencies, and missing data lineage / provenance.",
    inputSchema: mlPipelineSchema.shape,
    annotations: COMMON_ANNOTATIONS,
    handler: makeRunner(deps, zodParser(mlPipelineSchema), (d) => ({
      findings: auditMlPipeline(d),
    })),
  };
}

// ─── altais_audit_inference_api ────────────────────────────────────────────

const inferenceApiSchema = z.object({
  source: sourceField,
  config: z
    .object({
      rate_limited: boolOpt("Whether the prediction endpoint is rate limited."),
      authentication: boolOpt("Whether callers must authenticate."),
      returns_confidence_scores: boolOpt("Whether responses include confidence scores."),
      returns_logits: boolOpt("Whether responses include raw logits."),
      input_validation: boolOpt("Whether inference inputs are validated."),
      batch_endpoint: boolOpt("Whether a batch prediction endpoint is exposed."),
      monitoring: boolOpt("Whether the API has abuse / anomaly monitoring."),
      query_logging: boolOpt("Whether queries are logged for forensics."),
    })
    .strict()
    .optional()
    .describe("Structured description of the inference API."),
  filename: filenameField,
});

function buildInferenceApiTool(deps: MlSecurityModuleDeps): ToolDefinition {
  return {
    name: "altais_audit_inference_api",
    title: "Audit an inference API",
    description:
      "Check a model-serving / inference API for model-extraction and adversarial-evasion risk: missing rate limiting (model theft — OWASP ML05, CWE-770), missing authentication (CWE-306), exposed confidence scores / raw logits (eases model extraction and inversion), absent input validation (adversarial evasion — OWASP ML01), and missing abuse monitoring.",
    inputSchema: inferenceApiSchema.shape,
    annotations: COMMON_ANNOTATIONS,
    handler: makeRunner(deps, zodParser(inferenceApiSchema), (d) => ({
      findings: auditInferenceApi(d),
    })),
  };
}

// ─── altais_audit_model_supply_chain ───────────────────────────────────────

const modelSupplyChainSchema = z.object({
  config: z
    .object({
      source: z.string().min(1).max(256).optional(),
      format: z.string().min(1).max(64).optional(),
      signed: boolOpt("Whether the artifact is cryptographically signed."),
      checksum_verified: boolOpt("Whether the artifact checksum is verified."),
      scanned_for_malware: boolOpt("Whether the artifact is scanned for malicious payloads."),
      pinned_revision: boolOpt("Whether an immutable revision is pinned."),
    })
    .strict()
    .describe("Structured description of the model artifact and its provenance."),
  filename: filenameField,
});

function buildModelSupplyChainTool(deps: MlSecurityModuleDeps): ToolDefinition {
  return {
    name: "altais_audit_model_supply_chain",
    title: "Audit a model supply chain",
    description:
      "Verify the provenance and integrity of a model artifact: `pickle`-format models (insecure deserialization — CWE-502), unsigned models (CWE-347), missing checksum / revision pinning (CWE-1357), models from untrusted or external sources (OWASP ML06), and artifacts not scanned for malicious payloads.",
    inputSchema: modelSupplyChainSchema.shape,
    annotations: COMMON_ANNOTATIONS,
    handler: makeRunner(deps, zodParser(modelSupplyChainSchema), (d) => ({
      findings: auditModelSupplyChain(d),
    })),
  };
}

// ─── altais_check_owasp_ml ─────────────────────────────────────────────────

const owaspMlSchema = z.object({
  config: z
    .object({
      input_validation: boolOpt("Whether inference inputs are validated (ML01)."),
      data_validation: boolOpt("Whether training data is validated (ML02)."),
      inversion_defenses: boolOpt("Whether model-inversion defenses are applied (ML03)."),
      membership_inference_defenses: boolOpt(
        "Whether membership-inference defenses are applied (ML04).",
      ),
      model_theft_controls: boolOpt("Whether model-theft controls exist (ML05)."),
      supply_chain_verified: boolOpt("Whether the AI supply chain is verified (ML06)."),
      transfer_learning_reviewed: boolOpt("Whether transfer-learning risk is assessed (ML07)."),
      skewing_monitored: boolOpt("Whether model skewing is monitored (ML08)."),
      output_integrity_verified: boolOpt("Whether output integrity is verified (ML09)."),
      training_access_controlled: boolOpt(
        "Whether the training process is access-controlled (ML10).",
      ),
    })
    .strict()
    .optional()
    .describe("Controls in place, keyed to OWASP ML Top 10 categories."),
  filename: filenameField,
});

function buildOwaspMlTool(deps: MlSecurityModuleDeps): ToolDefinition {
  return {
    name: "altais_check_owasp_ml",
    title: "Check OWASP ML Security Top 10 coverage",
    description:
      "Check an ML system against the OWASP Machine Learning Security Top 10 (ML01 Input Manipulation, ML02 Data Poisoning, ML03 Model Inversion, ML04 Membership Inference, ML05 Model Theft, ML06 AI Supply Chain, ML07 Transfer Learning Attack, ML08 Model Skewing, ML09 Output Integrity, ML10 Model Poisoning). Returns per-category coverage status with detection hints and emits a finding for each category needing review.",
    inputSchema: owaspMlSchema.shape,
    annotations: COMMON_ANNOTATIONS,
    handler: makeRunner(deps, zodParser(owaspMlSchema), (d) => {
      const r = checkOwaspMl(d);
      return { findings: r.findings, extra: { categories: r.categories } };
    }),
  };
}

// ─── altais_check_llm_top10 ────────────────────────────────────────────────

const llmTop10Schema = z.object({
  source: sourceField,
  config: z
    .object({
      prompt_injection_defenses: boolOpt("Whether prompt-injection defenses exist (LLM01)."),
      output_pii_filtering: boolOpt("Whether output is filtered for sensitive data (LLM02)."),
      supply_chain_verified: boolOpt(
        "Whether the model / plugin supply chain is verified (LLM03).",
      ),
      data_validation: boolOpt("Whether training / RAG data is validated (LLM04)."),
      output_sanitization: boolOpt("Whether LLM output is sanitized downstream (LLM05)."),
      agency_limited: boolOpt("Whether agent agency is limited (LLM06)."),
      system_prompt_protected: boolOpt("Whether the system prompt is protected (LLM07)."),
      vector_store_secured: boolOpt("Whether the vector store / RAG inputs are secured (LLM08)."),
      grounding_enabled: boolOpt("Whether output is grounded to limit misinformation (LLM09)."),
      consumption_limited: boolOpt("Whether token / cost consumption is bounded (LLM10)."),
    })
    .strict()
    .optional()
    .describe("Controls in place, keyed to OWASP LLM Top 10 categories."),
  filename: filenameField,
});

function buildLlmTop10Tool(deps: MlSecurityModuleDeps): ToolDefinition {
  return {
    name: "altais_check_llm_top10",
    title: "Check OWASP LLM Top 10 coverage",
    description:
      "Audit an LLM application against the OWASP Top 10 for LLM Applications (2025): LLM01 Prompt Injection, LLM02 Sensitive Information Disclosure, LLM03 Supply Chain, LLM04 Data and Model Poisoning, LLM05 Improper Output Handling, LLM06 Excessive Agency, LLM07 System Prompt Leakage, LLM08 Vector and Embedding Weaknesses, LLM09 Misinformation, LLM10 Unbounded Consumption. Returns per-category coverage and emits findings for gaps.",
    inputSchema: llmTop10Schema.shape,
    annotations: COMMON_ANNOTATIONS,
    handler: makeRunner(deps, zodParser(llmTop10Schema), (d) => {
      const r = checkLlmTop10(d);
      return { findings: r.findings, extra: { categories: r.categories } };
    }),
  };
}

// ─── altais_audit_prompt_injection ─────────────────────────────────────────

const promptInjectionSchema = z.object({
  source: sourceField,
  config: z
    .object({
      instruction_data_separation: boolOpt(
        "Whether system instructions are separated from user data.",
      ),
      input_filtering: boolOpt("Whether user input is filtered before reaching the model."),
      output_validation: boolOpt("Whether model output is validated before being acted on."),
      tool_output_sanitized: boolOpt("Whether tool / retrieval output is sanitized."),
    })
    .strict()
    .optional()
    .describe("Structured description of the prompt-handling controls."),
  filename: filenameField,
});

function buildPromptInjectionTool(deps: MlSecurityModuleDeps): ToolDefinition {
  return {
    name: "altais_audit_prompt_injection",
    title: "Audit prompt handling for injection",
    description:
      "Analyze prompt construction for injection vulnerabilities (OWASP LLM01, CWE-1427): untrusted input concatenated or interpolated directly into a prompt string (f-strings, template literals, `+`), no separation of system instructions from user data, tool / retrieval output fed back to the model without sanitization, and missing input filtering or output validation.",
    inputSchema: promptInjectionSchema.shape,
    annotations: COMMON_ANNOTATIONS,
    handler: makeRunner(deps, zodParser(promptInjectionSchema), (d) => ({
      findings: auditPromptInjection(d),
    })),
  };
}

// ─── altais_audit_agent_permissions ────────────────────────────────────────

const agentPermissionsSchema = z.object({
  config: z
    .object({
      tools: z
        .array(
          z
            .object({
              name: z.string().min(1).max(128),
              scope: z.string().min(1).max(256).optional(),
            })
            .strict(),
        )
        .max(256)
        .optional()
        .describe("The agent's tools, each with a name and optional scope."),
      tool_count: z.number().int().min(0).max(100000).optional(),
      has_destructive_tools: boolOpt("Whether any tool performs destructive actions."),
      human_approval_required: boolOpt("Whether high-impact actions require human approval."),
      permission_scopes: z
        .array(z.string().min(1).max(256))
        .max(256)
        .optional()
        .describe("Permission scopes granted to the agent."),
      autonomous: boolOpt("Whether the agent runs fully autonomously."),
      can_spend_money: boolOpt("Whether the agent can spend money."),
      can_modify_data: boolOpt("Whether the agent can modify / delete data."),
      can_execute_code: boolOpt("Whether the agent can execute code."),
    })
    .strict()
    .describe("Structured description of the agent's tools and permissions."),
  filename: filenameField,
});

function buildAgentPermissionsTool(deps: MlSecurityModuleDeps): ToolDefinition {
  return {
    name: "altais_audit_agent_permissions",
    title: "Audit agent permissions for excessive agency",
    description:
      "Check an LLM agent for excessive agency (OWASP LLM06): too many tools / excessive functionality, broad or wildcard permission scopes, destructive or high-impact actions (spend money, modify data, execute code) with no human-in-the-loop approval (CWE-862 / CWE-269), and fully autonomous high-risk operation.",
    inputSchema: agentPermissionsSchema.shape,
    annotations: COMMON_ANNOTATIONS,
    handler: makeRunner(deps, zodParser(agentPermissionsSchema), (d) => ({
      findings: auditAgentPermissions(d),
    })),
  };
}

// ─── altais_audit_output_handling ──────────────────────────────────────────

const outputHandlingSchema = z.object({
  source: sourceField,
  config: z
    .object({
      html_encoded: boolOpt("Whether model output is HTML-encoded before rendering."),
      sql_parameterized: boolOpt("Whether model output reaching SQL is parameterized."),
      shell_safe: boolOpt("Whether model output is kept out of shell / exec calls."),
      schema_validated: boolOpt("Whether model output is validated against a schema."),
      treated_as_trusted: boolOpt("Whether model output is treated as trusted."),
    })
    .strict()
    .optional()
    .describe("Structured description of the output-handling controls."),
  filename: filenameField,
});

// Detection tokens loaded from data/scan-patterns.json so the literal API
// names are not embedded inline (see src/core/scan-patterns.ts).
const TOKEN_EVAL = scanToken("js-dynamic-code");
const TOKEN_FUNC = scanToken("js-function-constructor");
const TOKEN_EXEC = scanToken("shell-command");

function buildOutputHandlingTool(deps: MlSecurityModuleDeps): ToolDefinition {
  return {
    name: "altais_audit_output_handling",
    title: "Audit LLM output handling",
    description: `Verify LLM output is sanitized before downstream use (OWASP LLM05): model output passed unsanitized into HTML / the DOM (XSS — CWE-79), into SQL (CWE-89), into a shell / \`${TOKEN_EXEC}\` (command injection — CWE-78), into \`${TOKEN_EVAL}\` / \`${TOKEN_FUNC}\` (code injection — CWE-95), into a file path (path traversal — CWE-22), or returned to the user as trusted content.`,
    inputSchema: outputHandlingSchema.shape,
    annotations: COMMON_ANNOTATIONS,
    handler: makeRunner(deps, zodParser(outputHandlingSchema), (d) => ({
      findings: auditOutputHandling(d),
    })),
  };
}

export function createMlSecurityModule(deps: MlSecurityModuleDeps): ModuleDefinition {
  const tools: readonly ToolDefinition[] = [
    buildMlPipelineTool(deps),
    buildInferenceApiTool(deps),
    buildModelSupplyChainTool(deps),
    buildOwaspMlTool(deps),
    buildLlmTop10Tool(deps),
    buildPromptInjectionTool(deps),
    buildAgentPermissionsTool(deps),
    buildOutputHandlingTool(deps),
  ];
  return {
    name: "ml_security",
    description:
      "ML / LLM security audits: training-pipeline integrity (data poisoning, insecure model deserialization), inference-API hardening (model extraction, adversarial evasion), model supply-chain provenance, OWASP ML Top 10 and OWASP LLM Top 10 coverage, prompt-injection analysis, agent excessive-agency review, and LLM output-handling.",
    version: MODULE_VERSION,
    tools,
    init() {
      // No async resources to load.
    },
  };
}
