// Agentic module: 10 auditors for AI-agent / MCP-server architectures
// against the OWASP Agentic Applications Security Top 10 (2026),
// categories ASI01–ASI10 — goal hijacking, tool misuse, identity &
// privilege abuse, agentic supply chain, code execution, memory
// poisoning, inter-agent communication, cascading failures, human-agent
// trust exploitation, and rogue agents.

import { z } from "zod";
import type { CallToolResult } from "@modelcontextprotocol/sdk/types.js";

import type { FindingStore } from "../../core/report.js";
import type { Finding, ModuleDefinition, ToolDefinition } from "../../core/types.js";
import { auditAgentIdentity } from "./agent-identity.js";
import { auditCascadingFailures } from "./cascading.js";
import { auditCodeExecution } from "./code-execution.js";
import { auditGoalHijack } from "./goal-hijack.js";
import { auditInterAgentComms } from "./inter-agent.js";
import { auditMemoryPoisoning } from "./memory-poisoning.js";
import { auditRogueAgents } from "./rogue-agents.js";
import { auditAgenticSupplyChain } from "./supply-chain.js";
import { auditToolMisuse } from "./tool-misuse.js";
import { auditTrustExploitation } from "./trust-exploitation.js";

const MODULE_VERSION = "0.5.0";

const COMMON_ANNOTATIONS = {
  readOnlyHint: true,
  destructiveHint: false,
  idempotentHint: true,
  openWorldHint: false,
} as const;

export interface AgenticModuleDeps {
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

function withSummary(findings: readonly Finding[]): unknown {
  return { summary: summarize(findings), findings };
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
  deps: AgenticModuleDeps,
  parser: (args: unknown) => { success: true; data: TInput } | { success: false; message: string },
  run: (data: TInput) => readonly Finding[],
): (args: unknown) => CallToolResult {
  return (args: unknown) => {
    const parsed = parser(args);
    if (!parsed.success) return errorResult(`Invalid input: ${parsed.message}`);
    const findings = run(parsed.data);
    deps.findingStore.addMany(findings);
    return textResult(jsonText(withSummary(findings)));
  };
}

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
  .describe("Optional source code describing the agent system, scanned with pattern checks.");

const flag = (desc: string): z.ZodOptional<z.ZodBoolean> => z.boolean().optional().describe(desc);

// ─── altais_audit_goal_hijack (ASI01) ──────────────────────────────────────

const goalHijackSchema = z.object({
  source: sourceField,
  filename: filenameField,
  config: z
    .object({
      instruction_data_separation: flag(
        "Trusted instructions are structurally separated from untrusted data.",
      ),
      goal_validation: flag("The agent validates its goal / plan before acting."),
      untrusted_tool_output_to_planner: flag(
        "Tool / retrieval output is fed to the planner without validation.",
      ),
      untrusted_data_to_planner: flag(
        "Untrusted external data is fed to the planner without validation.",
      ),
      system_prompt_protected: flag("The system prompt is protected from runtime override."),
      plan_review: flag("A human or policy reviews the plan before high-impact execution."),
    })
    .optional(),
});

function buildGoalHijackTool(deps: AgenticModuleDeps): ToolDefinition {
  return {
    name: "altais_audit_goal_hijack",
    title: "Audit agent goal hijacking (ASI01)",
    description:
      "Audit an agent system against OWASP ASI01 (Agent Goal Hijacking): flags missing separation of trusted instructions from untrusted data, tool / retrieval output feeding the planner without validation, no goal or plan validation, an unprotected system prompt, and no plan review.",
    inputSchema: goalHijackSchema.shape,
    annotations: COMMON_ANNOTATIONS,
    handler: makeRunner(deps, zodParser(goalHijackSchema), (d) => auditGoalHijack(d)),
  };
}

// ─── altais_audit_tool_misuse (ASI02) ──────────────────────────────────────

const toolMisuseSchema = z.object({
  source: sourceField,
  filename: filenameField,
  config: z
    .object({
      tools: z
        .array(
          z.object({
            name: z.string().min(1).max(256),
            scope: z.string().min(1).max(256).optional(),
          }),
        )
        .max(512)
        .optional(),
      tool_allowlist: flag("Only an explicit allowlist of tools may be invoked."),
      tool_descriptors_verified: flag(
        "MCP tool descriptors are verified against tampering / tool poisoning.",
      ),
      over_permissioned_apis: flag("One or more tool APIs hold broader permissions than needed."),
      input_validation_on_tool_args: flag("Tool arguments are schema-validated before invocation."),
      tool_output_validation: flag("Tool output is validated before the agent consumes it."),
      rate_limited: flag("Tool invocations are rate-limited."),
    })
    .optional(),
});

function buildToolMisuseTool(deps: AgenticModuleDeps): ToolDefinition {
  return {
    name: "altais_audit_tool_misuse",
    title: "Audit tool integration misuse (ASI02)",
    description:
      "Audit an agent system against OWASP ASI02 (Tool Misuse): flags over-permissioned tool APIs, unverified / poisonable MCP tool descriptors, missing tool allowlist, unvalidated tool arguments, missing tool-output validation, no rate limiting, and tools registered with wildcard / admin scope.",
    inputSchema: toolMisuseSchema.shape,
    annotations: COMMON_ANNOTATIONS,
    handler: makeRunner(deps, zodParser(toolMisuseSchema), (d) => auditToolMisuse(d)),
  };
}

// ─── altais_audit_agent_identity (ASI03) ───────────────────────────────────

const agentIdentitySchema = z.object({
  source: sourceField,
  filename: filenameField,
  config: z
    .object({
      per_agent_identity: flag("Each agent runs under its own distinct identity."),
      privilege_inheritance: flag("Agents inherit the privileges of the caller / parent."),
      can_escalate_privileges: flag("An agent can escalate its own privileges at runtime."),
      confused_deputy_protection: flag(
        "Confused-deputy protection (the caller's authority is checked).",
      ),
      cross_session_credential_retention: flag("Credentials are retained across sessions."),
      scoped_credentials: flag("Credentials issued to the agent are narrowly scoped."),
      human_user_distinct_from_agent: flag(
        "The human user's identity is kept distinct from the agent's.",
      ),
    })
    .optional(),
});

function buildAgentIdentityTool(deps: AgenticModuleDeps): ToolDefinition {
  return {
    name: "altais_audit_agent_identity",
    title: "Audit agent identity and privilege model (ASI03)",
    description:
      "Audit an agent system against OWASP ASI03 (Identity & Privilege Abuse): flags shared / inherited identity, runtime privilege-escalation paths, missing confused-deputy protection, cross-session credential retention, unscoped credentials, and conflation of the user's identity with the agent's.",
    inputSchema: agentIdentitySchema.shape,
    annotations: COMMON_ANNOTATIONS,
    handler: makeRunner(deps, zodParser(agentIdentitySchema), (d) => auditAgentIdentity(d)),
  };
}

// ─── altais_audit_agentic_supply_chain (ASI04) ─────────────────────────────

const supplyChainSchema = z.object({
  source: sourceField,
  filename: filenameField,
  config: z
    .object({
      mcp_servers: z
        .array(
          z.object({
            name: z.string().min(1).max(256),
            source: z.string().min(1).max(256).optional(),
          }),
        )
        .max(512)
        .optional(),
      manifests_signed: flag("MCP / plugin manifests are cryptographically signed and verified."),
      plugins_verified: flag("Plugins are verified before loading."),
      agent_cards_verified: flag("Agent cards (A2A / discovery metadata) are verified."),
      registry_pinned: flag("Tool / server registries are pinned to specific versions."),
      typosquat_checked: flag("Component names are checked against typosquatting."),
      provenance_attestation: flag("Provenance attestation is required for components."),
    })
    .optional(),
});

function buildSupplyChainTool(deps: AgenticModuleDeps): ToolDefinition {
  return {
    name: "altais_audit_agentic_supply_chain",
    title: "Audit the agentic supply chain (ASI04)",
    description:
      "Audit an agent system against OWASP ASI04 (Agentic Supply Chain): flags unsigned manifests, unverified plugins, unverified agent cards, unpinned tool / server registries, no typosquat check, missing provenance attestation, and MCP servers from untrusted sources.",
    inputSchema: supplyChainSchema.shape,
    annotations: COMMON_ANNOTATIONS,
    handler: makeRunner(deps, zodParser(supplyChainSchema), (d) => auditAgenticSupplyChain(d)),
  };
}

// ─── altais_audit_code_execution (ASI05) ───────────────────────────────────

const codeExecutionSchema = z.object({
  source: sourceField,
  filename: filenameField,
  config: z
    .object({
      executes_generated_code: flag("The agent executes code it (or a model) generated."),
      sandboxed: flag("Generated code runs inside a sandbox."),
      sandbox_type: z
        .enum(["none", "process", "container", "microvm", "wasm", "gvisor", "firecracker"])
        .optional()
        .describe("The sandbox technology in use."),
      allowlist_enforced: flag("Only an allowlist of operations / modules is permitted."),
      network_access_in_sandbox: flag("The sandbox has network access."),
      filesystem_access_in_sandbox: flag("The sandbox has host filesystem access."),
      resource_limits: flag("CPU / memory / time resource limits are enforced on the sandbox."),
    })
    .optional(),
});

function buildCodeExecutionTool(deps: AgenticModuleDeps): ToolDefinition {
  return {
    name: "altais_audit_code_execution",
    title: "Audit agent code execution (ASI05)",
    description:
      "Audit an agent system against OWASP ASI05 (Code Execution): flags execution of generated code with no sandbox, a sandbox with network or host filesystem access, no operation allowlist, and missing resource limits. Scans `source` for `eval` / `exec` / `Function` / `child_process` on a line that references a model / LLM output variable.",
    inputSchema: codeExecutionSchema.shape,
    annotations: COMMON_ANNOTATIONS,
    handler: makeRunner(deps, zodParser(codeExecutionSchema), (d) => auditCodeExecution(d)),
  };
}

// ─── altais_audit_memory_poisoning (ASI06) ─────────────────────────────────

const memoryPoisoningSchema = z.object({
  source: sourceField,
  filename: filenameField,
  config: z
    .object({
      memory_validation: flag("Content is validated before it is written to memory."),
      memory_isolation_per_user: flag("Memory is isolated per user / tenant."),
      rag_source_trust_verified: flag("The trust of RAG / retrieval sources is verified."),
      shared_state_between_agents: flag("Mutable state is shared between agents."),
      memory_provenance: flag("Memory entries carry provenance metadata."),
      untrusted_content_persisted: flag(
        "Untrusted external content is persisted into long-term memory.",
      ),
    })
    .optional(),
});

function buildMemoryPoisoningTool(deps: AgenticModuleDeps): ToolDefinition {
  return {
    name: "altais_audit_memory_poisoning",
    title: "Audit context and memory poisoning (ASI06)",
    description:
      "Audit an agent system against OWASP ASI06 (Memory Poisoning): flags missing memory validation, cross-user memory bleed, untrusted RAG sources, persisted untrusted content, shared mutable state between agents, and memory entries without provenance.",
    inputSchema: memoryPoisoningSchema.shape,
    annotations: COMMON_ANNOTATIONS,
    handler: makeRunner(deps, zodParser(memoryPoisoningSchema), (d) => auditMemoryPoisoning(d)),
  };
}

// ─── altais_audit_inter_agent_comms (ASI07) ────────────────────────────────

const interAgentSchema = z.object({
  source: sourceField,
  filename: filenameField,
  config: z
    .object({
      message_authentication: flag("A2A messages are authenticated (sender identity verified)."),
      message_integrity: flag("Message integrity is protected (tamper-evident)."),
      origin_validation: flag("The origin of each message is validated."),
      encrypted_channel: flag("The A2A channel is encrypted."),
      message_signing: flag("Messages are cryptographically signed."),
      replay_protection: flag("Replay protection (nonces / timestamps) is in place."),
    })
    .optional(),
});

function buildInterAgentTool(deps: AgenticModuleDeps): ToolDefinition {
  return {
    name: "altais_audit_inter_agent_comms",
    title: "Audit inter-agent communication (ASI07)",
    description:
      "Audit an agent system against OWASP ASI07 (Insecure Inter-Agent Communication): flags unauthenticated agent-to-agent messages, missing integrity protection or signing, no origin validation, a cleartext channel, and missing replay protection.",
    inputSchema: interAgentSchema.shape,
    annotations: COMMON_ANNOTATIONS,
    handler: makeRunner(deps, zodParser(interAgentSchema), (d) => auditInterAgentComms(d)),
  };
}

// ─── altais_audit_cascading_failures (ASI08) ───────────────────────────────

const cascadingSchema = z.object({
  source: sourceField,
  filename: filenameField,
  config: z
    .object({
      kill_switch: flag("A kill switch can halt agents on demand."),
      circuit_breakers: flag("Circuit breakers cut off failing dependencies."),
      blast_radius_limits: flag("The blast radius of any single agent is bounded."),
      agent_isolation: flag("Agents are isolated from one another."),
      failure_detection: flag("Failures are detected and surfaced."),
      rate_limits_between_agents: flag("Rate limits apply to agent-to-agent calls."),
      max_agent_chain_depth: z
        .number()
        .int()
        .min(1)
        .max(10000)
        .optional()
        .describe("The maximum agent-chain / delegation depth, if configured."),
    })
    .optional(),
});

function buildCascadingTool(deps: AgenticModuleDeps): ToolDefinition {
  return {
    name: "altais_audit_cascading_failures",
    title: "Audit cascading failures (ASI08)",
    description:
      "Audit a multi-agent system against OWASP ASI08 (Cascading Failures): flags a missing kill switch, missing circuit breakers, unbounded blast radius, no agent isolation, no failure detection, no inter-agent rate limits, and a missing or excessively high agent-chain depth limit.",
    inputSchema: cascadingSchema.shape,
    annotations: COMMON_ANNOTATIONS,
    handler: makeRunner(deps, zodParser(cascadingSchema), (d) => auditCascadingFailures(d)),
  };
}

// ─── altais_audit_trust_exploitation (ASI09) ───────────────────────────────

const trustExploitationSchema = z.object({
  source: sourceField,
  filename: filenameField,
  config: z
    .object({
      consent_separation: flag("Consent UI is independent of any agent-controlled surface."),
      approval_flow_independent: flag("The approval flow runs on an independent, trusted channel."),
      action_attribution_clear: flag(
        "Each action is clearly attributed to the agent vs. the user.",
      ),
      high_risk_actions_need_confirmation: flag(
        "High-risk actions require an explicit user confirmation.",
      ),
      agent_cannot_render_own_approval_ui: flag("The agent cannot render its own approval UI."),
      deceptive_output_controls: flag(
        "Controls exist against deceptive / manipulative agent output.",
      ),
    })
    .optional(),
});

function buildTrustExploitationTool(deps: AgenticModuleDeps): ToolDefinition {
  return {
    name: "altais_audit_trust_exploitation",
    title: "Audit human-agent trust exploitation (ASI09)",
    description:
      "Audit an agent system against OWASP ASI09 (Human-Agent Trust Exploitation): flags consent / approval flows rendered by the agent-controlled surface, non-independent approval channels, high-risk actions without independent confirmation, unclear action attribution, and no controls against deceptive output.",
    inputSchema: trustExploitationSchema.shape,
    annotations: COMMON_ANNOTATIONS,
    handler: makeRunner(deps, zodParser(trustExploitationSchema), (d) => auditTrustExploitation(d)),
  };
}

// ─── altais_audit_rogue_agents (ASI10) ─────────────────────────────────────

const rogueAgentsSchema = z.object({
  source: sourceField,
  filename: filenameField,
  config: z
    .object({
      behavioral_baseline: flag("A behavioral baseline exists for normal agent activity."),
      anomaly_detection: flag("Anomaly detection runs against agent behavior."),
      anomaly_detection_coverage: z
        .enum(["none", "partial", "comprehensive"])
        .optional()
        .describe("Coverage of anomaly detection across agents / actions."),
      agent_inventory: flag("A complete inventory of agents is maintained."),
      agent_governance_policy: flag("An agent governance policy is defined and enforced."),
      sandboxing: flag("Agents run in a sandbox."),
      audit_logging: flag("Agent actions are recorded in an audit log."),
      revocation_capability: flag("A rogue agent can be revoked / killed."),
    })
    .optional(),
});

function buildRogueAgentsTool(deps: AgenticModuleDeps): ToolDefinition {
  return {
    name: "altais_audit_rogue_agents",
    title: "Audit rogue-agent detection and governance (ASI10)",
    description:
      "Audit an agent system against OWASP ASI10 (Rogue Agents): flags a missing behavioral baseline, missing or partial anomaly detection, no agent inventory or governance policy, no sandboxing, no audit logging, and no revocation / kill capability.",
    inputSchema: rogueAgentsSchema.shape,
    annotations: COMMON_ANNOTATIONS,
    handler: makeRunner(deps, zodParser(rogueAgentsSchema), (d) => auditRogueAgents(d)),
  };
}

export function createAgenticModule(deps: AgenticModuleDeps): ModuleDefinition {
  const tools: readonly ToolDefinition[] = [
    buildGoalHijackTool(deps),
    buildToolMisuseTool(deps),
    buildAgentIdentityTool(deps),
    buildSupplyChainTool(deps),
    buildCodeExecutionTool(deps),
    buildMemoryPoisoningTool(deps),
    buildInterAgentTool(deps),
    buildCascadingTool(deps),
    buildTrustExploitationTool(deps),
    buildRogueAgentsTool(deps),
  ];
  return {
    name: "agentic",
    description:
      "Agentic audits against the OWASP Agentic Applications Security Top 10 (2026), ASI01–ASI10: goal hijacking, tool misuse, identity & privilege abuse, agentic supply chain, code execution, memory poisoning, inter-agent communication, cascading failures, human-agent trust exploitation, and rogue agents.",
    version: MODULE_VERSION,
    tools,
    init() {
      // No async resources to load.
    },
  };
}
