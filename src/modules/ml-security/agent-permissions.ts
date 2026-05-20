// Agent-permissions auditor (altais_audit_agent_permissions).
//
// Checks an LLM agent's tool surface for excessive agency (OWASP LLM06):
// too many tools, broad / wildcard permission scopes, destructive or
// high-impact actions without a human-in-the-loop gate, and fully
// autonomous high-risk operation.

import type { Finding } from "../../core/types.js";
import { buildMlSecurityFinding } from "./finding.js";

export interface AgentToolSpec {
  /** Tool name. */
  readonly name: string;
  /** Optional scope / permission string for the tool. */
  readonly scope?: string;
}

export interface AgentPermissionsConfig {
  /** The agent's tools, each with a name and optional scope. */
  readonly tools?: readonly AgentToolSpec[];
  /** Total tool count (used when individual tools are not enumerated). */
  readonly tool_count?: number;
  /** Whether any tool performs destructive actions (delete, send, pay). */
  readonly has_destructive_tools?: boolean;
  /** Whether high-impact actions require human approval. */
  readonly human_approval_required?: boolean;
  /** The permission scopes granted to the agent. */
  readonly permission_scopes?: readonly string[];
  /** Whether the agent runs fully autonomously (no human in the loop). */
  readonly autonomous?: boolean;
  /** Whether the agent can spend money. */
  readonly can_spend_money?: boolean;
  /** Whether the agent can modify / delete data. */
  readonly can_modify_data?: boolean;
  /** Whether the agent can execute code. */
  readonly can_execute_code?: boolean;
}

export interface AgentPermissionsInput {
  readonly config: AgentPermissionsConfig;
  readonly filename?: string;
}

const REFS = [
  "https://genai.owasp.org/llmrisk/llm062025-excessive-agency/",
  "https://owasp.org/www-project-top-10-for-large-language-model-applications/",
  "https://cwe.mitre.org/data/definitions/269.html",
];

/** Above this tool count, the agent's functionality is considered excessive. */
const EXCESSIVE_TOOL_COUNT = 15;
/** A scope token that grants broad / unbounded access. */
const BROAD_SCOPE_RE =
  /(?:^|[\s,:])(?:\*|all|admin|full|write:\*|.*:\*|root|superuser)(?:$|[\s,])/i;

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

export function auditAgentPermissions(input: AgentPermissionsInput): readonly Finding[] {
  const c = input.config;
  const findings: Finding[] = [];

  const tools = c.tools ?? [];
  const toolCount = c.tool_count ?? tools.length;

  if (toolCount > EXCESSIVE_TOOL_COUNT) {
    findings.push(
      mk(
        "agent-excessive-tool-count",
        "medium",
        `Agent has an excessive number of tools (${toolCount})`,
        "A large tool surface gives the agent more functionality than any single task needs. Each extra tool widens the blast radius of a prompt injection or model error (OWASP LLM06 Excessive Functionality).",
        `Limit the agent to the minimum set of tools required for its task; gate optional tools behind explicit, per-task enablement. Current count is ${toolCount}, recommended ceiling is ${EXCESSIVE_TOOL_COUNT}.`,
        ["CWE-272"],
        `tool_count=${toolCount}`,
        input.filename,
        ["excessive-agency"],
      ),
    );
  }

  // Broad scopes on individual tools.
  for (const tool of tools) {
    if (tool.scope !== undefined && BROAD_SCOPE_RE.test(tool.scope)) {
      findings.push(
        mk(
          "agent-broad-tool-scope",
          "high",
          `Tool \`${tool.name}\` is granted a broad / wildcard scope`,
          "A wildcard or admin-level scope grants the tool far more permission than the agent's task requires. A hijacked agent inherits that full authority (OWASP LLM06 Excessive Permissions, CWE-269).",
          "Replace the wildcard scope with the narrowest concrete permissions the tool needs; never grant `*` / admin scopes to an agent tool.",
          ["CWE-269", "CWE-862"],
          `${tool.name}: scope=${tool.scope}`,
          input.filename,
          ["excessive-agency"],
        ),
      );
    }
  }

  // Broad scopes in the agent-level scope list.
  for (const scope of c.permission_scopes ?? []) {
    if (BROAD_SCOPE_RE.test(scope)) {
      findings.push(
        mk(
          "agent-broad-permission-scope",
          "high",
          `Agent is granted a broad / wildcard permission scope: \`${scope}\``,
          "A wildcard or admin permission scope on the agent itself means every tool call runs with excessive authority. The least-privilege principle is violated (OWASP LLM06, CWE-269).",
          "Grant the agent only the specific, scoped permissions its tools require; remove `*` / `admin` / `full` scopes.",
          ["CWE-269", "CWE-862"],
          `scope=${scope}`,
          input.filename,
          ["excessive-agency"],
        ),
      );
    }
  }

  const noHumanGate = c.human_approval_required !== true;

  if (c.has_destructive_tools === true && noHumanGate) {
    findings.push(
      mk(
        "agent-destructive-tools-no-approval",
        "high",
        "Agent has destructive tools but no human-approval gate",
        "Destructive tools (delete, send, transfer) executed without human approval let a prompt injection or model mistake cause irreversible damage (OWASP LLM06, CWE-862).",
        "Require explicit human-in-the-loop approval before any destructive action; default to dry-run / preview where possible.",
        ["CWE-862", "CWE-269"],
        "has_destructive_tools=true, human_approval_required=false",
        input.filename,
        ["excessive-agency", "human-in-the-loop"],
      ),
    );
  }

  if (c.can_spend_money === true && noHumanGate) {
    findings.push(
      mk(
        "agent-can-spend-money-no-approval",
        "high",
        "Agent can spend money without human approval",
        "An agent able to make purchases or payments with no approval step turns a successful injection into direct financial loss (OWASP LLM06).",
        "Require human approval for any spend, and enforce hard spending caps outside the model.",
        ["CWE-862", "CWE-269"],
        "can_spend_money=true, human_approval_required=false",
        input.filename,
        ["excessive-agency", "human-in-the-loop"],
      ),
    );
  }

  if (c.can_modify_data === true && noHumanGate) {
    findings.push(
      mk(
        "agent-can-modify-data-no-approval",
        "medium",
        "Agent can modify or delete data without human approval",
        "Data-modifying actions performed autonomously let an injected or hallucinated instruction corrupt or destroy records (OWASP LLM06).",
        "Gate write / delete actions behind human approval, scope them to specific records, and keep an audit trail with rollback.",
        ["CWE-862"],
        "can_modify_data=true, human_approval_required=false",
        input.filename,
        ["excessive-agency"],
      ),
    );
  }

  if (c.can_execute_code === true) {
    findings.push(
      mk(
        "agent-can-execute-code",
        c.autonomous === true || noHumanGate ? "high" : "medium",
        "Agent can execute code",
        "Code execution is the highest-impact tool an agent can hold: a successful injection becomes arbitrary code execution. Without sandboxing and approval the blast radius is the whole host (OWASP LLM06).",
        "Run agent-generated code in a strict sandbox, require human approval, and restrict it to a minimal, audited environment — or remove the capability.",
        ["CWE-94", "CWE-269"],
        `can_execute_code=true, autonomous=${c.autonomous ?? false}`,
        input.filename,
        ["excessive-agency"],
      ),
    );
  }

  if (
    c.autonomous === true &&
    (c.has_destructive_tools === true ||
      c.can_spend_money === true ||
      c.can_modify_data === true ||
      c.can_execute_code === true)
  ) {
    findings.push(
      mk(
        "agent-fully-autonomous-high-risk",
        "high",
        "Agent runs fully autonomously while holding high-impact capabilities",
        "A fully autonomous agent with destructive, financial, data-modifying, or code-execution capability has no human checkpoint between an injected instruction and an irreversible action (OWASP LLM06 Excessive Autonomy).",
        "Insert a human-in-the-loop checkpoint before high-impact actions, or reduce the agent's capabilities so full autonomy is low-risk.",
        ["CWE-269", "CWE-862"],
        "autonomous=true with high-impact capabilities",
        input.filename,
        ["excessive-agency", "autonomy"],
      ),
    );
  }

  return findings;
}
