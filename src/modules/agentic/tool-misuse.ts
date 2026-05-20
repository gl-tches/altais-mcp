// ASI02 — Tool Misuse auditor (altais_audit_tool_misuse).
//
// Agents act through tools. Over-permissioned tool APIs, poisonable MCP
// tool descriptors, and unvalidated tool arguments turn a single
// compromised step into real-world impact.

import type { Finding } from "../../core/types.js";
import { buildAgenticFinding } from "./finding.js";

export interface ToolEntry {
  readonly name: string;
  readonly scope?: string;
}

export interface ToolMisuseConfig {
  /** Inventory of tools the agent can call. */
  readonly tools?: readonly ToolEntry[];
  /** Only an explicit allowlist of tools may be invoked. */
  readonly tool_allowlist?: boolean;
  /** MCP tool descriptors are verified against tampering / tool poisoning. */
  readonly tool_descriptors_verified?: boolean;
  /** One or more tool APIs hold broader permissions than the agent needs. */
  readonly over_permissioned_apis?: boolean;
  /** Tool arguments are schema-validated before invocation. */
  readonly input_validation_on_tool_args?: boolean;
  /** Tool output is validated before the agent consumes it. */
  readonly tool_output_validation?: boolean;
  /** Tool invocations are rate-limited. */
  readonly rate_limited?: boolean;
}

export interface ToolMisuseAuditInput {
  readonly config?: ToolMisuseConfig;
  readonly source?: string;
  readonly filename?: string;
}

const REFS = [
  "https://genai.owasp.org/resource/agentic-ai-threats-and-mitigations/",
  "https://owasp.org/www-project-top-10-for-large-language-model-applications/",
  "https://cwe.mitre.org/data/definitions/269.html",
];

export function auditToolMisuse(input: ToolMisuseAuditInput): readonly Finding[] {
  const findings: Finding[] = [];
  const file = input.filename;
  const c = input.config;
  if (c === undefined) return findings;

  if (c.over_permissioned_apis === true) {
    findings.push(
      buildAgenticFinding(
        {
          rule: "tool-over-permissioned-apis",
          severity: "high",
          title: "ASI02: Tool APIs grant broader permissions than the agent needs",
          description:
            "An over-permissioned tool credential lets a misused or hijacked tool call reach resources beyond the agent's task, widening the blast radius (ASI02 Tool Misuse).",
          remediation:
            "Scope each tool credential to the minimum capability required (least privilege); split broad APIs into narrow, purpose-specific tools.",
          cwe: ["CWE-269", "CWE-20"],
          references: REFS,
          evidence: "over_permissioned_apis=true",
          tags: ["ASI02", "tool-misuse"],
        },
        file,
      ),
    );
  }

  if (c.tool_descriptors_verified === false) {
    findings.push(
      buildAgenticFinding(
        {
          rule: "tool-descriptors-unverified",
          severity: "high",
          title: "ASI02: MCP tool descriptors are not verified (tool-poisoning risk)",
          description:
            "If tool names, descriptions, and schemas are not verified, a malicious MCP server can poison a descriptor with hidden instructions, causing the agent to misuse the tool (ASI02 Tool Misuse).",
          remediation:
            "Verify tool descriptors against a signed, pinned source; alert on descriptor changes and treat tool descriptions as untrusted content.",
          cwe: ["CWE-269", "CWE-20"],
          references: REFS,
          evidence: "tool_descriptors_verified=false",
          tags: ["ASI02", "tool-misuse"],
        },
        file,
      ),
    );
  }

  if (c.tool_allowlist === false) {
    findings.push(
      buildAgenticFinding(
        {
          rule: "tool-no-allowlist",
          severity: "medium",
          title: "ASI02: No allowlist constrains which tools the agent may call",
          description:
            "Without an allowlist, a hijacked agent can reach any registered or discoverable tool, including dangerous ones outside its task scope (ASI02 Tool Misuse).",
          remediation:
            "Maintain a per-agent allowlist of permitted tools; deny by default and require explicit grant for new tools.",
          cwe: ["CWE-269"],
          references: REFS,
          evidence: "tool_allowlist=false",
          tags: ["ASI02", "tool-misuse"],
        },
        file,
      ),
    );
  }

  if (c.input_validation_on_tool_args === false) {
    findings.push(
      buildAgenticFinding(
        {
          rule: "tool-args-not-validated",
          severity: "high",
          title: "ASI02: Tool arguments are not validated before invocation",
          description:
            "Model-generated tool arguments are attacker-influenceable. Passing them to a tool unvalidated enables injection, path traversal, and out-of-scope operations (ASI02 Tool Misuse).",
          remediation:
            "Schema-validate every tool argument with explicit constraints (types, ranges, allowed values) before the tool runs.",
          cwe: ["CWE-20", "CWE-269"],
          references: REFS,
          evidence: "input_validation_on_tool_args=false",
          tags: ["ASI02", "tool-misuse"],
        },
        file,
      ),
    );
  }

  if (c.tool_output_validation === false) {
    findings.push(
      buildAgenticFinding(
        {
          rule: "tool-output-not-validated",
          severity: "medium",
          title: "ASI02: Tool output is consumed without validation",
          description:
            "Unvalidated tool output can carry malformed data or embedded instructions that mislead the agent into further misuse (ASI02 Tool Misuse).",
          remediation:
            "Validate and schema-check tool output before the agent acts on it; treat it as untrusted.",
          cwe: ["CWE-20"],
          references: REFS,
          evidence: "tool_output_validation=false",
          tags: ["ASI02", "tool-misuse"],
        },
        file,
      ),
    );
  }

  if (c.rate_limited === false) {
    findings.push(
      buildAgenticFinding(
        {
          rule: "tool-not-rate-limited",
          severity: "medium",
          title: "ASI02: Tool invocations are not rate-limited",
          description:
            "Unbounded tool invocation lets a misused agent amplify impact (mass actions, resource exhaustion) before anyone can intervene (ASI02 Tool Misuse).",
          remediation:
            "Apply per-tool and per-agent rate limits and budgets; alert when an agent approaches them.",
          cwe: ["CWE-269"],
          references: REFS,
          evidence: "rate_limited=false",
          tags: ["ASI02", "tool-misuse"],
        },
        file,
      ),
    );
  }

  for (const tool of c.tools ?? []) {
    const scope = (tool.scope ?? "").toLowerCase().trim();
    if (scope === "*" || scope === "all" || scope === "admin" || scope === "full") {
      findings.push(
        buildAgenticFinding(
          {
            rule: "tool-wildcard-scope",
            severity: "high",
            title: `ASI02: Tool "${tool.name}" has an unrestricted scope`,
            description:
              "A tool registered with a wildcard or admin scope grants the agent far more capability than any single task needs, maximizing the impact of misuse (ASI02 Tool Misuse).",
            remediation: `Replace the broad scope on "${tool.name}" with the narrowest capability the task requires.`,
            cwe: ["CWE-269"],
            references: REFS,
            evidence: `${tool.name}: scope=${tool.scope ?? ""}`,
            tags: ["ASI02", "tool-misuse"],
          },
          file,
        ),
      );
    }
  }

  return findings;
}
