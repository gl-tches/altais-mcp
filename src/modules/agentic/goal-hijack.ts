// ASI01 — Agent Goal Hijacking auditor (altais_audit_goal_hijack).
//
// Goal hijacking is the agentic-systems analogue of prompt injection: an
// attacker manipulates the agent's objective by smuggling instructions
// through untrusted data or tool/retrieval output that the planner treats
// as authoritative.

import type { Finding } from "../../core/types.js";
import { buildAgenticFinding } from "./finding.js";

export interface GoalHijackConfig {
  /** Trusted instructions are structurally separated from untrusted data. */
  readonly instruction_data_separation?: boolean;
  /** The agent validates its goal / plan before acting on it. */
  readonly goal_validation?: boolean;
  /** Tool / retrieval output is fed to the planner without validation. */
  readonly untrusted_tool_output_to_planner?: boolean;
  /** Untrusted external data is fed to the planner without validation. */
  readonly untrusted_data_to_planner?: boolean;
  /** The system prompt is protected from being overridden at runtime. */
  readonly system_prompt_protected?: boolean;
  /** A human or policy reviews the plan before high-impact execution. */
  readonly plan_review?: boolean;
}

export interface GoalHijackAuditInput {
  readonly config?: GoalHijackConfig;
  readonly source?: string;
  readonly filename?: string;
}

const REFS = [
  "https://genai.owasp.org/resource/agentic-ai-threats-and-mitigations/",
  "https://owasp.org/www-project-top-10-for-large-language-model-applications/",
  "https://cwe.mitre.org/data/definitions/1427.html",
];

export function auditGoalHijack(input: GoalHijackAuditInput): readonly Finding[] {
  const findings: Finding[] = [];
  const file = input.filename;
  const c = input.config;
  if (c === undefined) return findings;

  if (c.instruction_data_separation === false) {
    findings.push(
      buildAgenticFinding(
        {
          rule: "goal-no-instruction-data-separation",
          severity: "high",
          title: "ASI01: No separation of trusted instructions from untrusted data",
          description:
            "When system instructions and untrusted input share the same channel, an attacker who controls any input can inject text the agent interprets as a directive, redirecting its goal (ASI01 Agent Goal Hijacking).",
          remediation:
            "Keep the system prompt and trusted policy in a privileged channel; pass untrusted data only as clearly delimited, non-authoritative content (e.g. structured fields the model is told never to obey).",
          cwe: ["CWE-1427", "CWE-77"],
          references: REFS,
          evidence: "instruction_data_separation=false",
          tags: ["ASI01", "goal-hijack"],
        },
        file,
      ),
    );
  }

  if (c.untrusted_tool_output_to_planner === true) {
    findings.push(
      buildAgenticFinding(
        {
          rule: "goal-untrusted-tool-output-to-planner",
          severity: "high",
          title: "ASI01: Tool output reaches the planner without validation",
          description:
            "Tool results are attacker-influenceable. Feeding raw tool output back into the planning loop lets a poisoned response rewrite the agent's objective or next action (ASI01 Agent Goal Hijacking).",
          remediation:
            "Treat tool output as untrusted data: validate, schema-check, and label it before it re-enters the planner; never let it set or override the goal.",
          cwe: ["CWE-1427", "CWE-77"],
          references: REFS,
          evidence: "untrusted_tool_output_to_planner=true",
          tags: ["ASI01", "goal-hijack"],
        },
        file,
      ),
    );
  }

  if (c.untrusted_data_to_planner === true) {
    findings.push(
      buildAgenticFinding(
        {
          rule: "goal-untrusted-data-to-planner",
          severity: "high",
          title: "ASI01: Untrusted external data reaches the planner without validation",
          description:
            "Retrieved documents, web pages, and user content can carry embedded instructions. Routing them into the planner unvalidated enables indirect prompt injection that hijacks the agent's goal (ASI01).",
          remediation:
            "Sanitize and structurally delimit untrusted data; instruct the planner to treat it strictly as information, and validate any goal change against the original task.",
          cwe: ["CWE-1427", "CWE-77"],
          references: REFS,
          evidence: "untrusted_data_to_planner=true",
          tags: ["ASI01", "goal-hijack"],
        },
        file,
      ),
    );
  }

  if (c.goal_validation === false) {
    findings.push(
      buildAgenticFinding(
        {
          rule: "goal-no-goal-validation",
          severity: "medium",
          title: "ASI01: The agent does not validate its goal before acting",
          description:
            "Without a check that the current objective still matches the originally authorized task, a hijacked goal proceeds undetected (ASI01 Agent Goal Hijacking).",
          remediation:
            "Pin the authorized task at the start of a run and validate every derived goal / plan step against it; halt and escalate on divergence.",
          cwe: ["CWE-1427"],
          references: REFS,
          evidence: "goal_validation=false",
          tags: ["ASI01", "goal-hijack"],
        },
        file,
      ),
    );
  }

  if (c.system_prompt_protected === false) {
    findings.push(
      buildAgenticFinding(
        {
          rule: "goal-system-prompt-unprotected",
          severity: "medium",
          title: "ASI01: The system prompt is not protected from runtime override",
          description:
            "If untrusted input can append to, replace, or out-prioritize the system prompt, an attacker can install new objectives for the agent (ASI01).",
          remediation:
            "Render the system prompt in a privileged, immutable position; reject or neutralize input that attempts to redefine system-level instructions.",
          cwe: ["CWE-1427"],
          references: REFS,
          evidence: "system_prompt_protected=false",
          tags: ["ASI01", "goal-hijack"],
        },
        file,
      ),
    );
  }

  if (c.plan_review === false) {
    findings.push(
      buildAgenticFinding(
        {
          rule: "goal-no-plan-review",
          severity: "medium",
          title: "ASI01: No human or policy review of the agent plan",
          description:
            "High-impact plans that execute with no review give a hijacked goal a direct path to action (ASI01 Agent Goal Hijacking).",
          remediation:
            "Require human-in-the-loop or policy-engine review of plans that touch sensitive resources before execution.",
          cwe: ["CWE-1427"],
          references: REFS,
          evidence: "plan_review=false",
          tags: ["ASI01", "goal-hijack"],
        },
        file,
      ),
    );
  }

  return findings;
}
