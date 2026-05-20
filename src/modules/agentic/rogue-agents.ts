// ASI10 — Rogue Agents auditor (altais_audit_rogue_agents).
//
// A rogue agent is one acting outside its intended behavior — whether
// compromised, misaligned, or unauthorized. Detecting and containing it
// needs baselines, anomaly detection, inventory, governance, and
// revocation.

import type { Finding } from "../../core/types.js";
import { buildAgenticFinding } from "./finding.js";

export type AnomalyCoverage = "none" | "partial" | "comprehensive";

export interface RogueAgentsConfig {
  /** A behavioral baseline exists for normal agent activity. */
  readonly behavioral_baseline?: boolean;
  /** Anomaly detection runs against agent behavior. */
  readonly anomaly_detection?: boolean;
  /** Coverage of anomaly detection across agents / actions. */
  readonly anomaly_detection_coverage?: AnomalyCoverage;
  /** A complete inventory of agents is maintained. */
  readonly agent_inventory?: boolean;
  /** An agent governance policy is defined and enforced. */
  readonly agent_governance_policy?: boolean;
  /** Agents run in a sandbox. */
  readonly sandboxing?: boolean;
  /** Agent actions are recorded in an audit log. */
  readonly audit_logging?: boolean;
  /** A rogue agent can be revoked / killed. */
  readonly revocation_capability?: boolean;
}

export interface RogueAgentsAuditInput {
  readonly config?: RogueAgentsConfig;
  readonly source?: string;
  readonly filename?: string;
}

const REFS = [
  "https://genai.owasp.org/resource/agentic-ai-threats-and-mitigations/",
  "https://owasp.org/www-project-top-10-for-large-language-model-applications/",
  "https://cwe.mitre.org/data/definitions/778.html",
];

export function auditRogueAgents(input: RogueAgentsAuditInput): readonly Finding[] {
  const findings: Finding[] = [];
  const file = input.filename;
  const c = input.config;
  if (c === undefined) return findings;

  if (c.behavioral_baseline === false) {
    findings.push(
      buildAgenticFinding(
        {
          rule: "rogue-no-behavioral-baseline",
          severity: "medium",
          title: "ASI10: No behavioral baseline for agent activity",
          description:
            "Without a baseline of normal behavior, deviations that signal a rogue or compromised agent cannot be recognized (ASI10 Rogue Agents).",
          remediation:
            "Establish and maintain a behavioral baseline (tools used, call rates, resources touched) for each agent role.",
          cwe: ["CWE-778"],
          references: REFS,
          evidence: "behavioral_baseline=false",
          tags: ["ASI10", "rogue-agents"],
        },
        file,
      ),
    );
  }

  if (c.anomaly_detection === false) {
    findings.push(
      buildAgenticFinding(
        {
          rule: "rogue-no-anomaly-detection",
          severity: "high",
          title: "ASI10: No anomaly detection on agent behavior",
          description:
            "With no anomaly detection, a rogue agent's deviant actions go unnoticed until they cause visible harm (ASI10 Rogue Agents).",
          remediation:
            "Run anomaly detection against agent behavior and alert on deviations from the baseline.",
          cwe: ["CWE-778", "CWE-940"],
          references: REFS,
          evidence: "anomaly_detection=false",
          tags: ["ASI10", "rogue-agents"],
        },
        file,
      ),
    );
  } else if (
    c.anomaly_detection_coverage === "none" ||
    c.anomaly_detection_coverage === "partial"
  ) {
    findings.push(
      buildAgenticFinding(
        {
          rule: "rogue-partial-anomaly-coverage",
          severity: "medium",
          title: `ASI10: Anomaly detection coverage is ${c.anomaly_detection_coverage}`,
          description:
            "Anomaly detection that covers only some agents or actions leaves blind spots a rogue agent can operate within (ASI10 Rogue Agents).",
          remediation:
            "Extend anomaly-detection coverage to every agent, tool, and inter-agent interaction.",
          cwe: ["CWE-778"],
          references: REFS,
          evidence: `anomaly_detection_coverage=${c.anomaly_detection_coverage}`,
          tags: ["ASI10", "rogue-agents"],
        },
        file,
      ),
    );
  }

  if (c.agent_inventory === false) {
    findings.push(
      buildAgenticFinding(
        {
          rule: "rogue-no-agent-inventory",
          severity: "medium",
          title: "ASI10: No inventory of agents",
          description:
            "Without a complete agent inventory, an unauthorized or shadow agent cannot be distinguished from a legitimate one (ASI10 Rogue Agents).",
          remediation:
            "Maintain an authoritative inventory of every agent, its owner, role, and credentials; reconcile it regularly.",
          cwe: ["CWE-778"],
          references: REFS,
          evidence: "agent_inventory=false",
          tags: ["ASI10", "rogue-agents"],
        },
        file,
      ),
    );
  }

  if (c.agent_governance_policy === false) {
    findings.push(
      buildAgenticFinding(
        {
          rule: "rogue-no-governance-policy",
          severity: "medium",
          title: "ASI10: No agent governance policy",
          description:
            "Without a governance policy, there is no defined authority on what agents may do, who approves them, or how they are decommissioned (ASI10 Rogue Agents).",
          remediation:
            "Define and enforce an agent governance policy covering approval, scope, monitoring, and retirement.",
          cwe: ["CWE-778"],
          references: REFS,
          evidence: "agent_governance_policy=false",
          tags: ["ASI10", "rogue-agents"],
        },
        file,
      ),
    );
  }

  if (c.sandboxing === false) {
    findings.push(
      buildAgenticFinding(
        {
          rule: "rogue-no-sandboxing",
          severity: "high",
          title: "ASI10: Agents are not sandboxed",
          description:
            "An unsandboxed rogue agent has direct access to host resources, so its damage is unbounded once it goes off-script (ASI10 Rogue Agents).",
          remediation:
            "Run every agent in a sandbox with least-privilege resource access so a rogue agent stays contained.",
          cwe: ["CWE-940"],
          references: REFS,
          evidence: "sandboxing=false",
          tags: ["ASI10", "rogue-agents"],
        },
        file,
      ),
    );
  }

  if (c.audit_logging === false) {
    findings.push(
      buildAgenticFinding(
        {
          rule: "rogue-no-audit-logging",
          severity: "high",
          title: "ASI10: Agent actions are not audit-logged",
          description:
            "Without an audit log of agent actions, rogue behavior cannot be detected, investigated, or attributed after the fact (ASI10 Rogue Agents).",
          remediation:
            "Record every agent action — tool calls, decisions, inter-agent messages — in a tamper-evident audit log.",
          cwe: ["CWE-778"],
          references: REFS,
          evidence: "audit_logging=false",
          tags: ["ASI10", "rogue-agents"],
        },
        file,
      ),
    );
  }

  if (c.revocation_capability === false) {
    findings.push(
      buildAgenticFinding(
        {
          rule: "rogue-no-revocation",
          severity: "high",
          title: "ASI10: No capability to revoke or kill a rogue agent",
          description:
            "If a rogue agent cannot be revoked or killed, there is no way to stop it once detected, letting harm continue unchecked (ASI10 Rogue Agents).",
          remediation:
            "Provide a fast revocation / kill capability that disables an agent's credentials and halts its execution.",
          cwe: ["CWE-940"],
          references: REFS,
          evidence: "revocation_capability=false",
          tags: ["ASI10", "rogue-agents"],
        },
        file,
      ),
    );
  }

  return findings;
}
