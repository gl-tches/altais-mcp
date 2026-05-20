// ASI08 — Cascading Failures auditor (altais_audit_cascading_failures).
//
// In multi-agent systems a single fault, loop, or compromised agent can
// propagate through the mesh. Kill switches, circuit breakers, isolation,
// and chain-depth limits bound the blast radius.

import type { Finding } from "../../core/types.js";
import { buildAgenticFinding } from "./finding.js";

export interface CascadingFailuresConfig {
  /** A kill switch can halt agents on demand. */
  readonly kill_switch?: boolean;
  /** Circuit breakers cut off failing dependencies. */
  readonly circuit_breakers?: boolean;
  /** The blast radius of any single agent is bounded. */
  readonly blast_radius_limits?: boolean;
  /** Agents are isolated from one another. */
  readonly agent_isolation?: boolean;
  /** Failures are detected and surfaced. */
  readonly failure_detection?: boolean;
  /** Rate limits apply to agent-to-agent calls. */
  readonly rate_limits_between_agents?: boolean;
  /** A maximum agent-chain / delegation depth, if configured. */
  readonly max_agent_chain_depth?: number;
}

export interface CascadingFailuresAuditInput {
  readonly config?: CascadingFailuresConfig;
  readonly source?: string;
  readonly filename?: string;
}

const REFS = [
  "https://genai.owasp.org/resource/agentic-ai-threats-and-mitigations/",
  "https://owasp.org/www-community/attacks/Denial_of_Service",
  "https://cwe.mitre.org/data/definitions/400.html",
];

export function auditCascadingFailures(input: CascadingFailuresAuditInput): readonly Finding[] {
  const findings: Finding[] = [];
  const file = input.filename;
  const c = input.config;
  if (c === undefined) return findings;

  if (c.kill_switch === false) {
    findings.push(
      buildAgenticFinding(
        {
          rule: "cascading-no-kill-switch",
          severity: "high",
          title: "ASI08: No kill switch to halt the agent system",
          description:
            "Without a kill switch, a runaway or compromised agent cannot be stopped quickly, letting a failure cascade through the system unchecked (ASI08 Cascading Failures).",
          remediation:
            "Implement an out-of-band kill switch that can immediately halt individual agents and the whole fleet.",
          cwe: ["CWE-400", "CWE-691"],
          references: REFS,
          evidence: "kill_switch=false",
          tags: ["ASI08", "cascading-failures"],
        },
        file,
      ),
    );
  }

  if (c.circuit_breakers === false) {
    findings.push(
      buildAgenticFinding(
        {
          rule: "cascading-no-circuit-breakers",
          severity: "medium",
          title: "ASI08: No circuit breakers between agents / dependencies",
          description:
            "Without circuit breakers, a failing agent or dependency keeps receiving traffic, amplifying the fault across the system (ASI08 Cascading Failures).",
          remediation:
            "Add circuit breakers that trip on repeated failures and shed load until the dependency recovers.",
          cwe: ["CWE-691"],
          references: REFS,
          evidence: "circuit_breakers=false",
          tags: ["ASI08", "cascading-failures"],
        },
        file,
      ),
    );
  }

  if (c.blast_radius_limits === false) {
    findings.push(
      buildAgenticFinding(
        {
          rule: "cascading-unbounded-blast-radius",
          severity: "high",
          title: "ASI08: The blast radius of a single agent is unbounded",
          description:
            "With no blast-radius limits, a single compromised or faulty agent can affect the entire system rather than a contained slice (ASI08 Cascading Failures).",
          remediation:
            "Bound each agent's impact: cap the resources, peers, and actions it can reach; partition the system into isolated cells.",
          cwe: ["CWE-400"],
          references: REFS,
          evidence: "blast_radius_limits=false",
          tags: ["ASI08", "cascading-failures"],
        },
        file,
      ),
    );
  }

  if (c.agent_isolation === false) {
    findings.push(
      buildAgenticFinding(
        {
          rule: "cascading-no-agent-isolation",
          severity: "medium",
          title: "ASI08: Agents are not isolated from one another",
          description:
            "Without isolation, a fault or compromise in one agent directly destabilizes others sharing the same runtime or resources (ASI08 Cascading Failures).",
          remediation:
            "Run agents in isolated execution contexts with separate resource quotas so a failure stays local.",
          cwe: ["CWE-691"],
          references: REFS,
          evidence: "agent_isolation=false",
          tags: ["ASI08", "cascading-failures"],
        },
        file,
      ),
    );
  }

  if (c.failure_detection === false) {
    findings.push(
      buildAgenticFinding(
        {
          rule: "cascading-no-failure-detection",
          severity: "medium",
          title: "ASI08: Failures are not detected or surfaced",
          description:
            "If failures go undetected, a cascade is already widespread before any operator can react (ASI08 Cascading Failures).",
          remediation:
            "Monitor agent health and inter-agent error rates; alert on anomalies and trip protective controls automatically.",
          cwe: ["CWE-691"],
          references: REFS,
          evidence: "failure_detection=false",
          tags: ["ASI08", "cascading-failures"],
        },
        file,
      ),
    );
  }

  if (c.rate_limits_between_agents === false) {
    findings.push(
      buildAgenticFinding(
        {
          rule: "cascading-no-inter-agent-rate-limits",
          severity: "medium",
          title: "ASI08: No rate limits on agent-to-agent calls",
          description:
            "Unbounded A2A calls let a fault loop saturate the mesh and exhaust resources, accelerating a cascade (ASI08 Cascading Failures).",
          remediation:
            "Apply rate limits and budgets to inter-agent calls; shed or queue traffic that exceeds them.",
          cwe: ["CWE-400"],
          references: REFS,
          evidence: "rate_limits_between_agents=false",
          tags: ["ASI08", "cascading-failures"],
        },
        file,
      ),
    );
  }

  if (c.max_agent_chain_depth === undefined) {
    findings.push(
      buildAgenticFinding(
        {
          rule: "cascading-no-chain-depth-limit",
          severity: "high",
          title: "ASI08: No limit on agent-chain / delegation depth",
          description:
            "Without a maximum chain depth, agents can delegate to each other recursively without bound, causing infinite loops and resource exhaustion (ASI08 Cascading Failures).",
          remediation:
            "Set and enforce a maximum delegation / agent-chain depth; abort and alert when it is exceeded.",
          cwe: ["CWE-674", "CWE-400"],
          references: REFS,
          evidence: "max_agent_chain_depth=unset",
          tags: ["ASI08", "cascading-failures"],
        },
        file,
      ),
    );
  } else if (c.max_agent_chain_depth > 25) {
    findings.push(
      buildAgenticFinding(
        {
          rule: "cascading-chain-depth-too-high",
          severity: "medium",
          title: `ASI08: Agent-chain depth limit is very high (${String(c.max_agent_chain_depth)})`,
          description:
            "A very large chain-depth limit barely constrains recursive delegation, leaving room for runaway loops before the cap engages (ASI08 Cascading Failures).",
          remediation:
            "Lower the agent-chain depth limit to the smallest value the workflow genuinely needs.",
          cwe: ["CWE-674"],
          references: REFS,
          evidence: `max_agent_chain_depth=${String(c.max_agent_chain_depth)}`,
          tags: ["ASI08", "cascading-failures"],
        },
        file,
      ),
    );
  }

  return findings;
}
