// ASI03 — Identity & Privilege auditor (altais_audit_agent_identity).
//
// Agents need their own scoped identities. Shared or inherited identity,
// privilege escalation paths, and confused-deputy exposure let an agent
// act with authority it was never granted.

import type { Finding } from "../../core/types.js";
import { buildAgenticFinding } from "./finding.js";

export interface AgentIdentityConfig {
  /** Each agent runs under its own distinct identity. */
  readonly per_agent_identity?: boolean;
  /** Agents inherit the privileges of the caller / parent. */
  readonly privilege_inheritance?: boolean;
  /** An agent can escalate its own privileges at runtime. */
  readonly can_escalate_privileges?: boolean;
  /** Confused-deputy protection (caller authority is checked, not just agent). */
  readonly confused_deputy_protection?: boolean;
  /** Credentials are retained across sessions. */
  readonly cross_session_credential_retention?: boolean;
  /** Credentials issued to the agent are narrowly scoped. */
  readonly scoped_credentials?: boolean;
  /** The human user's identity is kept distinct from the agent's. */
  readonly human_user_distinct_from_agent?: boolean;
}

export interface AgentIdentityAuditInput {
  readonly config?: AgentIdentityConfig;
  readonly source?: string;
  readonly filename?: string;
}

const REFS = [
  "https://genai.owasp.org/resource/agentic-ai-threats-and-mitigations/",
  "https://owasp.org/www-project-non-human-identities-top-10/",
  "https://cwe.mitre.org/data/definitions/269.html",
];

export function auditAgentIdentity(input: AgentIdentityAuditInput): readonly Finding[] {
  const findings: Finding[] = [];
  const file = input.filename;
  const c = input.config;
  if (c === undefined) return findings;

  if (c.per_agent_identity === false) {
    findings.push(
      buildAgenticFinding(
        {
          rule: "identity-shared-agent-identity",
          severity: "high",
          title: "ASI03: Agents share a single identity",
          description:
            "A shared identity makes every agent indistinguishable in logs and authorization decisions; one compromised agent acts with the authority of all (ASI03 Identity & Privilege Abuse).",
          remediation:
            "Issue each agent (and each agent instance, where feasible) its own non-human identity with independent credentials.",
          cwe: ["CWE-269", "CWE-441"],
          references: REFS,
          evidence: "per_agent_identity=false",
          tags: ["ASI03", "agent-identity"],
        },
        file,
      ),
    );
  }

  if (c.privilege_inheritance === true) {
    findings.push(
      buildAgenticFinding(
        {
          rule: "identity-privilege-inheritance",
          severity: "high",
          title: "ASI03: Agents inherit caller / parent privileges",
          description:
            "When an agent runs with the full privileges of the user or parent agent that invoked it, a hijacked sub-task gains authority far beyond its purpose (ASI03 Identity & Privilege Abuse).",
          remediation:
            "Grant each agent its own least-privilege role; derive a downscoped token per delegated task rather than inheriting the caller's rights.",
          cwe: ["CWE-269"],
          references: REFS,
          evidence: "privilege_inheritance=true",
          tags: ["ASI03", "agent-identity"],
        },
        file,
      ),
    );
  }

  if (c.can_escalate_privileges === true) {
    findings.push(
      buildAgenticFinding(
        {
          rule: "identity-privilege-escalation-path",
          severity: "critical",
          title: "ASI03: The agent can escalate its own privileges at runtime",
          description:
            "A runtime privilege-escalation path lets a hijacked agent grant itself rights it was never assigned, defeating least privilege entirely (ASI03 Identity & Privilege Abuse).",
          remediation:
            "Remove self-service privilege grants; require an out-of-band approval for any change to an agent's role or scope.",
          cwe: ["CWE-269"],
          references: REFS,
          evidence: "can_escalate_privileges=true",
          tags: ["ASI03", "agent-identity"],
        },
        file,
      ),
    );
  }

  if (c.confused_deputy_protection === false) {
    findings.push(
      buildAgenticFinding(
        {
          rule: "identity-no-confused-deputy-protection",
          severity: "high",
          title: "ASI03: No confused-deputy protection on agent actions",
          description:
            "If the agent acts on its own authority without checking the originating caller's authorization, an attacker can trick it into performing privileged actions on their behalf (confused deputy) (ASI03).",
          remediation:
            "Propagate and check the original caller's authorization for each action; the agent must not be more privileged than the principal it serves.",
          cwe: ["CWE-441"],
          references: REFS,
          evidence: "confused_deputy_protection=false",
          tags: ["ASI03", "agent-identity"],
        },
        file,
      ),
    );
  }

  if (c.cross_session_credential_retention === true) {
    findings.push(
      buildAgenticFinding(
        {
          rule: "identity-cross-session-credential-retention",
          severity: "high",
          title: "ASI03: Credentials are retained across sessions",
          description:
            "Credentials kept beyond a session live longer than the trust that issued them and can be reused by a later, unrelated request — a credential-leak amplifier (ASI03 Identity & Privilege Abuse).",
          remediation:
            "Issue short-lived, session-scoped credentials and discard them when the session ends; never persist agent tokens across sessions.",
          cwe: ["CWE-522"],
          references: REFS,
          evidence: "cross_session_credential_retention=true",
          tags: ["ASI03", "agent-identity"],
        },
        file,
      ),
    );
  }

  if (c.scoped_credentials === false) {
    findings.push(
      buildAgenticFinding(
        {
          rule: "identity-unscoped-credentials",
          severity: "medium",
          title: "ASI03: Agent credentials are not narrowly scoped",
          description:
            "Broad credentials give a compromised agent access well beyond its task, increasing the blast radius of any leak (ASI03 Identity & Privilege Abuse).",
          remediation:
            "Scope every credential to the specific resources and actions the agent needs; prefer per-task downscoped tokens.",
          cwe: ["CWE-522", "CWE-269"],
          references: REFS,
          evidence: "scoped_credentials=false",
          tags: ["ASI03", "agent-identity"],
        },
        file,
      ),
    );
  }

  if (c.human_user_distinct_from_agent === false) {
    findings.push(
      buildAgenticFinding(
        {
          rule: "identity-user-agent-conflated",
          severity: "medium",
          title: "ASI03: The human user's identity is conflated with the agent's",
          description:
            "When the agent and the user it serves share one identity, actions cannot be attributed and the agent silently wields the user's full rights (ASI03 Identity & Privilege Abuse).",
          remediation:
            "Keep the agent's non-human identity distinct from the user's; record both the acting agent and the on-behalf-of user.",
          cwe: ["CWE-441"],
          references: REFS,
          evidence: "human_user_distinct_from_agent=false",
          tags: ["ASI03", "agent-identity"],
        },
        file,
      ),
    );
  }

  return findings;
}
