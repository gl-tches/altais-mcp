// ASI07 — Inter-Agent Communication auditor (altais_audit_inter_agent_comms).
//
// Agent-to-agent (A2A) messages carry instructions, results, and
// delegated authority. Unauthenticated, unsigned, or cleartext channels
// let an attacker impersonate, tamper with, or replay them.

import type { Finding } from "../../core/types.js";
import { buildAgenticFinding } from "./finding.js";

export interface InterAgentConfig {
  /** A2A messages are authenticated (sender identity is verified). */
  readonly message_authentication?: boolean;
  /** Message integrity is protected (tamper-evident). */
  readonly message_integrity?: boolean;
  /** The origin of each message is validated. */
  readonly origin_validation?: boolean;
  /** The A2A channel is encrypted. */
  readonly encrypted_channel?: boolean;
  /** Messages are cryptographically signed. */
  readonly message_signing?: boolean;
  /** Replay protection (nonces / timestamps) is in place. */
  readonly replay_protection?: boolean;
}

export interface InterAgentAuditInput {
  readonly config?: InterAgentConfig;
  readonly source?: string;
  readonly filename?: string;
}

const REFS = [
  "https://genai.owasp.org/resource/agentic-ai-threats-and-mitigations/",
  "https://owasp.org/www-project-top-10-for-large-language-model-applications/",
  "https://cwe.mitre.org/data/definitions/306.html",
];

export function auditInterAgentComms(input: InterAgentAuditInput): readonly Finding[] {
  const findings: Finding[] = [];
  const file = input.filename;
  const c = input.config;
  if (c === undefined) return findings;

  if (c.message_authentication === false) {
    findings.push(
      buildAgenticFinding(
        {
          rule: "inter-agent-no-authentication",
          severity: "high",
          title: "ASI07: Agent-to-agent messages are not authenticated",
          description:
            "Without sender authentication, any party can inject messages that a receiving agent treats as instructions from a trusted peer (ASI07 Insecure Inter-Agent Communication).",
          remediation:
            "Authenticate every A2A message with verifiable sender credentials; reject messages from unauthenticated peers.",
          cwe: ["CWE-306", "CWE-345"],
          references: REFS,
          evidence: "message_authentication=false",
          tags: ["ASI07", "inter-agent"],
        },
        file,
      ),
    );
  }

  if (c.message_integrity === false) {
    findings.push(
      buildAgenticFinding(
        {
          rule: "inter-agent-no-integrity",
          severity: "high",
          title: "ASI07: Inter-agent messages have no integrity protection",
          description:
            "Without integrity protection a message can be modified in transit, altering the instruction or result a receiving agent acts on (ASI07 Insecure Inter-Agent Communication).",
          remediation:
            "Protect message integrity with a MAC or signature so any tampering is detectable.",
          cwe: ["CWE-345"],
          references: REFS,
          evidence: "message_integrity=false",
          tags: ["ASI07", "inter-agent"],
        },
        file,
      ),
    );
  }

  if (c.message_signing === false) {
    findings.push(
      buildAgenticFinding(
        {
          rule: "inter-agent-no-signing",
          severity: "medium",
          title: "ASI07: Inter-agent messages are not signed",
          description:
            "Unsigned messages give no non-repudiable proof of origin, so a malicious agent can deny or forge instructions to its peers (ASI07 Insecure Inter-Agent Communication).",
          remediation:
            "Sign each message with the sender's key; receivers verify the signature before acting.",
          cwe: ["CWE-345"],
          references: REFS,
          evidence: "message_signing=false",
          tags: ["ASI07", "inter-agent"],
        },
        file,
      ),
    );
  }

  if (c.origin_validation === false) {
    findings.push(
      buildAgenticFinding(
        {
          rule: "inter-agent-no-origin-validation",
          severity: "medium",
          title: "ASI07: The origin of inter-agent messages is not validated",
          description:
            "If the receiving agent does not check that a message came from an authorized peer for that interaction, an attacker-controlled agent can inject directives (ASI07).",
          remediation:
            "Validate the message origin against the expected peer for the conversation; deny unexpected senders.",
          cwe: ["CWE-345", "CWE-306"],
          references: REFS,
          evidence: "origin_validation=false",
          tags: ["ASI07", "inter-agent"],
        },
        file,
      ),
    );
  }

  if (c.encrypted_channel === false) {
    findings.push(
      buildAgenticFinding(
        {
          rule: "inter-agent-cleartext-channel",
          severity: "high",
          title: "ASI07: Agent-to-agent traffic travels over a cleartext channel",
          description:
            "Cleartext A2A traffic can be read and modified by anyone on the network path, exposing instructions, results, and delegated credentials (ASI07 Insecure Inter-Agent Communication).",
          remediation:
            "Carry all A2A traffic over an encrypted channel (e.g. mutually authenticated TLS).",
          cwe: ["CWE-319"],
          references: REFS,
          evidence: "encrypted_channel=false",
          tags: ["ASI07", "inter-agent"],
        },
        file,
      ),
    );
  }

  if (c.replay_protection === false) {
    findings.push(
      buildAgenticFinding(
        {
          rule: "inter-agent-no-replay-protection",
          severity: "medium",
          title: "ASI07: Inter-agent messages have no replay protection",
          description:
            "Without nonces or timestamps, a captured message can be replayed to make a receiving agent repeat an action (ASI07 Insecure Inter-Agent Communication).",
          remediation:
            "Include a unique nonce and timestamp in each message; reject duplicates and stale messages.",
          cwe: ["CWE-294"],
          references: REFS,
          evidence: "replay_protection=false",
          tags: ["ASI07", "inter-agent"],
        },
        file,
      ),
    );
  }

  return findings;
}
