// ASI04 — Agentic Supply Chain auditor (altais_audit_agentic_supply_chain).
//
// The agentic supply chain is the set of runtime MCP servers, plugins,
// agent cards, and tool registries an agent loads. Unsigned manifests,
// unverified plugins, and unpinned registries let an attacker substitute
// a malicious component.

import type { Finding } from "../../core/types.js";
import { buildAgenticFinding } from "./finding.js";

export interface McpServerEntry {
  readonly name: string;
  readonly source?: string;
}

export interface AgenticSupplyChainConfig {
  /** Inventory of MCP servers the agent connects to at runtime. */
  readonly mcp_servers?: readonly McpServerEntry[];
  /** MCP / plugin manifests are cryptographically signed and verified. */
  readonly manifests_signed?: boolean;
  /** Plugins are verified before loading. */
  readonly plugins_verified?: boolean;
  /** Agent cards (A2A / discovery metadata) are verified. */
  readonly agent_cards_verified?: boolean;
  /** Tool / server registries are pinned to specific versions. */
  readonly registry_pinned?: boolean;
  /** Component names are checked against typosquatting. */
  readonly typosquat_checked?: boolean;
  /** Provenance attestation (e.g. SLSA) is required for components. */
  readonly provenance_attestation?: boolean;
}

export interface AgenticSupplyChainAuditInput {
  readonly config?: AgenticSupplyChainConfig;
  readonly source?: string;
  readonly filename?: string;
}

const REFS = [
  "https://genai.owasp.org/resource/agentic-ai-threats-and-mitigations/",
  "https://slsa.dev/",
  "https://cwe.mitre.org/data/definitions/1357.html",
];

export function auditAgenticSupplyChain(input: AgenticSupplyChainAuditInput): readonly Finding[] {
  const findings: Finding[] = [];
  const file = input.filename;
  const c = input.config;
  if (c === undefined) return findings;

  if (c.manifests_signed === false) {
    findings.push(
      buildAgenticFinding(
        {
          rule: "supply-chain-unsigned-manifests",
          severity: "high",
          title: "ASI04: MCP / plugin manifests are not signed or verified",
          description:
            "An unsigned manifest can be modified in transit or at rest to add malicious tools or alter descriptors; without signature verification the agent cannot detect substitution (ASI04 Agentic Supply Chain).",
          remediation:
            "Require signed manifests and verify the signature against a trusted key before loading any MCP server or plugin.",
          cwe: ["CWE-1357", "CWE-345"],
          references: REFS,
          evidence: "manifests_signed=false",
          tags: ["ASI04", "supply-chain"],
        },
        file,
      ),
    );
  }

  if (c.plugins_verified === false) {
    findings.push(
      buildAgenticFinding(
        {
          rule: "supply-chain-unverified-plugins",
          severity: "high",
          title: "ASI04: Plugins are loaded without verification",
          description:
            "Loading a plugin without integrity and authenticity checks executes whatever code the supplier — or an attacker who replaced it — provides (ASI04 Agentic Supply Chain).",
          remediation:
            "Verify each plugin's signature and integrity hash against a trusted source before loading; deny unverified plugins.",
          cwe: ["CWE-829", "CWE-345"],
          references: REFS,
          evidence: "plugins_verified=false",
          tags: ["ASI04", "supply-chain"],
        },
        file,
      ),
    );
  }

  if (c.agent_cards_verified === false) {
    findings.push(
      buildAgenticFinding(
        {
          rule: "supply-chain-unverified-agent-cards",
          severity: "medium",
          title: "ASI04: Agent cards are consumed without verification",
          description:
            "Agent cards advertise an agent's identity, skills, and endpoints. An unverified card lets an attacker impersonate a trusted agent or advertise malicious capabilities (ASI04 Agentic Supply Chain).",
          remediation:
            "Verify agent-card authenticity (signature / trusted registry) before trusting the advertised identity or skills.",
          cwe: ["CWE-345"],
          references: REFS,
          evidence: "agent_cards_verified=false",
          tags: ["ASI04", "supply-chain"],
        },
        file,
      ),
    );
  }

  if (c.registry_pinned === false) {
    findings.push(
      buildAgenticFinding(
        {
          rule: "supply-chain-unpinned-registry",
          severity: "medium",
          title: "ASI04: Tool / server registries are not version-pinned",
          description:
            "Resolving components from a floating registry reference means the agent can silently pull a different — possibly malicious — version of an MCP server or tool (ASI04 Agentic Supply Chain).",
          remediation:
            "Pin registry entries to specific, immutable versions or digests; review and re-pin on upgrade.",
          cwe: ["CWE-1357", "CWE-829"],
          references: REFS,
          evidence: "registry_pinned=false",
          tags: ["ASI04", "supply-chain"],
        },
        file,
      ),
    );
  }

  if (c.typosquat_checked === false) {
    findings.push(
      buildAgenticFinding(
        {
          rule: "supply-chain-no-typosquat-check",
          severity: "medium",
          title: "ASI04: Component names are not checked for typosquatting",
          description:
            "Attackers publish MCP servers and plugins under names confusingly similar to popular ones; without a check, an agent can install the impostor (ASI04 Agentic Supply Chain).",
          remediation:
            "Validate component names against a known-good allowlist and flag near-miss / homoglyph names before installation.",
          cwe: ["CWE-1357"],
          references: REFS,
          evidence: "typosquat_checked=false",
          tags: ["ASI04", "supply-chain"],
        },
        file,
      ),
    );
  }

  if (c.provenance_attestation === false) {
    findings.push(
      buildAgenticFinding(
        {
          rule: "supply-chain-no-provenance",
          severity: "medium",
          title: "ASI04: No provenance attestation required for components",
          description:
            "Without provenance attestation there is no verifiable record of how a component was built or by whom, so a tampered build cannot be distinguished from a legitimate one (ASI04 Agentic Supply Chain).",
          remediation:
            "Require SLSA-style provenance attestation for MCP servers, plugins, and tools, and verify it at install time.",
          cwe: ["CWE-1357", "CWE-345"],
          references: REFS,
          evidence: "provenance_attestation=false",
          tags: ["ASI04", "supply-chain"],
        },
        file,
      ),
    );
  }

  for (const srv of c.mcp_servers ?? []) {
    const src = (srv.source ?? "").toLowerCase().trim();
    if (src === "unknown" || src === "unverified" || src === "untrusted" || src === "community") {
      findings.push(
        buildAgenticFinding(
          {
            rule: "supply-chain-untrusted-mcp-server",
            severity: "high",
            title: `ASI04: MCP server "${srv.name}" comes from an untrusted source`,
            description:
              "A runtime MCP server from an unknown or unverified source can expose poisoned tools and descriptors directly into the agent's tool set (ASI04 Agentic Supply Chain).",
            remediation: `Source "${srv.name}" from a vetted, signed, and pinned registry; verify its provenance before connecting.`,
            cwe: ["CWE-829", "CWE-345"],
            references: REFS,
            evidence: `${srv.name}: source=${srv.source ?? ""}`,
            tags: ["ASI04", "supply-chain"],
          },
          file,
        ),
      );
    }
  }

  return findings;
}
