// ASI06 — Memory Poisoning auditor (altais_audit_memory_poisoning).
//
// Agent memory, RAG pipelines, and shared state persist data across
// turns and sessions. Unvalidated or cross-user memory lets an attacker
// plant content that influences later, unrelated decisions.

import type { Finding } from "../../core/types.js";
import { buildAgenticFinding } from "./finding.js";

export interface MemoryPoisoningConfig {
  /** Content is validated before it is written to memory. */
  readonly memory_validation?: boolean;
  /** Memory is isolated per user / tenant. */
  readonly memory_isolation_per_user?: boolean;
  /** The trust of RAG / retrieval sources is verified. */
  readonly rag_source_trust_verified?: boolean;
  /** Mutable state is shared between agents. */
  readonly shared_state_between_agents?: boolean;
  /** Memory entries carry provenance metadata. */
  readonly memory_provenance?: boolean;
  /** Untrusted external content is persisted into long-term memory. */
  readonly untrusted_content_persisted?: boolean;
}

export interface MemoryPoisoningAuditInput {
  readonly config?: MemoryPoisoningConfig;
  readonly source?: string;
  readonly filename?: string;
}

const REFS = [
  "https://genai.owasp.org/resource/agentic-ai-threats-and-mitigations/",
  "https://owasp.org/www-project-top-10-for-large-language-model-applications/",
  "https://cwe.mitre.org/data/definitions/349.html",
];

export function auditMemoryPoisoning(input: MemoryPoisoningAuditInput): readonly Finding[] {
  const findings: Finding[] = [];
  const file = input.filename;
  const c = input.config;
  if (c === undefined) return findings;

  if (c.memory_validation === false) {
    findings.push(
      buildAgenticFinding(
        {
          rule: "memory-no-validation",
          severity: "high",
          title: "ASI06: Content is written to agent memory without validation",
          description:
            "If anything an agent observes can be written to memory unvalidated, an attacker can plant instructions or false facts that influence every later run that reads them (ASI06 Memory Poisoning).",
          remediation:
            "Validate and sanitize content before persisting it; never store raw untrusted text as authoritative memory.",
          cwe: ["CWE-349", "CWE-20"],
          references: REFS,
          evidence: "memory_validation=false",
          tags: ["ASI06", "memory-poisoning"],
        },
        file,
      ),
    );
  }

  if (c.memory_isolation_per_user === false) {
    findings.push(
      buildAgenticFinding(
        {
          rule: "memory-cross-user-bleed",
          severity: "high",
          title: "ASI06: Agent memory is not isolated per user / tenant",
          description:
            "Shared memory across users lets one user's planted content reach another user's session — both a poisoning vector and a confidentiality leak (ASI06 Memory Poisoning).",
          remediation:
            "Partition memory strictly by user / tenant; enforce the boundary on every read and write.",
          cwe: ["CWE-349", "CWE-501"],
          references: REFS,
          evidence: "memory_isolation_per_user=false",
          tags: ["ASI06", "memory-poisoning"],
        },
        file,
      ),
    );
  }

  if (c.rag_source_trust_verified === false) {
    findings.push(
      buildAgenticFinding(
        {
          rule: "memory-untrusted-rag-sources",
          severity: "high",
          title: "ASI06: RAG / retrieval sources are not trust-verified",
          description:
            "A RAG pipeline that ingests unverified sources can retrieve attacker-authored documents carrying embedded instructions, poisoning the agent's context (ASI06 Memory Poisoning).",
          remediation:
            "Verify and allowlist RAG sources; sign or score documents for trust and treat low-trust content as non-authoritative.",
          cwe: ["CWE-349"],
          references: REFS,
          evidence: "rag_source_trust_verified=false",
          tags: ["ASI06", "memory-poisoning"],
        },
        file,
      ),
    );
  }

  if (c.untrusted_content_persisted === true) {
    findings.push(
      buildAgenticFinding(
        {
          rule: "memory-untrusted-content-persisted",
          severity: "high",
          title: "ASI06: Untrusted content is persisted into long-term memory",
          description:
            "Persisting untrusted external content gives a one-time injection lasting effect across all future sessions that read that memory (ASI06 Memory Poisoning).",
          remediation:
            "Do not persist untrusted content as durable memory; if it must be stored, label it untrusted and quarantine it from the planning context.",
          cwe: ["CWE-349", "CWE-501"],
          references: REFS,
          evidence: "untrusted_content_persisted=true",
          tags: ["ASI06", "memory-poisoning"],
        },
        file,
      ),
    );
  }

  if (c.shared_state_between_agents === true) {
    findings.push(
      buildAgenticFinding(
        {
          rule: "memory-shared-mutable-state",
          severity: "medium",
          title: "ASI06: Mutable state is shared between agents",
          description:
            "Shared mutable state lets a compromised agent poison the context of every other agent that reads it, spreading bad data laterally (ASI06 Memory Poisoning).",
          remediation:
            "Avoid shared mutable state; pass data through validated, immutable, attributed messages instead.",
          cwe: ["CWE-501"],
          references: REFS,
          evidence: "shared_state_between_agents=true",
          tags: ["ASI06", "memory-poisoning"],
        },
        file,
      ),
    );
  }

  if (c.memory_provenance === false) {
    findings.push(
      buildAgenticFinding(
        {
          rule: "memory-no-provenance",
          severity: "medium",
          title: "ASI06: Memory entries carry no provenance",
          description:
            "Without provenance metadata the agent cannot tell trusted memory from attacker-planted content, and poisoned entries cannot be traced or revoked (ASI06 Memory Poisoning).",
          remediation:
            "Tag every memory entry with its source, trust level, and timestamp; weight or filter retrieval by provenance.",
          cwe: ["CWE-349"],
          references: REFS,
          evidence: "memory_provenance=false",
          tags: ["ASI06", "memory-poisoning"],
        },
        file,
      ),
    );
  }

  return findings;
}
