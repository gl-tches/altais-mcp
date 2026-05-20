# `altais_audit_memory_poisoning`

Audits an agent system against OWASP ASI06 — Memory & Context Poisoning.

| Property | Value |
|----------|-------|
| Module | [`agentic`](../modules/agentic.md) |
| Tool type | Auditor (emits findings) |
| Annotations | `readOnlyHint: true` · `destructiveHint: false` · `idempotentHint: true` · `openWorldHint: false` |

## Description

Audits an agent system against **ASI06 — Memory & Context Poisoning**. It flags missing memory validation, cross-user memory bleed, untrusted RAG sources, persisted untrusted content, shared mutable state between agents, and memory entries without provenance. An agent calls this when reviewing how an agent stores and retrieves long-term context.

## Input parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `source` | `string` (1–524288 chars) | No | Source code describing the agent system, scanned with pattern checks. |
| `filename` | `string` (1–512 chars) | No | Filename used for the finding location. |
| `config` | `object` | No | Structured description of the memory / context controls. |
| `config.memory_validation` | `boolean` | No | Content is validated before it is written to memory. |
| `config.memory_isolation_per_user` | `boolean` | No | Memory is isolated per user / tenant. |
| `config.rag_source_trust_verified` | `boolean` | No | The trust of RAG / retrieval sources is verified. |
| `config.shared_state_between_agents` | `boolean` | No | Mutable state is shared between agents. |
| `config.memory_provenance` | `boolean` | No | Memory entries carry provenance metadata. |
| `config.untrusted_content_persisted` | `boolean` | No | Untrusted external content is persisted into long-term memory. |

## Output

Returns `{ summary: { total, by_severity }, findings: [...] }`. Each finding has the standard shape and carries the `owasp:asi06` tag. Findings are appended to the session report.

## Example

**Request**

```json
{ "config": { "memory_validation": false, "memory_isolation_per_user": false } }
```

**Response (excerpt)**

```json
{
  "summary": { "total": 2, "by_severity": { "high": 1, "medium": 1 } },
  "findings": [
    { "rule": "no-memory-validation", "severity": "medium", "tags": ["owasp:asi06"], "title": "Content is not validated before being written to memory", "status": "open" }
  ]
}
```

## Detections

All detections tie to **ASI06 — Memory & Context Poisoning**:

- Missing memory validation
- Cross-user memory bleed (no per-user isolation)
- Untrusted RAG / retrieval sources
- Persisted untrusted content
- Shared mutable state between agents
- Memory entries without provenance

## Related tools

- [`altais_audit_goal_hijack`](altais_audit_goal_hijack.md) — ASI01, untrusted data feeding the planner
- [`altais_audit_inter_agent_comms`](altais_audit_inter_agent_comms.md) — ASI07, integrity of agent-to-agent messages

## See also

- [`agentic` module](../modules/agentic.md)
- [Wiki home](../Home.md) · [Contributing](../Contributing.md) · [Deployment](../Deployment.md)
