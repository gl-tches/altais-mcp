# `altais_audit_inter_agent_comms`

Audits an agent system against OWASP ASI07 — Insecure Inter-Agent Communication.

| Property | Value |
|----------|-------|
| Module | [`agentic`](../modules/agentic.md) |
| Tool type | Auditor (emits findings) |
| Annotations | `readOnlyHint: true` · `destructiveHint: false` · `idempotentHint: true` · `openWorldHint: false` |

## Description

Audits an agent system against **ASI07 — Insecure Inter-Agent Communication**. It flags unauthenticated agent-to-agent messages, missing integrity protection or signing, no origin validation, a cleartext channel, and missing replay protection. An agent calls this when reviewing how agents exchange messages (A2A).

## Input parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `source` | `string` (1–524288 chars) | No | Source code describing the agent system, scanned with pattern checks. |
| `filename` | `string` (1–512 chars) | No | Filename used for the finding location. |
| `config` | `object` | No | Structured description of the inter-agent communication controls. |
| `config.message_authentication` | `boolean` | No | A2A messages are authenticated (sender identity verified). |
| `config.message_integrity` | `boolean` | No | Message integrity is protected (tamper-evident). |
| `config.origin_validation` | `boolean` | No | The origin of each message is validated. |
| `config.encrypted_channel` | `boolean` | No | The A2A channel is encrypted. |
| `config.message_signing` | `boolean` | No | Messages are cryptographically signed. |
| `config.replay_protection` | `boolean` | No | Replay protection (nonces / timestamps) is in place. |

## Output

Returns `{ summary: { total, by_severity }, findings: [...] }`. Each finding has the standard shape and carries the `owasp:asi07` tag. Findings are appended to the session report.

## Example

**Request**

```json
{ "config": { "message_authentication": false, "encrypted_channel": false } }
```

**Response (excerpt)**

```json
{
  "summary": { "total": 2, "by_severity": { "high": 2 } },
  "findings": [
    { "rule": "unauthenticated-messages", "severity": "high", "tags": ["owasp:asi07"], "title": "Agent-to-agent messages are not authenticated", "status": "open" }
  ]
}
```

## Detections

All detections tie to **ASI07 — Insecure Inter-Agent Communication**:

- Unauthenticated agent-to-agent messages
- Missing integrity protection
- Missing message signing
- No origin validation
- Cleartext channel
- Missing replay protection

## Related tools

- [`altais_audit_cascading_failures`](altais_audit_cascading_failures.md) — ASI08, containment of multi-agent failures
- [`altais_audit_memory_poisoning`](altais_audit_memory_poisoning.md) — ASI06, poisoning of shared agent state

## See also

- [`agentic` module](../modules/agentic.md)
- [Wiki home](../Home.md) · [Contributing](../Contributing.md) · [Deployment](../Deployment.md)
