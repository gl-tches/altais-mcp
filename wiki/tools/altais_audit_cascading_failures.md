# `altais_audit_cascading_failures`

Audits a multi-agent system against OWASP ASI08 — Cascading Agent Failures.

| Property | Value |
|----------|-------|
| Module | [`agentic`](../modules/agentic.md) |
| Tool type | Auditor (emits findings) |
| Annotations | `readOnlyHint: true` · `destructiveHint: false` · `idempotentHint: true` · `openWorldHint: false` |

## Description

Audits a multi-agent system against **ASI08 — Cascading Agent Failures**. It flags a missing kill switch, missing circuit breakers, unbounded blast radius, no agent isolation, no failure detection, no inter-agent rate limits, and a missing or excessively high agent-chain depth limit. An agent calls this when reviewing how failures are contained across a multi-agent system.

## Input parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `source` | `string` (1–524288 chars) | No | Source code describing the agent system, scanned with pattern checks. |
| `filename` | `string` (1–512 chars) | No | Filename used for the finding location. |
| `config` | `object` | No | Structured description of the failure-containment controls. |
| `config.kill_switch` | `boolean` | No | A kill switch can halt agents on demand. |
| `config.circuit_breakers` | `boolean` | No | Circuit breakers cut off failing dependencies. |
| `config.blast_radius_limits` | `boolean` | No | The blast radius of any single agent is bounded. |
| `config.agent_isolation` | `boolean` | No | Agents are isolated from one another. |
| `config.failure_detection` | `boolean` | No | Failures are detected and surfaced. |
| `config.rate_limits_between_agents` | `boolean` | No | Rate limits apply to agent-to-agent calls. |
| `config.max_agent_chain_depth` | `integer` (1–10000) | No | The maximum agent-chain / delegation depth, if configured. |

## Output

Returns `{ summary: { total, by_severity }, findings: [...] }`. Each finding has the standard shape and carries the `owasp:asi08` tag. Findings are appended to the session report.

## Example

**Request**

```json
{ "config": { "kill_switch": false, "circuit_breakers": false } }
```

**Response (excerpt)**

```json
{
  "summary": { "total": 2, "by_severity": { "high": 1, "medium": 1 } },
  "findings": [
    { "rule": "no-kill-switch", "severity": "high", "tags": ["owasp:asi08"], "title": "No kill switch to halt agents", "status": "open" }
  ]
}
```

## Detections

All detections tie to **ASI08 — Cascading Agent Failures**:

- Missing kill switch
- Missing circuit breakers
- Unbounded blast radius
- No agent isolation
- No failure detection
- No inter-agent rate limits
- Missing or excessively high agent-chain depth limit

## Related tools

- [`altais_audit_inter_agent_comms`](altais_audit_inter_agent_comms.md) — ASI07, securing agent-to-agent messages
- [`altais_audit_rogue_agents`](altais_audit_rogue_agents.md) — ASI10, detecting and revoking misbehaving agents

## See also

- [`agentic` module](../modules/agentic.md)
- [Wiki home](../Home.md) · [Contributing](../Contributing.md) · [Deployment](../Deployment.md)
