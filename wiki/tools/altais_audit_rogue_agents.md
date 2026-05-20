# `altais_audit_rogue_agents`

Audits an agent system against OWASP ASI10 — Rogue Agents.

| Property | Value |
|----------|-------|
| Module | [`agentic`](../modules/agentic.md) |
| Tool type | Auditor (emits findings) |
| Annotations | `readOnlyHint: true` · `destructiveHint: false` · `idempotentHint: true` · `openWorldHint: false` |

## Description

Audits an agent system against **ASI10 — Rogue Agents**. It flags a missing behavioral baseline, missing or partial anomaly detection, no agent inventory or governance policy, no sandboxing, no audit logging, and no revocation or kill capability. An agent calls this when reviewing how an organization detects and contains misbehaving agents.

## Input parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `source` | `string` (1–524288 chars) | No | Source code describing the agent system, scanned with pattern checks. |
| `filename` | `string` (1–512 chars) | No | Filename used for the finding location. |
| `config` | `object` | No | Structured description of the rogue-agent governance controls. |
| `config.behavioral_baseline` | `boolean` | No | A behavioral baseline exists for normal agent activity. |
| `config.anomaly_detection` | `boolean` | No | Anomaly detection runs against agent behavior. |
| `config.anomaly_detection_coverage` | `enum` | No | Coverage of anomaly detection: `none`, `partial`, or `comprehensive`. |
| `config.agent_inventory` | `boolean` | No | A complete inventory of agents is maintained. |
| `config.agent_governance_policy` | `boolean` | No | An agent governance policy is defined and enforced. |
| `config.sandboxing` | `boolean` | No | Agents run in a sandbox. |
| `config.audit_logging` | `boolean` | No | Agent actions are recorded in an audit log. |
| `config.revocation_capability` | `boolean` | No | A rogue agent can be revoked / killed. |

## Output

Returns `{ summary: { total, by_severity }, findings: [...] }`. Each finding has the standard shape and carries the `owasp:asi10` tag. Findings are appended to the session report.

## Example

**Request**

```json
{ "config": { "anomaly_detection": false, "revocation_capability": false } }
```

**Response (excerpt)**

```json
{
  "summary": { "total": 2, "by_severity": { "high": 1, "medium": 1 } },
  "findings": [
    { "rule": "no-anomaly-detection", "severity": "high", "tags": ["owasp:asi10"], "title": "No anomaly detection on agent behavior", "status": "open" }
  ]
}
```

## Detections

All detections tie to **ASI10 — Rogue Agents**:

- Missing behavioral baseline
- Missing or partial anomaly detection
- No agent inventory
- No agent governance policy
- No sandboxing
- No audit logging
- No revocation / kill capability

## Related tools

- [`altais_audit_agent_identity`](altais_audit_agent_identity.md) — ASI03, identity and privilege model
- [`altais_audit_cascading_failures`](altais_audit_cascading_failures.md) — ASI08, containing the blast radius of a rogue agent

## See also

- [`agentic` module](../modules/agentic.md)
- [Wiki home](../Home.md) · [Contributing](../Contributing.md) · [Deployment](../Deployment.md)
