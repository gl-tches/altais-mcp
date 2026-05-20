# `altais_audit_agent_identity`

Audits an agent system against OWASP ASI03 — Identity & Privilege Abuse.

| Property | Value |
|----------|-------|
| Module | [`agentic`](../modules/agentic.md) |
| Tool type | Auditor (emits findings) |
| Annotations | `readOnlyHint: true` · `destructiveHint: false` · `idempotentHint: true` · `openWorldHint: false` |

## Description

Audits an agent system against **ASI03 — Identity & Privilege Abuse**. It flags shared or inherited identity, runtime privilege-escalation paths, missing confused-deputy protection, cross-session credential retention, unscoped credentials, and conflation of the user's identity with the agent's. An agent calls this when reviewing how identity and privileges are modeled for agents.

## Input parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `source` | `string` (1–524288 chars) | No | Source code describing the agent system, scanned with pattern checks. |
| `filename` | `string` (1–512 chars) | No | Filename used for the finding location. |
| `config` | `object` | No | Structured description of the identity / privilege model. |
| `config.per_agent_identity` | `boolean` | No | Each agent runs under its own distinct identity. |
| `config.privilege_inheritance` | `boolean` | No | Agents inherit the privileges of the caller / parent. |
| `config.can_escalate_privileges` | `boolean` | No | An agent can escalate its own privileges at runtime. |
| `config.confused_deputy_protection` | `boolean` | No | Confused-deputy protection (the caller's authority is checked). |
| `config.cross_session_credential_retention` | `boolean` | No | Credentials are retained across sessions. |
| `config.scoped_credentials` | `boolean` | No | Credentials issued to the agent are narrowly scoped. |
| `config.human_user_distinct_from_agent` | `boolean` | No | The human user's identity is kept distinct from the agent's. |

## Output

Returns `{ summary: { total, by_severity }, findings: [...] }`. Each finding has the standard shape and carries the `owasp:asi03` tag. Findings are appended to the session report.

## Example

**Request**

```json
{ "config": { "privilege_inheritance": true, "confused_deputy_protection": false } }
```

**Response (excerpt)**

```json
{
  "summary": { "total": 2, "by_severity": { "high": 1, "medium": 1 } },
  "findings": [
    { "rule": "privilege-inheritance", "severity": "high", "tags": ["owasp:asi03"], "title": "Agents inherit caller / parent privileges", "status": "open" }
  ]
}
```

## Detections

All detections tie to **ASI03 — Identity & Privilege Abuse**:

- Shared / inherited agent identity
- Runtime privilege-escalation paths
- Missing confused-deputy protection
- Cross-session credential retention
- Unscoped credentials
- Conflation of the user's identity with the agent's

## Related tools

- [`altais_audit_tool_misuse`](altais_audit_tool_misuse.md) — ASI02, over-permissioned tool APIs
- [`altais_audit_rogue_agents`](altais_audit_rogue_agents.md) — ASI10, detection and revocation of misbehaving agents

## See also

- [`agentic` module](../modules/agentic.md)
- [Wiki home](../Home.md) · [Contributing](../Contributing.md) · [Deployment](../Deployment.md)
