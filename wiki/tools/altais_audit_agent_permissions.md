# `altais_audit_agent_permissions`

Checks an LLM agent for excessive agency (OWASP LLM06).

| Property | Value |
|----------|-------|
| Module | [`ml_security`](../modules/ml_security.md) |
| Tool type | Auditor (emits findings) |
| Annotations | `readOnlyHint: true` · `destructiveHint: false` · `idempotentHint: true` · `openWorldHint: false` |

## Description

Checks an LLM agent for excessive agency (OWASP LLM06): too many tools or excessive functionality, broad or wildcard permission scopes, destructive or high-impact actions (spend money, modify data, execute code) with no human-in-the-loop approval, and fully autonomous high-risk operation. An agent calls this when reviewing the capabilities granted to an LLM agent.

## Input parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `config` | `object` (strict) | Yes | Structured description of the agent's tools and permissions. |
| `config.tools` | `array` of `object` (max 256) | No | The agent's tools, each `{ name, scope? }`. |
| `config.tools[].name` | `string` (1–128 chars) | Yes | The tool's name. |
| `config.tools[].scope` | `string` (1–256 chars) | No | The tool's permission scope. |
| `config.tool_count` | `integer` (0–100000) | No | Number of tools the agent holds. |
| `config.has_destructive_tools` | `boolean` | No | Whether any tool performs destructive actions. |
| `config.human_approval_required` | `boolean` | No | Whether high-impact actions require human approval. |
| `config.permission_scopes` | `array` of `string` (1–256 chars, max 256) | No | Permission scopes granted to the agent. |
| `config.autonomous` | `boolean` | No | Whether the agent runs fully autonomously. |
| `config.can_spend_money` | `boolean` | No | Whether the agent can spend money. |
| `config.can_modify_data` | `boolean` | No | Whether the agent can modify / delete data. |
| `config.can_execute_code` | `boolean` | No | Whether the agent can execute code. |
| `filename` | `string` (1–512 chars) | No | Filename used for the finding location. |

## Output

Returns `{ summary: { total, by_severity }, findings: [...] }`. Each finding has the standard shape `{ id, module, rule, severity, cwe, title, description, location?, evidence?, remediation, references, tags, status }`. Findings are appended to the session report.

## Example

**Request**

```json
{ "config": { "can_modify_data": true, "human_approval_required": false, "autonomous": true } }
```

**Response (excerpt)**

```json
{
  "summary": { "total": 1, "by_severity": { "high": 1 } },
  "findings": [
    { "rule": "destructive-action-no-approval", "severity": "high", "cwe": ["CWE-862"], "title": "Destructive action with no human approval", "status": "open" }
  ]
}
```

## Detections

- Too many tools / excessive functionality
- Broad or wildcard permission scopes
- Destructive / high-impact actions — spend money, modify data, execute code — with no human-in-the-loop approval (CWE-862, CWE-269)
- Fully autonomous high-risk operation

## Related tools

- [`altais_check_llm_top10`](altais_check_llm_top10.md) — full OWASP LLM Top 10 coverage report
- [`altais_audit_tool_misuse`](altais_audit_tool_misuse.md) — the agentic counterpart (ASI02)
- [`altais_audit_code_execution`](altais_audit_code_execution.md) — audits generated-code execution (ASI05)

## See also

- [`ml_security` module](../modules/ml_security.md)
- [Wiki home](../Home.md) · [Contributing](../Contributing.md) · [Deployment](../Deployment.md)
