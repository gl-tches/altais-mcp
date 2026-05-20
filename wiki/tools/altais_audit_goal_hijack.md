# `altais_audit_goal_hijack`

Audits an agent system against OWASP ASI01 — Agent Goal Hijacking.

| Property | Value |
|----------|-------|
| Module | [`agentic`](../modules/agentic.md) |
| Tool type | Auditor (emits findings) |
| Annotations | `readOnlyHint: true` · `destructiveHint: false` · `idempotentHint: true` · `openWorldHint: false` |

## Description

Audits an agent system against **ASI01 — Agent Goal Hijacking**. It flags missing separation of trusted instructions from untrusted data, tool or retrieval output feeding the planner without validation, no goal or plan validation, an unprotected system prompt, and no plan review. An agent calls this when reviewing how a planner accepts goals and data.

## Input parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `source` | `string` (1–524288 chars) | No | Source code describing the agent system, scanned with pattern checks. |
| `filename` | `string` (1–512 chars) | No | Filename used for the finding location. |
| `config` | `object` | No | Structured description of the goal / planning controls. |
| `config.instruction_data_separation` | `boolean` | No | Trusted instructions are structurally separated from untrusted data. |
| `config.goal_validation` | `boolean` | No | The agent validates its goal / plan before acting. |
| `config.untrusted_tool_output_to_planner` | `boolean` | No | Tool / retrieval output is fed to the planner without validation. |
| `config.untrusted_data_to_planner` | `boolean` | No | Untrusted external data is fed to the planner without validation. |
| `config.system_prompt_protected` | `boolean` | No | The system prompt is protected from runtime override. |
| `config.plan_review` | `boolean` | No | A human or policy reviews the plan before high-impact execution. |

## Output

Returns `{ summary: { total, by_severity }, findings: [...] }`. Each finding has the standard shape `{ id, module, rule, severity, cwe, title, description, location?, evidence?, remediation, references, tags, status }` and carries the `owasp:asi01` tag. Findings are appended to the session report.

## Example

**Request**

```json
{ "config": { "instruction_data_separation": false, "plan_review": false } }
```

**Response (excerpt)**

```json
{
  "summary": { "total": 2, "by_severity": { "high": 1, "medium": 1 } },
  "findings": [
    { "rule": "no-instruction-data-separation", "severity": "high", "tags": ["owasp:asi01"], "title": "Trusted instructions are not separated from untrusted data", "status": "open" }
  ]
}
```

## Detections

All detections tie to **ASI01 — Agent Goal Hijacking**:

- No separation of trusted instructions from untrusted data
- Tool / retrieval output feeding the planner without validation
- Untrusted external data feeding the planner without validation
- No goal or plan validation
- Unprotected system prompt
- No plan review before high-impact execution

## Related tools

- [`altais_audit_memory_poisoning`](altais_audit_memory_poisoning.md) — ASI06, poisoning of persisted context
- [`altais_audit_prompt_injection`](altais_audit_prompt_injection.md) — the LLM-application counterpart (OWASP LLM01)

## See also

- [`agentic` module](../modules/agentic.md)
- [Wiki home](../Home.md) · [Contributing](../Contributing.md) · [Deployment](../Deployment.md)
