# `altais_audit_tool_misuse`

Audits an agent system against OWASP ASI02 — Tool Misuse & Exploitation.

| Property | Value |
|----------|-------|
| Module | [`agentic`](../modules/agentic.md) |
| Tool type | Auditor (emits findings) |
| Annotations | `readOnlyHint: true` · `destructiveHint: false` · `idempotentHint: true` · `openWorldHint: false` |

## Description

Audits an agent system against **ASI02 — Tool Misuse & Exploitation**. It flags over-permissioned tool APIs, unverified or poisonable MCP tool descriptors, a missing tool allowlist, unvalidated tool arguments, missing tool-output validation, no rate limiting, and tools registered with wildcard or admin scope. An agent calls this when reviewing how an agent integrates and invokes tools.

## Input parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `source` | `string` (1–524288 chars) | No | Source code describing the agent system, scanned with pattern checks. |
| `filename` | `string` (1–512 chars) | No | Filename used for the finding location. |
| `config` | `object` | No | Structured description of the tool integration. |
| `config.tools` | `array` of `object` (max 512) | No | The agent's tools, each `{ name, scope? }`. |
| `config.tools[].name` | `string` (1–256 chars) | Yes | The tool's name. |
| `config.tools[].scope` | `string` (1–256 chars) | No | The tool's permission scope. |
| `config.tool_allowlist` | `boolean` | No | Only an explicit allowlist of tools may be invoked. |
| `config.tool_descriptors_verified` | `boolean` | No | MCP tool descriptors are verified against tampering / tool poisoning. |
| `config.over_permissioned_apis` | `boolean` | No | One or more tool APIs hold broader permissions than needed. |
| `config.input_validation_on_tool_args` | `boolean` | No | Tool arguments are schema-validated before invocation. |
| `config.tool_output_validation` | `boolean` | No | Tool output is validated before the agent consumes it. |
| `config.rate_limited` | `boolean` | No | Tool invocations are rate-limited. |

## Output

Returns `{ summary: { total, by_severity }, findings: [...] }`. Each finding has the standard shape and carries the `owasp:asi02` tag. Findings are appended to the session report.

## Example

**Request**

```json
{ "config": { "tool_allowlist": false, "tool_descriptors_verified": false } }
```

**Response (excerpt)**

```json
{
  "summary": { "total": 2, "by_severity": { "high": 1, "medium": 1 } },
  "findings": [
    { "rule": "no-tool-allowlist", "severity": "medium", "tags": ["owasp:asi02"], "title": "No explicit tool allowlist", "status": "open" }
  ]
}
```

## Detections

All detections tie to **ASI02 — Tool Misuse & Exploitation**:

- Over-permissioned tool APIs
- Unverified / poisonable MCP tool descriptors
- Missing tool allowlist
- Unvalidated tool arguments
- Missing tool-output validation
- No rate limiting on tool invocations
- Tools registered with wildcard / admin scope

## Related tools

- [`altais_audit_agent_permissions`](altais_audit_agent_permissions.md) — the LLM-application counterpart (OWASP LLM06)
- [`altais_audit_agentic_supply_chain`](altais_audit_agentic_supply_chain.md) — ASI04, trust of tool / server components

## See also

- [`agentic` module](../modules/agentic.md)
- [Wiki home](../Home.md) · [Contributing](../Contributing.md) · [Deployment](../Deployment.md)
