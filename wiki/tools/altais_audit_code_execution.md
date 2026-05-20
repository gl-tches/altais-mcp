# `altais_audit_code_execution`

Audits an agent system against OWASP ASI05 — Unexpected Code Execution.

| Property | Value |
|----------|-------|
| Module | [`agentic`](../modules/agentic.md) |
| Tool type | Auditor (emits findings) |
| Annotations | `readOnlyHint: true` · `destructiveHint: false` · `idempotentHint: true` · `openWorldHint: false` |

## Description

Audits an agent system against **ASI05 — Unexpected Code Execution**. It flags execution of generated code with no sandbox, a sandbox with network or host filesystem access, no operation allowlist, and missing resource limits. It also scans `source` for `eval` / `exec` / `Function` / `child_process` on a line that references a model or LLM output variable. An agent calls this when reviewing whether an agent runs code it generates.

## Input parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `source` | `string` (1–524288 chars) | No | Source code describing the agent system, scanned with pattern checks. |
| `filename` | `string` (1–512 chars) | No | Filename used for the finding location. |
| `config` | `object` | No | Structured description of the code-execution controls. |
| `config.executes_generated_code` | `boolean` | No | The agent executes code it (or a model) generated. |
| `config.sandboxed` | `boolean` | No | Generated code runs inside a sandbox. |
| `config.sandbox_type` | `enum` | No | The sandbox technology: `none`, `process`, `container`, `microvm`, `wasm`, `gvisor`, or `firecracker`. |
| `config.allowlist_enforced` | `boolean` | No | Only an allowlist of operations / modules is permitted. |
| `config.network_access_in_sandbox` | `boolean` | No | The sandbox has network access. |
| `config.filesystem_access_in_sandbox` | `boolean` | No | The sandbox has host filesystem access. |
| `config.resource_limits` | `boolean` | No | CPU / memory / time resource limits are enforced on the sandbox. |

## Output

Returns `{ summary: { total, by_severity }, findings: [...] }`. Each finding has the standard shape and carries the `owasp:asi05` tag. Findings are appended to the session report.

## Example

**Request**

```json
{ "config": { "executes_generated_code": true, "sandboxed": false } }
```

**Response (excerpt)**

```json
{
  "summary": { "total": 1, "by_severity": { "critical": 1 } },
  "findings": [
    { "rule": "generated-code-no-sandbox", "severity": "critical", "tags": ["owasp:asi05"], "title": "Generated code executes with no sandbox", "status": "open" }
  ]
}
```

## Detections

All detections tie to **ASI05 — Unexpected Code Execution**:

- Generated code executed with no sandbox
- Sandbox with network access
- Sandbox with host filesystem access
- No operation / module allowlist
- Missing resource limits
- `eval` / `exec` / `Function` / `child_process` on a line referencing a model / LLM output variable

## Related tools

- [`altais_audit_agent_permissions`](altais_audit_agent_permissions.md) — the LLM-application counterpart (OWASP LLM06)
- [`altais_audit_output_handling`](altais_audit_output_handling.md) — LLM output flowing into `eval` / shell sinks

## See also

- [`agentic` module](../modules/agentic.md)
- [Wiki home](../Home.md) · [Contributing](../Contributing.md) · [Deployment](../Deployment.md)
