# `altais_audit_prompt_injection`

Analyzes prompt construction for injection vulnerabilities (OWASP LLM01).

| Property | Value |
|----------|-------|
| Module | [`ml_security`](../modules/ml_security.md) |
| Tool type | Auditor (emits findings) |
| Annotations | `readOnlyHint: true` · `destructiveHint: false` · `idempotentHint: true` · `openWorldHint: false` |

## Description

Analyzes prompt construction for injection vulnerabilities (OWASP LLM01): untrusted input concatenated or interpolated directly into a prompt string (f-strings, template literals, `+`), no separation of system instructions from user data, tool or retrieval output fed back to the model without sanitization, and missing input filtering or output validation. An agent calls this when reviewing how an LLM application builds prompts.

## Input parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `source` | `string` (1–524288 chars) | No | Source code to scan for risky patterns. |
| `config` | `object` (strict) | No | Structured description of the prompt-handling controls. |
| `config.instruction_data_separation` | `boolean` | No | Whether system instructions are separated from user data. |
| `config.input_filtering` | `boolean` | No | Whether user input is filtered before reaching the model. |
| `config.output_validation` | `boolean` | No | Whether model output is validated before being acted on. |
| `config.tool_output_sanitized` | `boolean` | No | Whether tool / retrieval output is sanitized. |
| `filename` | `string` (1–512 chars) | No | Filename used for the finding location. |

## Output

Returns `{ summary: { total, by_severity }, findings: [...] }`. Each finding has the standard shape `{ id, module, rule, severity, cwe, title, description, location?, evidence?, remediation, references, tags, status }`. Findings are appended to the session report.

## Example

**Request**

```json
{ "source": "prompt = f'You are a bot. {user_input}'" }
```

**Response (excerpt)**

```json
{
  "summary": { "total": 1, "by_severity": { "high": 1 } },
  "findings": [
    { "rule": "untrusted-input-in-prompt", "severity": "high", "cwe": ["CWE-1427"], "title": "Untrusted input interpolated into a prompt", "status": "open" }
  ]
}
```

## Detections

- Untrusted input concatenated / interpolated into a prompt string — f-strings, template literals, `+` (OWASP LLM01, CWE-1427)
- No separation of system instructions from user data
- Tool / retrieval output fed to the model without sanitization
- Missing input filtering
- Missing output validation

## Related tools

- [`altais_check_llm_top10`](altais_check_llm_top10.md) — full OWASP LLM Top 10 coverage report
- [`altais_audit_output_handling`](altais_audit_output_handling.md) — audits how LLM output is consumed downstream
- [`altais_audit_goal_hijack`](altais_audit_goal_hijack.md) — the agentic counterpart (ASI01)

## See also

- [`ml_security` module](../modules/ml_security.md)
- [Wiki home](../Home.md) · [Contributing](../Contributing.md) · [Deployment](../Deployment.md)
