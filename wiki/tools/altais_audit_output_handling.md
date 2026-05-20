# `altais_audit_output_handling`

Verifies LLM output is sanitized before downstream use (OWASP LLM05).

| Property | Value |
|----------|-------|
| Module | [`ml_security`](../modules/ml_security.md) |
| Tool type | Auditor (emits findings) |
| Annotations | `readOnlyHint: true` · `destructiveHint: false` · `idempotentHint: true` · `openWorldHint: false` |

## Description

Verifies LLM output is sanitized before downstream use (OWASP LLM05): model output passed unsanitized into HTML or the DOM, into SQL, into a shell or `exec`, into `eval` / `Function`, into a file path, or returned to the user as trusted content. An agent calls this when reviewing how an LLM application consumes model output.

## Input parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `source` | `string` (1–524288 chars) | No | Source code to scan for risky patterns. |
| `config` | `object` (strict) | No | Structured description of the output-handling controls. |
| `config.html_encoded` | `boolean` | No | Whether model output is HTML-encoded before rendering. |
| `config.sql_parameterized` | `boolean` | No | Whether model output reaching SQL is parameterized. |
| `config.shell_safe` | `boolean` | No | Whether model output is kept out of shell / exec calls. |
| `config.schema_validated` | `boolean` | No | Whether model output is validated against a schema. |
| `config.treated_as_trusted` | `boolean` | No | Whether model output is treated as trusted. |
| `filename` | `string` (1–512 chars) | No | Filename used for the finding location. |

## Output

Returns `{ summary: { total, by_severity }, findings: [...] }`. Each finding has the standard shape `{ id, module, rule, severity, cwe, title, description, location?, evidence?, remediation, references, tags, status }`. Findings are appended to the session report.

## Example

**Request**

```json
{ "source": "element.innerHTML = llmResponse" }
```

**Response (excerpt)**

```json
{
  "summary": { "total": 1, "by_severity": { "high": 1 } },
  "findings": [
    { "rule": "llm-output-to-dom", "severity": "high", "cwe": ["CWE-79"], "title": "LLM output written unsanitized to the DOM", "status": "open" }
  ]
}
```

## Detections

- LLM output into HTML / the DOM — XSS (CWE-79)
- LLM output into SQL (CWE-89)
- LLM output into a shell / `exec` — command injection (CWE-78)
- LLM output into `eval` / `Function` — code injection (CWE-95)
- LLM output into a file path — path traversal (CWE-22)
- LLM output returned to the user as trusted content

## Related tools

- [`altais_audit_prompt_injection`](altais_audit_prompt_injection.md) — audits prompt construction (OWASP LLM01)
- [`altais_check_llm_top10`](altais_check_llm_top10.md) — full OWASP LLM Top 10 coverage report

## See also

- [`ml_security` module](../modules/ml_security.md)
- [Wiki home](../Home.md) · [Contributing](../Contributing.md) · [Deployment](../Deployment.md)
