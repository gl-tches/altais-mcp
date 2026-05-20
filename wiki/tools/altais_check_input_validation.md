# `altais_check_input_validation`

Verifies that request and external input is validated before use.

| Property | Value |
|----------|-------|
| Module | [`code`](../modules/code.md) |
| Tool type | Auditor (emits findings) |
| Annotations | `readOnlyHint: true` · `destructiveHint: false` · `idempotentHint: true` · `openWorldHint: false` |

## Description

Verifies that request and external input is validated before use: untrusted input (`req.body`, `request.form`, `os.Args`) consumed with no recognized validator (Zod, Joi, yup, express-validator, pydantic), `parseInt` without an explicit radix, and unbounded regular expressions applied to user input (ReDoS risk). An agent calls this when reviewing whether a handler validates the data it receives.

## Input parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `source` | `string` (1–524288 chars) | Yes | Full source code text to review. |
| `language` | `enum` | Yes | One of `c`, `cpp`, `java`, `python`, `javascript`, `typescript`, `go` — selects language-specific patterns. |
| `filename` | `string` (1–512 chars) | No | Filename used for the finding location. |

## Output

Returns `{ summary: { total, by_severity }, findings: [...] }`. Each finding has the standard shape `{ id, module, rule, severity, cwe, title, description, location?, evidence?, remediation, references, tags, status }`. Findings are appended to the session report.

## Example

**Request**

```json
{ "source": "const id = parseInt(req.body.id)", "language": "javascript" }
```

**Response (excerpt)**

```json
{
  "summary": { "total": 2, "by_severity": { "low": 1, "medium": 1 } },
  "findings": [
    { "rule": "parseint-without-radix", "severity": "low", "status": "open" },
    { "rule": "unvalidated-request-input", "severity": "medium", "status": "open" }
  ]
}
```

## Detections

- Untrusted input (`req.body`, `request.form`, `os.Args`) consumed with no recognized validator — Zod, Joi, yup, express-validator, pydantic (CWE-20)
- `parseInt` without an explicit radix (CWE-704)
- Unbounded regular expression applied to user input — ReDoS risk (CWE-1333)

## Related tools

- [`altais_review_secure_coding`](altais_review_secure_coding.md) — broad secure-coding review
- [`altais_check_error_handling`](altais_check_error_handling.md) — checks error handling for information leakage

## See also

- [`code` module](../modules/code.md)
- [Wiki home](../Home.md) · [Contributing](../Contributing.md) · [Deployment](../Deployment.md)
