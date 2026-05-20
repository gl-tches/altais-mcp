# `altais_review_secure_coding`

Reviews source code against CERT secure-coding guidance.

| Property | Value |
|----------|-------|
| Module | [`code`](../modules/code.md) |
| Tool type | Auditor (emits findings) |
| Annotations | `readOnlyHint: true` · `destructiveHint: false` · `idempotentHint: true` · `openWorldHint: false` |

## Description

Reviews source code against CERT secure-coding guidance: non-literal `printf`-family format strings, integer-overflow risks in size and allocation expressions, ignored security-relevant return values, time-of-check/time-of-use file races, dangerous process and evaluation APIs (`system`, `popen`, `eval`), `switch` statements with no `default`, and signed/unsigned comparison mismatches. An agent calls this for a broad secure-coding review of a source file in a supported language.

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
{ "source": "printf(user_input);", "language": "c" }
```

**Response (excerpt)**

```json
{
  "summary": { "total": 1, "by_severity": { "high": 1 } },
  "findings": [
    {
      "rule": "format-string",
      "severity": "high",
      "cwe": ["CWE-134"],
      "title": "Non-literal format string",
      "status": "open"
    }
  ]
}
```

## Detections

- Non-literal `printf`-family format strings (CWE-134)
- Integer-overflow risk in size and allocation expressions (CWE-190)
- Ignored security-relevant return values (CWE-252)
- Time-of-check/time-of-use file races (CWE-367)
- Dangerous process / evaluation APIs — `system`, `popen`, `eval` (CWE-78, CWE-95)
- `switch` statement with no `default` case (CWE-478)
- Signed/unsigned comparison mismatch (CWE-697)

## Related tools

- [`altais_audit_unsafe`](altais_audit_unsafe.md) — audits Rust `unsafe` code
- [`altais_check_memory_safety`](altais_check_memory_safety.md) — finds memory-safety defects in C / C++ / Rust
- [`altais_check_input_validation`](altais_check_input_validation.md) — checks input validation coverage

## See also

- [`code` module](../modules/code.md)
- [Wiki home](../Home.md) · [Contributing](../Contributing.md) · [Deployment](../Deployment.md)
