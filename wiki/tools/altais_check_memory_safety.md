# `altais_check_memory_safety`

Detects memory-safety defects in C, C++, and Rust source code.

| Property | Value |
|----------|-------|
| Module | [`code`](../modules/code.md) |
| Tool type | Auditor (emits findings) |
| Annotations | `readOnlyHint: true` · `destructiveHint: false` · `idempotentHint: true` · `openWorldHint: false` |

## Description

Detects memory-safety defects. In C / C++ it flags unbounded string functions (`strcpy`, `strcat`, `sprintf`, `gets`, `scanf("%s")`), allocation results used without a NULL check, `memcpy` / `memmove` with an unchecked size, `alloca`, double free, and use-after-free. In Rust it flags `get_unchecked`, `slice::from_raw_parts`, `Vec::set_len`, and uninitialized-memory use. An agent calls this when reviewing systems code for buffer and lifetime bugs.

## Input parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `source` | `string` (1–524288 chars) | Yes | Full source code text to review. |
| `language` | `enum` | Yes | One of `c`, `cpp`, `rust`. |
| `filename` | `string` (1–512 chars) | No | Filename used for the finding location. |

## Output

Returns `{ summary: { total, by_severity }, findings: [...] }`. Each finding has the standard shape `{ id, module, rule, severity, cwe, title, description, location?, evidence?, remediation, references, tags, status }`. Findings are appended to the session report.

## Example

**Request**

```json
{ "source": "strcpy(dst, src);", "language": "c" }
```

**Response (excerpt)**

```json
{
  "summary": { "total": 1, "by_severity": { "high": 1 } },
  "findings": [
    {
      "rule": "unbounded-string-function",
      "severity": "high",
      "cwe": ["CWE-120"],
      "title": "Unbounded string function",
      "status": "open"
    }
  ]
}
```

## Detections

- Unbounded string functions — `strcpy`, `strcat`, `sprintf`, `gets`, `scanf("%s")` (CWE-120, CWE-242)
- Allocation result used without a NULL check (CWE-476)
- `memcpy` / `memmove` with an unchecked size (CWE-787, CWE-120)
- `alloca` (CWE-770)
- Double free (CWE-415)
- Use-after-free (CWE-416)
- Rust `get_unchecked`, `slice::from_raw_parts`, `Vec::set_len` (CWE-125, CWE-787)
- Rust uninitialized-memory use (CWE-908)

## Related tools

- [`altais_audit_unsafe`](altais_audit_unsafe.md) — audits Rust `unsafe` code for soundness
- [`altais_review_secure_coding`](altais_review_secure_coding.md) — broad secure-coding review

## See also

- [`code` module](../modules/code.md)
- [Wiki home](../Home.md) · [Contributing](../Contributing.md) · [Deployment](../Deployment.md)
