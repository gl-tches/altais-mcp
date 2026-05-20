# `altais_audit_unsafe`

Audits Rust `unsafe` blocks and functions for soundness.

| Property | Value |
|----------|-------|
| Module | [`code`](../modules/code.md) |
| Tool type | Auditor (emits findings) |
| Annotations | `readOnlyHint: true` · `destructiveHint: false` · `idempotentHint: true` · `openWorldHint: false` |

## Description

Audits Rust `unsafe` blocks and functions for soundness: `unsafe` constructs with no `// SAFETY:` justification, `mem::transmute`, `static mut`, raw-pointer dereferences, `get_unchecked`, `slice::from_raw_parts`, `Vec::set_len`, `mem::uninitialized` / `MaybeUninit::assume_init`, and `ptr::read` / `ptr::write`. An agent calls this when reviewing Rust code that steps outside the borrow checker's guarantees.

## Input parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `source` | `string` (1–524288 chars) | Yes | Full Rust source code text to review. |
| `filename` | `string` (1–512 chars) | No | Filename used for the finding location. |

## Output

Returns `{ summary: { total, by_severity }, findings: [...] }`. Each finding has the standard shape `{ id, module, rule, severity, cwe, title, description, location?, evidence?, remediation, references, tags, status }`. Findings are appended to the session report.

## Example

**Request**

```json
{ "source": "unsafe { std::mem::transmute(x) }" }
```

**Response (excerpt)**

```json
{
  "summary": { "total": 2, "by_severity": { "high": 1, "low": 1 } },
  "findings": [
    { "rule": "transmute", "severity": "high", "status": "open" },
    { "rule": "missing-safety-comment", "severity": "low", "status": "open" }
  ]
}
```

## Detections

- `unsafe` construct with no `// SAFETY:` justification (CWE-1104)
- `mem::transmute` (CWE-704)
- `static mut` (CWE-362)
- Raw-pointer dereference (CWE-476, CWE-825)
- `get_unchecked` (CWE-125, CWE-787)
- `slice::from_raw_parts` (CWE-125, CWE-787)
- `Vec::set_len` (CWE-908)
- `mem::uninitialized` / `MaybeUninit::assume_init` (CWE-908)
- `ptr::read` / `ptr::write` (CWE-787)

## Related tools

- [`altais_check_memory_safety`](altais_check_memory_safety.md) — finds memory-safety defects in C / C++ / Rust
- [`altais_review_secure_coding`](altais_review_secure_coding.md) — broad secure-coding review

## See also

- [`code` module](../modules/code.md)
- [Wiki home](../Home.md) · [Contributing](../Contributing.md) · [Deployment](../Deployment.md)
