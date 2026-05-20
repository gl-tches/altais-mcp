# `altais_check_error_handling`

Detects error handling that leaks sensitive information or hides failures.

| Property | Value |
|----------|-------|
| Module | [`code`](../modules/code.md) |
| Tool type | Auditor (emits findings) |
| Annotations | `readOnlyHint: true` · `destructiveHint: false` · `idempotentHint: true` · `openWorldHint: false` |

## Description

Detects error handling that leaks sensitive information or hides failures: stack traces and raw exception messages returned to clients, `printStackTrace()` near responses, Python tracebacks in responses, empty or swallowed `catch` blocks, bare `except: pass`, overly broad exception handlers, and debug mode left enabled. An agent calls this when reviewing how a code path catches, reports, and surfaces errors.

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
{ "source": "} catch (e) { res.send(e.stack); }", "language": "javascript" }
```

**Response (excerpt)**

```json
{
  "summary": { "total": 1, "by_severity": { "medium": 1 } },
  "findings": [
    {
      "rule": "stack-trace-in-response",
      "severity": "medium",
      "cwe": ["CWE-209"],
      "title": "Stack trace returned to the client",
      "status": "open"
    }
  ]
}
```

## Detections

- Stack traces and raw exception messages returned to clients (CWE-209)
- `printStackTrace()` near a response (CWE-209)
- Python tracebacks returned in responses (CWE-209)
- Empty or swallowed `catch` blocks (CWE-390)
- Bare `except: pass` (CWE-390)
- Overly broad exception handlers (CWE-396)
- Debug mode left enabled (CWE-489)

## Related tools

- [`altais_review_secure_coding`](altais_review_secure_coding.md) — broad secure-coding review
- [`altais_check_input_validation`](altais_check_input_validation.md) — checks input validation coverage

## See also

- [`code` module](../modules/code.md)
- [Wiki home](../Home.md) · [Contributing](../Contributing.md) · [Deployment](../Deployment.md)
