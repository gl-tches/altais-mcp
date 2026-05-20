# `altais_scan_code`

Run security pattern detection against inline source code.

| Property | Value |
|----------|-------|
| Module | [`scan`](../modules/scan.md) |
| Tool type | Auditor (emits findings) |
| Annotations | `readOnlyHint: true` · `destructiveHint: false` · `idempotentHint: true` · `openWorldHint: false` |

## Description

Applies the scan module's pattern engine to a string of source code (TypeScript, JavaScript, Python, Go, or Rust). It detects 15 vulnerability classes spanning injection, XSS, SSRF, and more without executing the code. An agent calls this to scan a code snippet it just generated or received before committing it.

## Input parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `source` | `string` (1 char to the configured `max_source_bytes`) | Yes | Source code to scan. |
| `language` | `string` (1–32 chars) | No | Language hint, e.g. `typescript`, `python`. Auto-detected from `filename`/`source` if omitted. |
| `filename` | `string` (1–512 chars) | No | Filename used for reporting and language detection. |
| `rules` | `string[]` (up to 64 items, each 1–128 chars) | No | Restrict to specific pattern IDs or category names. Empty means all enabled rules run. |

## Output

`{ language, summary: { total, by_severity }, findings: [...] }`. Each finding has the standard shape (`id`, `module`, `rule`, `severity`, `cwe`, `title`, `description`, `location?`, `evidence?`, `remediation`, `references`, `tags`, `status`). Findings are also appended to the session report. If the language cannot be detected or is unsupported, an error result is returned.

## Example

**Request**

```json
{ "source": "db.query('SELECT * FROM users WHERE id = ' + req.params.id)", "language": "javascript" }
```

**Response (excerpt)**

```json
{
  "language": "javascript",
  "summary": { "total": 1, "by_severity": { "high": 1 } },
  "findings": [
    {
      "id": "scan:sql-injection:ab12cd34ef56",
      "module": "scan",
      "rule": "sql-injection",
      "severity": "high",
      "cwe": ["CWE-89"],
      "title": "Possible SQL injection",
      "remediation": "Use parameterized queries.",
      "status": "open"
    }
  ]
}
```

## Detections

Main vulnerability classes detected:

- Injection — SQL, command, and related injection (CWE-89, CWE-78)
- Cross-site scripting (CWE-79)
- Server-side request forgery (CWE-918)
- Path traversal (CWE-22)
- Mishandling of exceptional conditions
- Prototype pollution (CWE-1321)
- Server-side template injection
- Regular-expression denial of service (ReDoS)
- Race conditions
- Insecure deserialization (CWE-502)
- Business-logic flaws
- HTTP request smuggling
- Web cache poisoning
- CRLF injection (CWE-93)
- Host-header injection

## Related tools

- [`altais_scan_file`](altais_scan_file.md) — runs the same patterns against a file on disk
- [`altais_scan_diff`](altais_scan_diff.md) — runs the same patterns against a unified diff

## See also

- [`scan` module](../modules/scan.md)
- [Wiki home](../Home.md) · [Contributing](../Contributing.md) · [Deployment](../Deployment.md)
