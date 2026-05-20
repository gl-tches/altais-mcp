# `altais_scan_diff`

Parse a unified diff and scan the touched hunks, reporting only findings on added lines.

| Property | Value |
|----------|-------|
| Module | [`scan`](../modules/scan.md) |
| Tool type | Auditor (emits findings) |
| Annotations | `readOnlyHint: true` · `destructiveHint: false` · `idempotentHint: true` · `openWorldHint: false` |

## Description

Parses a unified diff (such as `git diff` output), runs the scan module's pattern engine against the touched hunks of every changed file, and remaps finding locations to absolute line numbers. Only findings that overlap a line added by the diff are reported, so it surfaces issues a change introduced rather than pre-existing ones. An agent calls this to review a pull request or staged change.

## Input parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `diff` | `string` (1 char to the configured `max_source_bytes`) | Yes | Unified diff text, e.g. `git diff` output. |
| `rules` | `string[]` (up to 64 items, each 1–128 chars) | No | Restrict to specific pattern IDs or category names. Empty means all enabled rules run. |

## Output

`{ files: [{ path, language, findings }], summary: { total, by_severity }, findings: [...] }`. The `files` array reports a per-file finding count; `findings` carries the standard finding shape with locations remapped onto the changed file. Findings are appended to the session report.

## Example

**Request**

```json
{ "diff": "--- a/app.py\n+++ b/app.py\n@@ -1 +1,2 @@\n+os.system(user_input)\n" }
```

**Response (excerpt)**

```json
{
  "files": [{ "path": "app.py", "language": "python", "findings": 1 }],
  "summary": { "total": 1, "by_severity": { "high": 1 } },
  "findings": ["..."]
}
```

## Detections

Same pattern coverage as [`altais_scan_code`](altais_scan_code.md): injection, XSS, SSRF, path traversal, exceptional conditions, prototype pollution, SSTI, ReDoS, race conditions, insecure deserialization, business-logic flaws, request smuggling, cache poisoning, CRLF injection, and host-header injection. Files with an unsupported or undetected language are listed with a zero finding count. Findings that do not touch an added line are filtered out.

## Related tools

- [`altais_scan_code`](altais_scan_code.md) — scans a full source snippet, not just changed lines
- [`altais_scan_file`](altais_scan_file.md) — scans a file on disk by path

## See also

- [`scan` module](../modules/scan.md)
- [Wiki home](../Home.md) · [Contributing](../Contributing.md) · [Deployment](../Deployment.md)
