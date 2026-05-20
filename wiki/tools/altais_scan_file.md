# `altais_scan_file`

Read a file from disk and run the scan patterns against it.

| Property | Value |
|----------|-------|
| Module | [`scan`](../modules/scan.md) |
| Tool type | Auditor (emits findings) |
| Annotations | `readOnlyHint: true` · `destructiveHint: false` · `idempotentHint: true` · `openWorldHint: false` |

## Description

Resolves a file path against the configured `scan_root`, canonicalizes it (rejecting symlinks that escape the root), reads it, and runs the scan module's pattern engine over its contents. The same 15 vulnerability classes as `altais_scan_code` are detected. An agent calls this to scan an existing project file by path rather than pasting its contents.

## Input parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `path` | `string` (1–2048 chars) | Yes | File path to scan, resolved against the configured `scan_root`. |
| `rules` | `string[]` (up to 64 items, each 1–128 chars) | No | Restrict to specific pattern IDs or category names. Empty means all enabled rules run. |

## Output

`{ file, language, summary: { total, by_severity }, findings: [...] }`, where `file` is the path relative to `scan_root`. Findings carry the standard shape and are appended to the session report. Error results are returned when the file is missing, escapes `scan_root`, is not a regular file, exceeds the size limit, or has an unsupported language.

## Example

**Request**

```json
{ "path": "src/handlers/user.ts" }
```

**Response (excerpt)**

```json
{
  "file": "src/handlers/user.ts",
  "language": "typescript",
  "summary": { "total": 1, "by_severity": { "high": 1 } },
  "findings": ["..."]
}
```

## Detections

Same pattern coverage as [`altais_scan_code`](altais_scan_code.md): injection, XSS, SSRF, path traversal, exceptional conditions, prototype pollution, SSTI, ReDoS, race conditions, insecure deserialization, business-logic flaws, request smuggling, cache poisoning, CRLF injection, and host-header injection. The path is enforced to stay within `scan_root`; symlinks pointing outside it are rejected.

## Related tools

- [`altais_scan_code`](altais_scan_code.md) — scans inline source instead of a file path
- [`altais_scan_diff`](altais_scan_diff.md) — scans a unified diff, reporting only changed lines

## See also

- [`scan` module](../modules/scan.md)
- [Wiki home](../Home.md) · [Contributing](../Contributing.md) · [Deployment](../Deployment.md)
