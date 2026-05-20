# `altais_audit_dockerfile`

Analyzes a Dockerfile for security best-practice violations.

| Property | Value |
|----------|-------|
| Module | [`container`](../modules/container.md) |
| Tool type | Auditor (emits findings) |
| Annotations | `readOnlyHint: true` · `destructiveHint: false` · `idempotentHint: true` · `openWorldHint: false` |

## Description

Analyzes the text of a Dockerfile for security best-practice violations: running as root, mutable or `latest` base-image tags, `ADD` of remote URLs, remote scripts piped into a shell, credentials baked into `ENV`/`ARG`, world-writable `chmod 777`, `sudo` in `RUN`, whole-context `COPY .`, and a missing `HEALTHCHECK`. An agent calls this when reviewing a container build definition.

## Input parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `content` | `string` (1–524288 chars) | Yes | Full text of the Dockerfile to audit. |
| `filename` | `string` (1–512 chars) | No | Filename used for the finding location. |

## Output

Returns `{ summary: { total, by_severity }, findings: [...] }`. Each finding has the standard shape `{ id, module, rule, severity, cwe, title, description, location?, evidence?, remediation, references, tags, status }`. Findings are appended to the session report.

## Example

**Request**

```json
{ "content": "FROM ubuntu:latest\nRUN curl http://x | sh\n" }
```

**Response (excerpt)**

```json
{
  "summary": { "total": 2, "by_severity": { "medium": 1, "high": 1 } },
  "findings": [
    { "rule": "mutable-base-tag", "severity": "medium", "status": "open" },
    { "rule": "remote-script-piped-to-shell", "severity": "high", "status": "open" }
  ]
}
```

## Detections

- Container running as root — no `USER` directive (CWE-250)
- Mutable / `latest` base-image tag (CWE-1357)
- `ADD` of a remote URL (CWE-494)
- Remote script piped into a shell (CWE-494)
- Credentials baked into `ENV` / `ARG` (CWE-798)
- World-writable `chmod 777` (CWE-732)
- `sudo` used in `RUN` (CWE-250)
- Whole-context `COPY .` (CWE-200)
- Missing `HEALTHCHECK` (CWE-1188)

## Related tools

- [`altais_audit_compose`](altais_audit_compose.md) — reviews Docker Compose files
- [`altais_check_base_image`](altais_check_base_image.md) — assesses a base-image reference

## See also

- [`container` module](../modules/container.md)
- [Wiki home](../Home.md) · [Contributing](../Contributing.md) · [Deployment](../Deployment.md)
