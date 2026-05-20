# `altais_audit_compose`

Reviews a Docker Compose file for security misconfigurations.

| Property | Value |
|----------|-------|
| Module | [`container`](../modules/container.md) |
| Tool type | Auditor (emits findings) |
| Annotations | `readOnlyHint: true` · `destructiveHint: false` · `idempotentHint: true` · `openWorldHint: false` |

## Description

Reviews the text of a Docker Compose file for security misconfigurations: privileged mode, shared host network / PID / IPC namespaces, a mounted Docker socket, dangerous added Linux capabilities, a disabled seccomp / AppArmor sandbox, hardcoded credentials, and unpinned image tags. An agent calls this when reviewing a multi-container service definition.

## Input parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `content` | `string` (1–524288 chars) | Yes | Full text of the Docker Compose file to audit. |
| `filename` | `string` (1–512 chars) | No | Filename used for the finding location. |

## Output

Returns `{ summary: { total, by_severity }, findings: [...] }`. Each finding has the standard shape `{ id, module, rule, severity, cwe, title, description, location?, evidence?, remediation, references, tags, status }`. Findings are appended to the session report.

## Example

**Request**

```json
{ "content": "services:\n  app:\n    privileged: true\n" }
```

**Response (excerpt)**

```json
{
  "summary": { "total": 1, "by_severity": { "high": 1 } },
  "findings": [
    {
      "rule": "privileged-mode",
      "severity": "high",
      "title": "Service runs in privileged mode",
      "status": "open"
    }
  ]
}
```

## Detections

- Privileged mode (CWE-250)
- Shared host network / PID / IPC namespaces (CWE-668)
- Mounted Docker socket (CWE-668)
- Dangerous added Linux capabilities (CWE-250)
- Disabled seccomp / AppArmor sandbox (CWE-693)
- Hardcoded credentials (CWE-798)
- Unpinned image tags (CWE-1357)

## Related tools

- [`altais_audit_dockerfile`](altais_audit_dockerfile.md) — analyzes a Dockerfile
- [`altais_check_base_image`](altais_check_base_image.md) — assesses a base-image reference

## See also

- [`container` module](../modules/container.md)
- [Wiki home](../Home.md) · [Contributing](../Contributing.md) · [Deployment](../Deployment.md)
