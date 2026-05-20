# `altais_check_base_image`

Assesses a container base-image reference for pinning, end-of-life, and bloat.

| Property | Value |
|----------|-------|
| Module | [`container`](../modules/container.md) |
| Tool type | Auditor (emits findings) |
| Annotations | `readOnlyHint: true` · `destructiveHint: false` · `idempotentHint: true` · `openWorldHint: false` |

## Description

Assesses a base-image reference for known issues and bloat: missing version pinning (`latest` or untagged), missing digest pinning, end-of-life base images that no longer receive patches, and full-OS or non-minimal images where a `-slim`, `-alpine`, or distroless variant would cut attack surface. An agent calls this when reviewing the `FROM` line of a Dockerfile or any base-image choice.

## Input parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `image` | `string` (1–512 chars) | Yes | An image reference, e.g. `node:20-alpine` or `ubuntu:24.04@sha256:...`. |
| `filename` | `string` (1–512 chars) | No | Filename used for the finding location. |

## Output

Returns `{ summary: { total, by_severity }, findings: [...] }`. Each finding has the standard shape `{ id, module, rule, severity, cwe, title, description, location?, evidence?, remediation, references, tags, status }`. Findings are appended to the session report.

## Example

**Request**

```json
{ "image": "node:latest" }
```

**Response (excerpt)**

```json
{
  "summary": { "total": 2, "by_severity": { "medium": 2 } },
  "findings": [
    { "rule": "missing-version-pin", "severity": "medium", "status": "open" },
    { "rule": "missing-digest-pin", "severity": "medium", "status": "open" }
  ]
}
```

## Detections

- Missing version pinning — `latest` or untagged (CWE-1357)
- Missing digest pinning (CWE-494)
- End-of-life base image no longer receiving patches (CWE-1104, CWE-1395)
- Full-OS / non-minimal image where a `-slim`, `-alpine`, or distroless variant would cut attack surface (CWE-1357)

## Related tools

- [`altais_audit_dockerfile`](altais_audit_dockerfile.md) — analyzes a Dockerfile
- [`altais_audit_compose`](altais_audit_compose.md) — reviews Docker Compose files

## See also

- [`container` module](../modules/container.md)
- [Wiki home](../Home.md) · [Contributing](../Contributing.md) · [Deployment](../Deployment.md)
