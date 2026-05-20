# `altais_audit_registry`

Checks a package-registry configuration file for insecure transport and credential exposure.

| Property | Value |
|----------|-------|
| Module | [`supply_chain`](../modules/supply_chain.md) |
| Tool type | Auditor (emits findings) |
| Annotations | `readOnlyHint: true` · `destructiveHint: false` · `idempotentHint: true` · `openWorldHint: false` |

## Description

This tool checks a package-registry configuration file — `.npmrc`, `pip.conf`, or `.cargo/config.toml` — for HTTP (non-TLS) registries, plaintext auth tokens, disabled TLS verification, and pip `trusted-host` entries that include public hosts. An agent calls it when reviewing how a project authenticates to and resolves packages from its registries.

## Input parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `content` | `string` (1–512 KiB) | Yes | Registry configuration text (`.npmrc`, `pip.conf`, `.cargo/config.toml`). |
| `kind` | enum: `npmrc` \| `pip` \| `cargo` \| `auto` | No | Configuration kind. Default `auto` (detected from content / filename). |
| `filename` | `string` (1–512 chars) | No | Filename for kind detection and finding location. |

## Output

Returns `{ summary: { total, by_severity }, findings: [...] }` with the standard finding shape. All findings are appended to the session report `FindingStore`.

## Example

**Request**

```json
{ "content": "registry=http://internal/\n//internal/:_authToken=plain", "kind": "npmrc" }
```

**Response (excerpt)**

```json
{
  "summary": { "total": 2, "by_severity": { "high": 1, "medium": 1 } },
  "findings": [
    { "rule": "http-registry", "severity": "high", "title": "Registry configured over plaintext HTTP" },
    { "rule": "plaintext-auth-token", "severity": "medium", "title": "Auth token stored in plaintext" }
  ]
}
```

## Detections

- `http-registry` — a registry configured over plaintext HTTP rather than HTTPS (CWE-319)
- `plaintext-auth-token` — an authentication token stored in cleartext in the config (CWE-312)
- Disabled TLS / certificate verification (CWE-295)
- pip `trusted-host` entries that include public hosts (CWE-295)

## Related tools

- [`altais_check_dependency_confusion`](altais_check_dependency_confusion.md) — flags packages resolved from the wrong registry
- [`altais_check_build_integrity`](altais_check_build_integrity.md) — audits the CI/CD pipeline that uses these registries

## See also

- [`supply_chain` module](../modules/supply_chain.md)
- [Wiki home](../Home.md) · [Contributing](../Contributing.md) · [Deployment](../Deployment.md)
