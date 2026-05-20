# `altais_check_dependency_confusion`

Flags packages matching an internal name pattern but resolved from a public registry.

| Property | Value |
|----------|-------|
| Module | [`supply_chain`](../modules/supply_chain.md) |
| Tool type | Auditor (emits findings) |
| Annotations | `readOnlyHint: true` · `destructiveHint: false` · `idempotentHint: true` · `openWorldHint: false` |

## Description

This tool parses a lockfile alongside a description of which package names, scopes, and prefixes are internal, and flags any package that matches the internal pattern yet resolved from a public registry — the dependency-confusion attack profile. Supplying internal-registry hostnames lets the tool suppress false positives for packages correctly served from a private registry. An agent calls it when reviewing a dependency tree that mixes internal and public packages.

## Input parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `content` | `string` (1–8 MiB) | Yes | Raw lockfile content. |
| `kind` | enum: `npm` \| `cargo` \| `poetry` \| `go` | No | Lockfile kind. Inferred from `filename` if omitted. |
| `filename` | `string` (1–512 chars) | No | Filename for kind detection and finding location. |
| `internal_names` | `string[]` (each 1–256 chars, max 256) | No | Exact internal package names. |
| `internal_scopes` | `string[]` (each 1–64 chars, max 64) | No | Internal package scopes (e.g. `@acme`). |
| `internal_prefixes` | `string[]` (each 1–128 chars, max 64) | No | Internal package-name prefixes. |
| `internal_registries` | `string[]` (each 1–256 chars, max 32) | No | Hostnames of trusted internal registries, used to suppress false positives. |

Provide `kind`, or a `filename` from which the kind can be detected.

## Output

Returns `{ summary: { total, by_severity }, findings: [...] }` with the standard finding shape; each finding names the at-risk package and the public registry it resolved from. All findings are appended to the session report `FindingStore`.

## Example

**Request**

```json
{ "content": "...", "kind": "npm", "internal_scopes": ["@acme"] }
```

**Response (excerpt)**

```json
{
  "summary": { "total": 1, "by_severity": { "high": 1 } },
  "findings": [
    { "rule": "dependency-confusion-risk", "severity": "high", "title": "@acme/utils resolved from npmjs.org" }
  ]
}
```

## Detections

- `dependency-confusion-risk` — a package matching an internal name / scope / prefix resolved from a public registry rather than an internal one (CWE-427 / CWE-1357)

## Related tools

- [`altais_detect_typosquat`](altais_detect_typosquat.md) — flags near-miss package names
- [`altais_audit_registry`](altais_audit_registry.md) — audits the registry config that governs resolution

## See also

- [`supply_chain` module](../modules/supply_chain.md)
- [Wiki home](../Home.md) · [Contributing](../Contributing.md) · [Deployment](../Deployment.md)
