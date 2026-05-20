# `altais_detect_typosquat`

Flags dependency names within edit-distance 1–2 of a popular package in the same ecosystem.

| Property | Value |
|----------|-------|
| Module | [`supply_chain`](../modules/supply_chain.md) |
| Tool type | Auditor (emits findings) |
| Annotations | `readOnlyHint: true` · `destructiveHint: false` · `idempotentHint: true` · `openWorldHint: false` |

## Description

This tool parses a lockfile and, for each dependency, compares its name against a curated list of popular packages in the same ecosystem. It flags any package within edit-distance 1 or 2 of a popular name — a common typosquatting profile where an attacker publishes a near-miss package to capture mistyped installs. An agent calls it when reviewing a dependency tree for malicious-package risk.

## Input parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `content` | `string` (1–8 MiB) | Yes | Raw lockfile content. |
| `kind` | enum: `npm` \| `cargo` \| `poetry` \| `go` | No | Lockfile kind. Inferred from `filename` if omitted. |
| `filename` | `string` (1–512 chars) | No | Filename for kind detection and finding location. |

Provide `kind`, or a `filename` from which the kind can be detected.

## Output

Returns `{ summary: { total, by_severity }, findings: [...] }` with the standard finding shape; each finding names the suspect package and the popular package it resembles. All findings are appended to the session report `FindingStore`.

## Example

**Request**

```json
{ "content": "...", "kind": "npm" }
```

**Response (excerpt)**

```json
{
  "summary": { "total": 1, "by_severity": { "high": 1 } },
  "findings": [
    { "rule": "typosquat-candidate", "severity": "high", "title": "reqeusts resembles requests" }
  ]
}
```

## Detections

- `typosquat-candidate` — a dependency name within edit-distance 1 or 2 of a known popular package in the same ecosystem (CWE-1357 / CWE-829)

## Related tools

- [`altais_check_dependency_confusion`](altais_check_dependency_confusion.md) — flags internal names resolved from public registries
- [`altais_audit_deps`](altais_audit_deps.md) — scans the same lockfile for known vulnerabilities

## See also

- [`supply_chain` module](../modules/supply_chain.md)
- [Wiki home](../Home.md) · [Contributing](../Contributing.md) · [Deployment](../Deployment.md)
