# `altais_audit_deps`

Parses a lockfile and matches every dependency against the bundled vulnerability database.

| Property | Value |
|----------|-------|
| Module | [`supply_chain`](../modules/supply_chain.md) |
| Tool type | Auditor (emits findings) |
| Annotations | `readOnlyHint: true` · `destructiveHint: false` · `idempotentHint: true` · `openWorldHint: false` |

## Description

This tool parses a lockfile (npm, cargo, poetry, or go) and matches every `(name, version)` pair against the bundled OSV snapshot, returning a finding per vulnerable package. The bundled database is small and curated — for production use, replace `data/osv-snapshot.json` with a fresh OSV export. An agent calls it when reviewing a project's dependency tree for known vulnerabilities.

## Input parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `content` | `string` (1–8 MiB) | Yes | Raw lockfile content. |
| `kind` | enum: `npm` \| `cargo` \| `poetry` \| `go` | No | Lockfile kind. Inferred from `filename` if omitted. |
| `filename` | `string` (1–512 chars) | No | Filename for kind detection and finding location. |

Provide `kind`, or a `filename` from which the kind can be detected.

## Output

Returns `{ summary: { total, by_severity }, findings: [...] }` with the standard finding shape; each finding identifies the vulnerable package, version, and advisory. All findings are appended to the session report `FindingStore`.

## Example

**Request**

```json
{ "content": "{ \"lockfileVersion\": 3, \"packages\": { \"node_modules/lodash\": { \"version\": \"4.17.11\" } } }", "kind": "npm" }
```

**Response (excerpt)**

```json
{
  "summary": { "total": 1, "by_severity": { "critical": 1 } },
  "findings": [
    { "rule": "vulnerable-dependency", "severity": "critical", "title": "lodash 4.17.11 — CVE-2019-10744" }
  ]
}
```

## Detections

- `vulnerable-dependency` — a `(name, version)` pair matched against an advisory in the bundled OSV snapshot (CWE-1395, plus the CWE attached to the matched advisory)

## Related tools

- [`altais_generate_sbom`](altais_generate_sbom.md) — emit an SBOM from the same lockfile
- [`altais_generate_vex`](altais_generate_vex.md) — declare exploitability decisions on surfaced advisories

## See also

- [`supply_chain` module](../modules/supply_chain.md)
- [Wiki home](../Home.md) · [Contributing](../Contributing.md) · [Deployment](../Deployment.md)
