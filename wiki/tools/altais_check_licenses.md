# `altais_check_licenses`

Classifies every dependency's license against allow / warn / deny lists.

| Property | Value |
|----------|-------|
| Module | [`supply_chain`](../modules/supply_chain.md) |
| Tool type | Auditor (emits findings) |
| Annotations | `readOnlyHint: true` · `destructiveHint: false` · `idempotentHint: true` · `openWorldHint: false` |

## Description

This tool parses a lockfile and classifies each dependency's declared license against three lists: allow, warn, and deny. It returns findings for `denied` licenses, `warn` licenses (typically weak copyleft), and `unknown` (no license declared). Custom lists override the bundled SPDX-based defaults. An agent calls it when reviewing a dependency tree for license-compliance risk.

## Input parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `content` | `string` (1–8 MiB) | Yes | Raw lockfile content. |
| `kind` | enum: `npm` \| `cargo` \| `poetry` \| `go` | No | Lockfile kind. Inferred from `filename` if omitted. |
| `filename` | `string` (1–512 chars) | No | Filename for kind detection and finding location. |
| `allow` | `string[]` (each 1–128 chars, max 256) | No | SPDX identifiers to treat as allowed. Overrides the default allow list. |
| `warn` | `string[]` (each 1–128 chars, max 256) | No | SPDX identifiers to flag as a warning. Overrides the default warn list. |
| `deny` | `string[]` (each 1–128 chars, max 256) | No | SPDX identifiers to treat as denied. Overrides the default deny list. |

Provide `kind`, or a `filename` from which the kind can be detected. When `allow` / `warn` / `deny` are omitted, the bundled SPDX-based defaults apply.

## Output

Returns `{ summary: { total, by_severity }, findings: [...] }` with the standard finding shape. All findings are appended to the session report `FindingStore`.

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
    { "rule": "denied-license", "severity": "high", "title": "pkg-x uses GPL-3.0" }
  ]
}
```

## Detections

- `denied-license` — a dependency carries a license on the deny list (CWE-1104)
- `warn` category — a dependency carries a weak-copyleft / cautionary license
- `unknown` category — a dependency declares no license at all

## Related tools

- [`altais_audit_deps`](altais_audit_deps.md) — scan the same lockfile for known vulnerabilities
- [`altais_generate_sbom`](altais_generate_sbom.md) — emit an SBOM that records license data

## See also

- [`supply_chain` module](../modules/supply_chain.md)
- [Wiki home](../Home.md) · [Contributing](../Contributing.md) · [Deployment](../Deployment.md)
