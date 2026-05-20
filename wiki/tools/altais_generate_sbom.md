# `altais_generate_sbom`

Emits a CycloneDX 1.5 or SPDX 2.3 software bill of materials from a lockfile.

| Property | Value |
|----------|-------|
| Module | [`supply_chain`](../modules/supply_chain.md) |
| Tool type | Generator (returns an artifact) |
| Annotations | `readOnlyHint: true` · `destructiveHint: false` · `idempotentHint: true` · `openWorldHint: false` |

## Description

This tool parses a lockfile (npm, cargo, poetry, or go) and emits a software bill of materials in CycloneDX 1.5 or SPDX 2.3 format. The document lists every dependency with its Package URL (PURL) and any hashes the lockfile carries. An agent calls it when producing a dependency manifest for distribution, compliance, or downstream vulnerability scanning.

## Input parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `content` | `string` (1–8 MiB) | Yes | Raw lockfile content. |
| `kind` | enum: `npm` \| `cargo` \| `poetry` \| `go` | No | Lockfile kind. Inferred from `filename` if omitted. |
| `filename` | `string` (1–512 chars) | No | Filename for kind detection. |
| `format` | enum: `cyclonedx` \| `spdx` | No | Output format. Default `cyclonedx`. |
| `project_name` | `string` (1–256 chars) | No | Name of the project the SBOM describes. |
| `project_version` | `string` (1–64 chars) | No | Version of the project the SBOM describes. |

Provide `kind`, or a `filename` from which the kind can be detected.

## Output

Returns the SBOM artifact itself — not a findings list. For `cyclonedx` the document is a CycloneDX 1.5 BOM (`bomFormat`, `specVersion`, `metadata`, `components[]`); for `spdx` an SPDX 2.3 document. This tool does not append anything to the session report.

## Example

**Request**

```json
{ "content": "...", "kind": "cargo", "format": "cyclonedx" }
```

**Response (excerpt)**

```json
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.5",
  "components": [
    { "name": "serde", "version": "1.0.0", "purl": "pkg:cargo/serde@1.0.0" }
  ]
}
```

## Detections

This is a generator, not an auditor. The emitted artifact contains:

- Document metadata — format, spec version, the generating tool (`altais-mcp`), and optional project name / version
- One component entry per dependency, each carrying the package name, version, and a PURL (`pkg:<type>/<name>@<version>`)
- Any cryptographic hashes recorded in the source lockfile

## Related tools

- [`altais_audit_deps`](altais_audit_deps.md) — scan the same lockfile for known vulnerabilities
- [`altais_generate_vex`](altais_generate_vex.md) — pair the SBOM with exploitability statements

## See also

- [`supply_chain` module](../modules/supply_chain.md)
- [Wiki home](../Home.md) · [Contributing](../Contributing.md) · [Deployment](../Deployment.md)
