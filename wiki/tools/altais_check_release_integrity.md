# `altais_check_release_integrity`

Verifies a release process carries the controls that let a consumer trust a published artifact.

| Property | Value |
|----------|-------|
| Module | [`sdlc`](../modules/sdlc.md) |
| Tool type | Auditor (emits findings) |
| Annotations | `readOnlyHint: true` · `destructiveHint: false` · `idempotentHint: true` · `openWorldHint: false` |

## Description

Verifies a release process carries the controls that let a consumer trust a published artifact: signed artifacts, published checksums, reproducible builds, a published SBOM, signed provenance attestation, release from a protected branch, a maintained changelog, and signed tags. It flags each missing control. An agent calls this when reviewing how a project ships releases.

## Input parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `config` | `object` | Yes | Declared release-process controls. |
| `config.artifacts_signed` | `boolean` | No | Whether release artifacts are cryptographically signed. |
| `config.checksums_published` | `boolean` | No | Whether checksums are published alongside artifacts. |
| `config.reproducible_build` | `boolean` | No | Whether the build is reproducible. |
| `config.sbom_published` | `boolean` | No | Whether an SBOM is published with the release. |
| `config.provenance_attestation` | `boolean` | No | Whether a signed provenance attestation is published. |
| `config.release_from_protected_branch` | `boolean` | No | Whether releases are cut from a protected branch. |
| `config.changelog_maintained` | `boolean` | No | Whether a changelog is maintained. |
| `config.tags_signed` | `boolean` | No | Whether release tags are signed. |
| `filename` | `string` (1–512 chars) | No | Filename used for the finding location. |

## Output

Returns `{ summary: { total, by_severity }, findings: [...] }`. Each finding has the standard shape `{ id, module, rule, severity, cwe, title, description, location?, evidence?, remediation, references, tags, status }`. Findings are appended to the session report.

## Example

**Request**

```json
{ "config": { "artifacts_signed": false, "sbom_published": false } }
```

**Response (excerpt)**

```json
{
  "summary": { "total": 2, "by_severity": { "high": 1, "medium": 1 } },
  "findings": [
    { "rule": "unsigned-artifacts", "severity": "high", "cwe": ["CWE-353"], "title": "Release artifacts are not signed", "status": "open" }
  ]
}
```

## Detections

- Unsigned release artifacts (CWE-353)
- No published checksums (CWE-353)
- Non-reproducible build (CWE-1357)
- No published SBOM (CWE-1357)
- Missing provenance attestation (CWE-345)
- Release not cut from a protected branch
- No maintained changelog
- Unsigned release tags (CWE-347)

## Related tools

- [`altais_assess_slsa_level`](altais_assess_slsa_level.md) — assesses the SLSA Build Track level
- [`altais_check_signed_commits`](altais_check_signed_commits.md) — verifies GPG/SSH commit signing
- [`altais_audit_ci_cd`](altais_audit_ci_cd.md) — audits the pipeline that builds the release

## See also

- [`sdlc` module](../modules/sdlc.md)
- [Wiki home](../Home.md) · [Contributing](../Contributing.md) · [Deployment](../Deployment.md)
