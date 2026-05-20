# `altais_audit_ci_cd`

Reviews a CI/CD pipeline for the security gates that should block an insecure change.

| Property | Value |
|----------|-------|
| Module | [`sdlc`](../modules/sdlc.md) |
| Tool type | Auditor (emits findings) |
| Annotations | `readOnlyHint: true` · `destructiveHint: false` · `idempotentHint: true` · `openWorldHint: false` |

## Description

Reviews a CI/CD pipeline for the gates that should stop an insecure change: SAST, dependency/SCA scanning, secret scanning, container image scanning, DAST, and a fail-on-findings policy. When pipeline YAML is supplied it is additionally scanned for unpinned third-party actions, over-broad `permissions: write-all`, and secrets echoed to logs. An agent calls this when reviewing a pipeline's posture. At least one of `content` or `config` must be provided.

## Input parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `content` | `string` (1–524288 chars) | No | CI/CD pipeline YAML (GitHub Actions, GitLab CI, etc.) to scan. |
| `config` | `object` | No | Declared presence of pipeline security gates. |
| `config.has_sast` | `boolean` | No | Whether a SAST gate is present. |
| `config.has_dependency_scan` | `boolean` | No | Whether a dependency / SCA scan is present. |
| `config.has_secret_scan` | `boolean` | No | Whether a secret scan is present. |
| `config.has_container_scan` | `boolean` | No | Whether a container image scan is present. |
| `config.has_dast` | `boolean` | No | Whether a DAST stage is present. |
| `config.blocks_on_failure` | `boolean` | No | Whether the pipeline fails the build on findings. |
| `config.signed_artifacts` | `boolean` | No | Whether build artifacts are signed. |
| `filename` | `string` (1–512 chars) | No | Filename used for the finding location. |

Provide at least one of `content` or `config`.

## Output

Returns `{ summary: { total, by_severity }, findings: [...] }`. Each finding has the standard shape `{ id, module, rule, severity, cwe, title, description, location?, evidence?, remediation, references, tags, status }`. Findings are appended to the session report.

## Example

**Request**

```json
{ "config": { "has_sast": false, "blocks_on_failure": false } }
```

**Response (excerpt)**

```json
{
  "summary": { "total": 2, "by_severity": { "medium": 2 } },
  "findings": [
    { "rule": "no-sast-gate", "severity": "medium", "cwe": ["CWE-1395"], "title": "Pipeline has no SAST gate", "status": "open" }
  ]
}
```

## Detections

- Missing SAST gate (CWE-1395)
- Missing dependency / SCA scan (CWE-1395)
- Missing secret scan
- Missing container image scan
- Missing DAST stage
- Pipeline does not block on findings (CWE-693)
- Unsigned build artifacts
- Unpinned third-party actions (CWE-829)
- Over-broad `permissions: write-all` (CWE-1269)
- Secrets echoed to build logs

## Related tools

- [`altais_check_release_integrity`](altais_check_release_integrity.md) — verifies release-process trust controls
- [`altais_assess_slsa_level`](altais_assess_slsa_level.md) — assesses the SLSA Build Track level
- [`altais_generate_precommit`](altais_generate_precommit.md) — generates a commit-time gate

## See also

- [`sdlc` module](../modules/sdlc.md)
- [Wiki home](../Home.md) · [Contributing](../Contributing.md) · [Deployment](../Deployment.md)
