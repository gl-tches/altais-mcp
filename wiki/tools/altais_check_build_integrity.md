# `altais_check_build_integrity`

Pattern-based audit of CI/CD configuration for build-tampering vectors.

| Property | Value |
|----------|-------|
| Module | [`supply_chain`](../modules/supply_chain.md) |
| Tool type | Auditor (emits findings) |
| Annotations | `readOnlyHint: true` · `destructiveHint: false` · `idempotentHint: true` · `openWorldHint: false` |

## Description

This tool runs a pattern-based audit of build-pipeline configuration — GitHub Actions YAML, GitLab CI YAML, Jenkinsfiles, and similar. It flags third-party actions pinned by mutable tag or branch, secrets echoed in shell steps, write-all `permissions`, `pull_request_target` checkouts of PR refs, missing signature verification on releases, and `curl | bash` install steps. An agent calls it when reviewing a project's CI/CD configuration for supply-chain tamper risk.

## Input parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `content` | `string` (1–2 MiB) | Yes | CI/CD configuration text (GitHub Actions YAML, GitLab CI YAML, Jenkinsfile, etc.). |
| `filename` | `string` (1–512 chars) | No | Filename for finding location. |

## Output

Returns `{ summary: { total, by_severity }, findings: [...] }` with the standard finding shape. All findings are appended to the session report `FindingStore`.

## Example

**Request**

```json
{ "content": "jobs:\n  build:\n    steps:\n      - uses: actions/checkout@main\n", "filename": ".github/workflows/ci.yml" }
```

**Response (excerpt)**

```json
{
  "summary": { "total": 1, "by_severity": { "medium": 1 } },
  "findings": [
    { "rule": "unpinned-action", "severity": "medium", "title": "Third-party action pinned to a mutable ref" }
  ]
}
```

## Detections

- `unpinned-action` — third-party action pinned by mutable tag or branch instead of a commit SHA (CWE-829)
- Secrets echoed in shell steps (CWE-532)
- Write-all `permissions` granted to a workflow / job (CWE-250)
- `pull_request_target` workflow checking out an untrusted PR ref (CWE-94)
- Missing signature verification on release artifacts (CWE-347)
- `curl | bash` (remote script piped to a shell) install steps (CWE-494)

## Related tools

- [`altais_audit_registry`](altais_audit_registry.md) — audits package-registry configuration
- [`altais_verify_slsa`](altais_verify_slsa.md) — verifies the provenance the pipeline emits

## See also

- [`supply_chain` module](../modules/supply_chain.md)
- [Wiki home](../Home.md) · [Contributing](../Contributing.md) · [Deployment](../Deployment.md)
