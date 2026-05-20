# `altais_check_signed_commits`

Verifies commits are GPG/SSH signed and that signing is enforced.

| Property | Value |
|----------|-------|
| Module | [`sdlc`](../modules/sdlc.md) |
| Tool type | Auditor (emits findings) |
| Annotations | `readOnlyHint: true` · `destructiveHint: false` · `idempotentHint: true` · `openWorldHint: false` |

## Description

Verifies that commits are GPG or SSH signed and that signing is enforced. It accepts `git log` output with signature markers and/or a precomputed signing summary, and flags signing not being enforced, unsigned commits, and signatures that cannot be verified (bad, expired, revoked, or unknown key). An agent calls this when reviewing a repository's commit-authenticity posture. At least one of `git_log` or `config` must be provided.

## Input parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `git_log` | `string` (1–524288 chars) | No | `git log` output, one commit per line, each with a signature marker (`%G?` letter, `gpg:` line, or `Good signature`). |
| `config` | `object` | No | Precomputed commit-signing summary. |
| `config.signing_enforced` | `boolean` | No | Whether commit signing is enforced. |
| `config.total_commits` | `integer` (0–10000000) | No | Total number of commits considered. |
| `config.signed_commits` | `integer` (0–10000000) | No | Number of signed commits. |
| `config.verified_commits` | `integer` (0–10000000) | No | Number of commits whose signature verifies. |
| `filename` | `string` (1–512 chars) | No | Filename used for the finding location. |

Provide at least one of `git_log` or `config`.

## Output

Returns `{ summary: { total, by_severity }, findings: [...] }`. Each finding has the standard shape `{ id, module, rule, severity, cwe, title, description, location?, evidence?, remediation, references, tags, status }`. Findings are appended to the session report.

## Example

**Request**

```json
{ "config": { "signing_enforced": false, "total_commits": 100, "signed_commits": 12 } }
```

**Response (excerpt)**

```json
{
  "summary": { "total": 2, "by_severity": { "medium": 2 } },
  "findings": [
    { "rule": "signing-not-enforced", "severity": "medium", "cwe": ["CWE-347"], "title": "Commit signing is not enforced", "status": "open" }
  ]
}
```

## Detections

- Commit signing not enforced (CWE-347)
- Unsigned commits present (CWE-347)
- Signatures that cannot be verified — bad, expired, revoked, or unknown key (CWE-347)

## Related tools

- [`altais_audit_branch_protection`](altais_audit_branch_protection.md) — checks branch protection, including a signed-commit requirement
- [`altais_check_release_integrity`](altais_check_release_integrity.md) — verifies signed tags and artifacts

## See also

- [`sdlc` module](../modules/sdlc.md)
- [Wiki home](../Home.md) · [Contributing](../Contributing.md) · [Deployment](../Deployment.md)
