# `altais_audit_branch_protection`

Audits a repository's default-branch protection settings and flags each weak or missing control.

| Property | Value |
|----------|-------|
| Module | [`sdlc`](../modules/sdlc.md) |
| Tool type | Auditor (emits findings) |
| Annotations | `readOnlyHint: true` · `destructiveHint: false` · `idempotentHint: true` · `openWorldHint: false` |

## Description

Audits a repository's default-branch protection settings and flags each weak or missing control: no required review, undismissed stale approvals, no required status checks, admins able to bypass protection, allowed force pushes, allowed branch deletion, no signed-commit requirement, and unresolved-conversation merges. An agent calls this when reviewing how a repository guards its mainline.

## Input parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `config` | `object` | Yes | Declared default-branch protection settings. |
| `config.required_reviews` | `integer` (0–100) | No | Number of approving reviews required to merge. |
| `config.dismiss_stale_reviews` | `boolean` | No | Whether stale approvals are dismissed on new commits. |
| `config.required_status_checks` | `boolean` or `array` of `string` (1–256 chars, max 200) | No | Required status checks: a boolean, or an explicit list of check names. |
| `config.require_up_to_date` | `boolean` | No | Whether branches must be up to date before merge. |
| `config.enforce_for_admins` | `boolean` | No | Whether protection rules also apply to admins. |
| `config.restrict_force_push` | `boolean` | No | Whether force pushes are restricted. |
| `config.restrict_deletions` | `boolean` | No | Whether branch deletion is restricted. |
| `config.require_signed_commits` | `boolean` | No | Whether signed commits are required. |
| `config.require_linear_history` | `boolean` | No | Whether a linear history is required. |
| `config.require_conversation_resolution` | `boolean` | No | Whether all review conversations must be resolved before merge. |
| `filename` | `string` (1–512 chars) | No | Filename used for the finding location. |

## Output

Returns `{ summary: { total, by_severity }, findings: [...] }`. Each finding has the standard shape `{ id, module, rule, severity, cwe, title, description, location?, evidence?, remediation, references, tags, status }`. Findings are appended to the session report.

## Example

**Request**

```json
{ "config": { "required_reviews": 0, "restrict_force_push": false } }
```

**Response (excerpt)**

```json
{
  "summary": { "total": 2, "by_severity": { "high": 1, "medium": 1 } },
  "findings": [
    { "rule": "no-required-review", "severity": "high", "cwe": ["CWE-1269"], "title": "Default branch requires no review", "status": "open" }
  ]
}
```

## Detections

- No required review (CWE-1269)
- Stale approvals not dismissed (CWE-1269)
- No required status checks (CWE-284)
- Admins can bypass protection (CWE-284)
- Force pushes allowed (CWE-284)
- Branch deletion allowed (CWE-284)
- No signed-commit requirement (CWE-1269)
- Unresolved conversations can be merged (CWE-1269)

## Related tools

- [`altais_check_signed_commits`](altais_check_signed_commits.md) — verifies commits are actually signed
- [`altais_check_codeowners`](altais_check_codeowners.md) — verifies sensitive paths have a required reviewer
- [`altais_check_release_integrity`](altais_check_release_integrity.md) — verifies releases come from a protected branch

## See also

- [`sdlc` module](../modules/sdlc.md)
- [Wiki home](../Home.md) · [Contributing](../Contributing.md) · [Deployment](../Deployment.md)
