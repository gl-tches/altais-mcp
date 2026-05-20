# `altais_check_codeowners`

Verifies a CODEOWNERS file gives security-sensitive paths a required reviewer.

| Property | Value |
|----------|-------|
| Module | [`sdlc`](../modules/sdlc.md) |
| Tool type | Auditor (emits findings) |
| Annotations | `readOnlyHint: true` · `destructiveHint: false` · `idempotentHint: true` · `openWorldHint: false` |

## Description

Verifies a CODEOWNERS file gives security-sensitive paths a required reviewer. It flags sensitive paths with no owner rule, a missing catch-all `*` rule, rules with no actual owner, malformed owner entries, and (info-level) a single owner gating every rule. An agent calls this when reviewing how a repository routes review for security-critical code.

## Input parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `content` | `string` (1–524288 chars) | Yes | The CODEOWNERS file body to audit. |
| `sensitive_paths` | `array` of `string` (1–256 chars, max 200) | No | Security-sensitive paths that must have an owner rule. Defaults to auth, crypto, security, CI, infra, deploy, iam, secrets, and Dockerfile. |
| `filename` | `string` (1–512 chars) | No | Filename used for the finding location. |

## Output

Returns `{ summary: { total, by_severity }, findings: [...] }`. Each finding has the standard shape `{ id, module, rule, severity, cwe, title, description, location?, evidence?, remediation, references, tags, status }`. Findings are appended to the session report.

## Example

**Request**

```json
{ "content": "* @team\n" }
```

**Response (excerpt)**

```json
{
  "summary": { "total": 1, "by_severity": { "medium": 1 } },
  "findings": [
    { "rule": "sensitive-path-uncovered", "severity": "medium", "cwe": ["CWE-1220"], "title": "Sensitive path has no dedicated owner rule", "status": "open" }
  ]
}
```

## Detections

- Sensitive path with no dedicated owner rule (CWE-1220)
- Missing catch-all `*` rule (CWE-1220)
- Rule with no actual owner (CWE-284)
- Malformed owner entry
- A single owner gating every rule (info)

## Related tools

- [`altais_audit_branch_protection`](altais_audit_branch_protection.md) — checks required reviews on the default branch
- [`altais_generate_review_checklist`](altais_generate_review_checklist.md) — generates a checklist for the reviewer

## See also

- [`sdlc` module](../modules/sdlc.md)
- [Wiki home](../Home.md) · [Contributing](../Contributing.md) · [Deployment](../Deployment.md)
