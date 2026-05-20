# `altais_generate_review_checklist`

Generates a security code-review checklist tailored to the change type, languages, and sensitivity.

| Property | Value |
|----------|-------|
| Module | [`sdlc`](../modules/sdlc.md) |
| Tool type | Generator (returns an artifact) |
| Annotations | `readOnlyHint: true` · `destructiveHint: false` · `idempotentHint: true` · `openWorldHint: false` |

## Description

Generates a security code-review checklist tailored to the change type (feature, bugfix, dependency, infrastructure, auth, crypto), the languages involved, and the change's sensitivity. It covers input validation, authorization, secrets, crypto, error handling, dependencies, and tests, with extra items weighted to the change type and language-specific pitfalls appended. High-sensitivity changes elevate every recommended item to mandatory. An agent calls this before reviewing a pull request. This is a generator — it returns an artifact, not findings.

## Input parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `config` | `object` | Yes | The checklist request. |
| `config.change_type` | `enum` | Yes | The kind of change: `feature`, `bugfix`, `dependency`, `infrastructure`, `auth`, or `crypto`. |
| `config.languages` | `array` of `string` (1–64 chars, max 40) | Yes | Programming languages involved in the change. |
| `config.sensitivity` | `enum` | Yes | How security-sensitive the change is: `low`, `medium`, or `high`. |

## Output

Returns a generator artifact: `{ change_type, sensitivity, languages, items, content }`. `items` is an array of `{ id, category, text, priority }` where `priority` is `must` or `should`, and `content` is a rendered Markdown checklist. It does not append findings to the session report.

## Example

**Request**

```json
{ "config": { "change_type": "auth", "languages": ["typescript"], "sensitivity": "high" } }
```

**Response (excerpt)**

```json
{
  "change_type": "auth",
  "sensitivity": "high",
  "items": [
    { "id": "REVIEW-01", "category": "Input validation", "text": "Every external input is validated...", "priority": "must" },
    { "id": "REVIEW-08", "category": "Authentication", "text": "Credential handling, session lifetime...", "priority": "must" }
  ]
}
```

## Detections

This is a generator and does not emit findings. The checklist categories it can produce:

- Base items — input validation, authorization, secrets, error handling, dependencies, tests, logging
- `feature` — attack surface, least privilege
- `bugfix` — root cause, regression testing
- `dependency` — supply chain, provenance, advisories
- `infrastructure` — configuration, state & secrets
- `auth` — authentication, authorization, session
- `crypto` — algorithms, key management, randomness
- Language pitfalls — per-language items for Python, JavaScript, TypeScript, Go, Rust, Java
- Sensitivity items — review-depth, threat-model, and rollout items at `medium` / `high`

## Related tools

- [`altais_generate_precommit`](altais_generate_precommit.md) — generates a commit-time hook configuration
- [`altais_check_codeowners`](altais_check_codeowners.md) — verifies sensitive paths have a required reviewer

## See also

- [`sdlc` module](../modules/sdlc.md)
- [Wiki home](../Home.md) · [Contributing](../Contributing.md) · [Deployment](../Deployment.md)
