# `altais_generate_precommit`

Generates a ready-to-use `.pre-commit-config.yaml` wiring the requested security and quality checks.

| Property | Value |
|----------|-------|
| Module | [`sdlc`](../modules/sdlc.md) |
| Tool type | Generator (returns an artifact) |
| Annotations | `readOnlyHint: true` · `destructiveHint: false` · `idempotentHint: true` · `openWorldHint: false` |

## Description

Builds a `.pre-commit-config.yaml` body that wires the security and quality checks an agent selects: secret scanning (gitleaks + detect-secrets), language linters and formatters, SAST (Semgrep, plus Bandit for Python), dependency auditing, large-file blocking, and private-key detection. An agent calls this when setting up or hardening a repository's commit-time gate. This is a generator — it returns an artifact, not findings.

## Input parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `config` | `object` | Yes | The pre-commit configuration request. |
| `config.languages` | `array` of `string` (1–64 chars, max 40) | Yes | Programming languages in the codebase, e.g. `python`, `typescript`. |
| `config.checks` | `array` of `enum` (1–7 items) | Yes | Checks to wire in. Each is one of `secrets`, `lint`, `format`, `sast`, `dependency-audit`, `large-files`, `private-key`. |

## Output

Returns a generator artifact: `{ filename, checks, languages, hooks, content, notes }`. `filename` is `.pre-commit-config.yaml`, `content` is the rendered YAML body, `hooks` lists the wired hook IDs, and `notes` carries setup instructions (e.g. creating a `.secrets.baseline`). It does not append findings to the session report.

## Example

**Request**

```json
{ "config": { "languages": ["python"], "checks": ["secrets", "sast"] } }
```

**Response (excerpt)**

```json
{
  "filename": ".pre-commit-config.yaml",
  "hooks": ["gitleaks", "detect-secrets", "semgrep", "bandit"],
  "content": "# .pre-commit-config.yaml\nminimum_pre_commit_version: 3.5.0\nrepos:\n  - repo: https://github.com/gitleaks/gitleaks\n    rev: v8.21.1\n    hooks:\n      - id: gitleaks\n",
  "notes": ["Run `detect-secrets scan > .secrets.baseline` once to create the baseline before enabling the hook."]
}
```

## Detections

This is a generator and does not emit findings. The checks it can wire:

- `secrets` — gitleaks and detect-secrets secret scanning
- `lint` / `format` — language-specific linter and formatter hooks (Ruff, ESLint, gofmt/go-vet, rustfmt/clippy, RuboCop)
- `sast` — Semgrep `p/security-audit`, plus Bandit when Python is a listed language
- `dependency-audit` — a local dependency-audit hook
- `large-files` — `check-added-large-files` (max 500 KB)
- `private-key` — `detect-private-key`

## Related tools

- [`altais_generate_review_checklist`](altais_generate_review_checklist.md) — generates a code-review checklist for a change
- [`altais_audit_ci_cd`](altais_audit_ci_cd.md) — audits the CI/CD pipeline's security gates

## See also

- [`sdlc` module](../modules/sdlc.md)
- [Wiki home](../Home.md) · [Contributing](../Contributing.md) · [Deployment](../Deployment.md)
