# `sdlc` module

Secure software-development-lifecycle tooling: it generates commit-time and code-review safeguards and audits the release path. The module ships two generators — a `.pre-commit-config.yaml` builder and a tailored security code-review checklist — alongside six auditors and assessors that check CI/CD security gates, release integrity, GPG/SSH commit signing, default-branch protection, CODEOWNERS coverage of sensitive paths, and the achieved SLSA v1.2 Build Track level. An agent enables this module to harden how a project builds, reviews, signs, and ships code.

| Property | Value |
|----------|-------|
| Module name | `sdlc` |
| Status | Opt-in (disabled by default) |
| Config key | `[modules] sdlc` in `altais.config.toml` |
| Tools | 8 |

## Tools

| Tool | Description |
|------|-------------|
| [`altais_generate_precommit`](../tools/altais_generate_precommit.md) | Generates a `.pre-commit-config.yaml` wiring the requested security and quality checks. |
| [`altais_audit_ci_cd`](../tools/altais_audit_ci_cd.md) | Reviews a CI/CD pipeline for the security gates that should block an insecure change. |
| [`altais_generate_review_checklist`](../tools/altais_generate_review_checklist.md) | Generates a security code-review checklist tailored to the change type, languages, and sensitivity. |
| [`altais_check_release_integrity`](../tools/altais_check_release_integrity.md) | Verifies a release process carries the controls that let a consumer trust a published artifact. |
| [`altais_check_signed_commits`](../tools/altais_check_signed_commits.md) | Verifies commits are GPG/SSH signed and that signing is enforced. |
| [`altais_audit_branch_protection`](../tools/altais_audit_branch_protection.md) | Audits a repository's default-branch protection settings. |
| [`altais_assess_slsa_level`](../tools/altais_assess_slsa_level.md) | Assesses the achieved SLSA v1.2 Build Track level (0–3) from build-process facts. |
| [`altais_check_codeowners`](../tools/altais_check_codeowners.md) | Verifies a CODEOWNERS file gives security-sensitive paths a required reviewer. |

## Enabling this module

All three of these modules are opt-in. Enable one by setting its key to `true` under `[modules]` in `altais.config.toml`. Note `agentic` also has an `[agentic]` config section.

```toml
[modules]
sdlc = true
```

## See also

- [Wiki home](../Home.md)
