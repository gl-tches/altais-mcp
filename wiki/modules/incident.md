# `incident` module

The `incident` module covers incident readiness and response. It pairs two auditors — audit-logging completeness and canary / honeypot coverage — with five generators that produce ready-to-adopt artifacts: NIST SP 800-61 incident-response playbooks, an RFC 9116 `security.txt`, GHSA-style security advisories, SIEM integration guidance, and a vulnerability-disclosure / bug-bounty program. The auditors push findings into the session report; the generators return a self-contained artifact and emit no findings.

| Property | Value |
|----------|-------|
| Module name | `incident` |
| Status | Opt-in (disabled by default) |
| Config key | `[modules] incident` in `altais.config.toml` |
| Tools | 7 |

## Tools

| Tool | Description |
|------|-------------|
| [`altais_audit_logging`](../tools/altais_audit_logging.md) | Assesses audit-trail completeness and log-injection prevention. |
| [`altais_generate_playbook`](../tools/altais_generate_playbook.md) | Generates a scenario-specific incident-response playbook along the NIST SP 800-61 lifecycle. |
| [`altais_generate_security_txt`](../tools/altais_generate_security_txt.md) | Generates an RFC 9116 `security.txt` file body. |
| [`altais_draft_advisory`](../tools/altais_draft_advisory.md) | Drafts a security advisory in GitHub Security Advisory (GHSA) markdown format. |
| [`altais_check_canary`](../tools/altais_check_canary.md) | Assesses canary-token and honeypot deception-control coverage. |
| [`altais_recommend_siem`](../tools/altais_recommend_siem.md) | Generates platform-aware SIEM integration guidance. |
| [`altais_generate_disclosure_program`](../tools/altais_generate_disclosure_program.md) | Generates a vulnerability-disclosure or bug-bounty policy document. |

## Enabling this module

All four of these modules are opt-in. Enable one by setting its key to `true` under `[modules]` in `altais.config.toml` (e.g. `incident = true`).

## See also

- [Wiki home](../Home.md)
