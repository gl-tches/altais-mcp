# `runtime` module

The `runtime` module covers runtime application protection. It provides a WAF rule generator (ModSecurity, Cloudflare, AWS WAF, or NGINX/NAXSI), a RASP configuration recommender, and an application-monitoring auditor for security-event logging, alerting, SIEM integration, and detection coverage. The two generators return ready-to-use artifacts and emit no findings; the monitoring auditor pushes findings into the session report.

| Property | Value |
|----------|-------|
| Module name | `runtime` |
| Status | Opt-in (disabled by default) |
| Config key | `[modules] runtime` in `altais.config.toml` |
| Tools | 3 |

## Tools

| Tool | Description |
|------|-------------|
| [`altais_generate_waf_rules`](../tools/altais_generate_waf_rules.md) | Generates a ready-to-use WAF rule set for a chosen platform. |
| [`altais_recommend_rasp`](../tools/altais_recommend_rasp.md) | Recommends a Runtime Application Self-Protection (RASP) configuration for an application's stack. |
| [`altais_audit_monitoring`](../tools/altais_audit_monitoring.md) | Audits an application's monitoring posture for security-event coverage. |

## Enabling this module

All four of these modules are opt-in. Enable one by setting its key to `true` under `[modules]` in `altais.config.toml` (e.g. `runtime = true`).

## See also

- [Wiki home](../Home.md)
