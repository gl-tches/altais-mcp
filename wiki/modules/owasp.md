# `owasp` module

The `owasp` module produces coverage reports that map security findings onto the OWASP Top 10 lists — Web (2025), API Security (2023), Mobile (2024), and Serverless — and against the OWASP ASVS controls. Each tool evaluates findings from the session `FindingStore` (or a supplied list), matching them to categories by CWE intersection and keyword.

| Property | Value |
|----------|-------|
| Module name | `owasp` |
| Status | Default-enabled |
| Config key | `[modules] owasp` in `altais.config.toml` |
| Tools | 5 |

## Tools

| Tool | Description |
|------|-------------|
| [`altais_check_owasp_web`](../tools/altais_check_owasp_web.md) | Map findings to the OWASP Top 10:2025 (Web) categories A01–A10. |
| [`altais_check_owasp_api`](../tools/altais_check_owasp_api.md) | Map findings to the OWASP API Security Top 10 (2023) categories. |
| [`altais_check_owasp_mobile`](../tools/altais_check_owasp_mobile.md) | Map findings to the OWASP Mobile Top 10 (2024) categories. |
| [`altais_check_owasp_serverless`](../tools/altais_check_owasp_serverless.md) | Map findings to the OWASP Serverless Top 10 categories. |
| [`altais_check_asvs`](../tools/altais_check_asvs.md) | Return OWASP ASVS controls at a given verification level, optionally filtered to one section. |

## Enabling this module

The `owasp` module is one of the seven default-enabled modules, so it is active out of the box. To disable it, set `owasp = false` under `[modules]` in `altais.config.toml`. The default-enabled set is `scan`, `threat_model`, `owasp`, `secrets`, `headers`, `supply_chain`, and `auth`; `core` is always loaded; all other modules are opt-in.

## See also

- [Wiki home](../Home.md)
