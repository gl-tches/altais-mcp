# `headers` module

The `headers` module audits HTTP response security, generates hardened Content-Security-Policy headers, and validates Cross-Origin Resource Sharing policies. It checks CSP, HSTS, framing, content-type, referrer, and permissions headers, plus cookie attributes and CORS — and produces a strict CSP that never relies on `'unsafe-inline'` or `'unsafe-eval'`.

| Property | Value |
|----------|-------|
| Module name | `headers` |
| Status | Default-enabled |
| Config key | `[modules] headers` in `altais.config.toml` |
| Tools | 3 |

## Tools

| Tool | Description |
|------|-------------|
| [`altais_audit_headers`](../tools/altais_audit_headers.md) | Check a response header map against current HTTP security best practice. |
| [`altais_generate_csp`](../tools/altais_generate_csp.md) | Build a Content-Security-Policy header from a high-level description of what the app loads. |
| [`altais_check_cors`](../tools/altais_check_cors.md) | Validate a CORS policy expressed as a header map or a structured config. |

## Enabling this module

The `headers` module is one of the seven default-enabled modules, so it is active out of the box. To disable it, set `headers = false` under `[modules]` in `altais.config.toml`. The default-enabled set is `scan`, `threat_model`, `owasp`, `secrets`, `headers`, `supply_chain`, and `auth`; `core` is always loaded; all other modules are opt-in.

## See also

- [Wiki home](../Home.md)
