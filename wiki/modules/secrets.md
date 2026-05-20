# `secrets` module

The `secrets` module detects hardcoded credentials in source code and git history. It combines known-pattern matching against a bundled secret-pattern database (AWS, GitHub, Slack, Stripe, GCP, JWT, PEM keys, DSNs, and more) with a Shannon-entropy heuristic for random-looking credentials that match no known pattern. Literal secrets are redacted in finding evidence.

| Property | Value |
|----------|-------|
| Module name | `secrets` |
| Status | Default-enabled |
| Config key | `[modules] secrets` in `altais.config.toml` |
| Tools | 3 |

## Tools

| Tool | Description |
|------|-------------|
| [`altais_scan_secrets`](../tools/altais_scan_secrets.md) | Match input text against the bundled secret-pattern database. |
| [`altais_scan_entropy`](../tools/altais_scan_entropy.md) | Compute Shannon entropy on candidate tokens and flag high-entropy strings. |
| [`altais_scan_git_secrets`](../tools/altais_scan_git_secrets.md) | Walk `git log -p` / `git diff` output, attributing findings to commits and files. |

## Enabling this module

The `secrets` module is one of the seven default-enabled modules, so it is active out of the box. To disable it, set `secrets = false` under `[modules]` in `altais.config.toml`. The default-enabled set is `scan`, `threat_model`, `owasp`, `secrets`, `headers`, `supply_chain`, and `auth`; `core` is always loaded; all other modules are opt-in.

## See also

- [Wiki home](../Home.md)
