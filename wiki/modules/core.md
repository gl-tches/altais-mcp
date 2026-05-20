# `core` module

The `core` module provides the always-loaded utility tools that underpin every `altais-mcp` session: configuration inspection, CWE lookup from the bundled database, CVSS scoring, consolidated session reporting, and a composite risk summary. It is the only module that cannot be disabled.

| Property | Value |
|----------|-------|
| Module name | `core` |
| Status | Always loaded |
| Config key | `[modules] core` in `altais.config.toml` |
| Tools | 5 |

## Tools

| Tool | Description |
|------|-------------|
| [`altais_get_config`](../tools/altais_get_config.md) | Return the active server config and the list of currently loaded modules. |
| [`altais_explain_cwe`](../tools/altais_explain_cwe.md) | Look up a CWE entry from the bundled CWE database. |
| [`altais_score`](../tools/altais_score.md) | Calculate a CVSS base score (v3.1 or v4.0) from a vector string. |
| [`altais_report`](../tools/altais_report.md) | Aggregate every finding from the session into a markdown or JSON report. |
| [`altais_risk_summary`](../tools/altais_risk_summary.md) | Return a composite risk score and severity breakdown for the session. |

## Enabling this module

The `core` module is always loaded — it is not opt-in and cannot be disabled. Its tools are available in every `altais-mcp` session regardless of `altais.config.toml`. The seven default-enabled modules (`scan`, `threat_model`, `owasp`, `secrets`, `headers`, `supply_chain`, `auth`) ship enabled; all other modules are opt-in via the `[modules]` table in `altais.config.toml`.

## See also

- [Wiki home](../Home.md)
