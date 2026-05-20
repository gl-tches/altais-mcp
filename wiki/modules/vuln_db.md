# `vuln_db` module

The `vuln_db` module is altais-mcp's vulnerability knowledge base. It provides offline CVE lookup, a full CWE taxonomy lookup with related weaknesses, a complete CVSS v3.1 + v4.0 calculator, and CWE/description-to-MITRE-ATT&CK technique mapping. Every tool reads bundled, offline data — there are no network calls. Unlike the analyzer modules, these are lookup and calculation tools: they return structured JSON records and do not push findings into the session report store.

| Property | Value |
|----------|-------|
| Module name | `vuln_db` |
| Status | Opt-in (disabled by default) |
| Config key | `[modules] vuln_db` in `altais.config.toml` |
| Tools | 4 |

## Tools

| Tool | Description |
|------|-------------|
| [`altais_lookup_cve`](../tools/altais_lookup_cve.md) | Looks up a CVE by identifier in a bundled, curated offline snapshot of high-impact CVEs. |
| [`altais_lookup_cwe`](../tools/altais_lookup_cwe.md) | Performs a full CWE taxonomy lookup with related parent / child / peer weaknesses. |
| [`altais_calculate_cvss`](../tools/altais_calculate_cvss.md) | Parses and scores a CVSS v3.1 or v4.0 vector string. |
| [`altais_map_attack`](../tools/altais_map_attack.md) | Maps a CWE and/or a free-text description to MITRE ATT&CK techniques. |

## Enabling this module

All four of these modules are opt-in. Enable one by setting its key to `true` under `[modules]` in `altais.config.toml` (e.g. `vuln_db = true`).

## See also

- [Wiki home](../Home.md)
