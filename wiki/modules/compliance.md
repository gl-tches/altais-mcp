# `compliance` module

The `compliance` module maps security findings to the controls of 16 bundled compliance frameworks — OWASP ASVS/SAMM/DSOMM, NIST 800-53/SSDF/AI RMF, ISO 27001, SOC 2, GDPR, PCI-DSS, NIS2, DORA, CRA, CISA Secure by Design, EO 14028, and FDA 524B. It runs gap analyses, and generates audit evidence packs. Findings are matched to controls by CWE intersection and keyword match; mapping and gap results are emitted back into the session report as an audit trail.

| Property | Value |
|----------|-------|
| Module name | `compliance` |
| Status | Opt-in (disabled by default) |
| Config key | `[modules] compliance` in `altais.config.toml` |
| Tools | 3 |

## Tools

| Tool | Description |
|------|-------------|
| [`altais_map_findings`](../tools/altais_map_findings.md) | Map security findings to a framework's controls by CWE intersection and keyword match. |
| [`altais_gap_analysis`](../tools/altais_gap_analysis.md) | Classify every control as `addressed` or `gap` and report coverage statistics. |
| [`altais_generate_evidence`](../tools/altais_generate_evidence.md) | Generate a structured audit evidence pack per control. |

## Enabling this module

All five of these modules are opt-in. Enable one by setting its key to `true` under `[modules]` in `altais.config.toml`. Note `iac` also has an `[iac]` config section, and `compliance` has a `[compliance]` section.

## See also

- [Wiki home](../Home.md)
