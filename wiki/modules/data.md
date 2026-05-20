# `data` module

The `data` module audits data-privacy security: PII detection in code and sample data, data-sensitivity classification, privacy-by-design (GDPR) compliance auditing, and data-retention and deletion review. Every tool is an auditor that emits CWE-tagged findings into the session report.

| Property | Value |
|----------|-------|
| Module name | `data` |
| Status | Opt-in (disabled by default) |
| Config key | `[modules] data` in `altais.config.toml` |
| Tools | 4 |

## Tools

| Tool | Description |
|------|-------------|
| [`altais_detect_pii`](../tools/altais_detect_pii.md) | Scan source or sample data for PII; raw values are masked in findings. |
| [`altais_classify_data`](../tools/altais_classify_data.md) | Classify data fields into restricted / confidential / internal / public tiers. |
| [`altais_audit_privacy`](../tools/altais_audit_privacy.md) | Check an implementation against GDPR-aligned privacy-by-design principles. |
| [`altais_check_retention`](../tools/altais_check_retention.md) | Analyze data-retention policies against the GDPR storage-limitation principle. |

## Enabling this module

All four of these modules are opt-in. Enable one by setting its key to `true` under `[modules]` in `altais.config.toml` (e.g. `data = true`).

## See also

- [Wiki home](../Home.md)
