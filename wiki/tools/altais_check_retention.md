# `altais_check_retention`

Analyzes data-retention policies against the GDPR storage-limitation principle.

| Property | Value |
|----------|-------|
| Module | [`data`](../modules/data.md) |
| Tool type | Auditor (emits findings) |
| Annotations | `readOnlyHint: true` · `destructiveHint: false` · `idempotentHint: true` · `openWorldHint: false` |

## Description

Analyzes data-retention policies against the GDPR storage-limitation principle. It flags missing or undefined retention periods, indefinite or excessively long retention (over 3650 days), missing automated deletion, a `none` deletion method, personal-data categories deleted only by `soft_delete`, and personal data with no documented legal basis. It optionally regex-scans source for hardcoded indefinite retention. An agent calls this when reviewing how long a system keeps each category of data.

## Input parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `policies` | `array` (1–500 items) | Yes | Data-retention policies to review. |
| `policies[].data_category` | `string` (1–256 chars) | Yes | Name of the data category. |
| `policies[].retention_period_days` | `integer` (-1 to 1000000) | No | Retention period in days; `<= 0` means indefinite. |
| `policies[].deletion_method` | `enum` | No | One of `hard_delete`, `soft_delete`, `anonymize`, `none`. |
| `policies[].automated_deletion` | `boolean` | No | Whether deletion runs automatically at end of retention. |
| `policies[].legal_basis` | `string` (1–512 chars) | No | Documented GDPR Article 6 lawful basis for retention. |
| `policies[].contains_pii` | `boolean` | No | Whether the category contains personal data. |
| `source` | `string` (1–524288 chars) | No | Source to scan for hardcoded indefinite retention. |
| `filename` | `string` (1–512 chars) | No | Filename used for the finding location. |

## Output

Returns `{ summary: { total, by_severity }, findings: [...] }`. Each finding has the standard shape `{ id, module, rule, severity, cwe, title, description, location?, evidence?, remediation, references, tags, status }`. Findings are appended to the session report.

## Example

**Request**

```json
{ "policies": [{ "data_category": "logs", "retention_period_days": -1, "contains_pii": true }] }
```

**Response (excerpt)**

```json
{
  "summary": { "total": 2, "by_severity": { "medium": 2 } },
  "findings": [
    { "rule": "indefinite-retention", "severity": "medium", "status": "open" },
    { "rule": "missing-legal-basis", "severity": "medium", "status": "open" }
  ]
}
```

## Detections

- Missing or undefined retention period (CWE-359)
- Indefinite retention — `retention_period_days <= 0` (CWE-359)
- Excessively long retention — over 3650 days (CWE-359)
- Missing automated deletion (CWE-359)
- `none` deletion method (CWE-359)
- Personal-data category deleted only by `soft_delete` (CWE-359)
- Personal data with no documented legal basis (CWE-359)
- Hardcoded indefinite retention found in source (CWE-359)

## Related tools

- [`altais_audit_privacy`](altais_audit_privacy.md) — audits privacy-by-design compliance
- [`altais_detect_pii`](altais_detect_pii.md) — finds PII in code and sample data
- [`altais_classify_data`](altais_classify_data.md) — classifies data fields by sensitivity tier

## See also

- [`data` module](../modules/data.md)
- [Wiki home](../Home.md) · [Contributing](../Contributing.md) · [Deployment](../Deployment.md)
