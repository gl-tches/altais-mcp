# `altais_detect_pii`

Scans source code or sample data for personally identifiable information, masking raw values in findings.

| Property | Value |
|----------|-------|
| Module | [`data`](../modules/data.md) |
| Tool type | Auditor (emits findings) |
| Annotations | `readOnlyHint: true` · `destructiveHint: false` · `idempotentHint: true` · `openWorldHint: false` |

## Description

Scans source code or sample data for personally identifiable information: email addresses, phone numbers, US Social Security Numbers, credit-card-like numbers (Luhn-checked), IPv4 addresses, IBANs, and dates of birth, plus PII-revealing identifiers in code (variable and column names like `ssn`, `first_name`, `date_of_birth`, `passport`, `home_address`). Raw values are masked in findings and never echoed back. An agent calls this when reviewing code or sample datasets for exposed personal data.

## Input parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `source` | `string` (1–524288 chars) | Yes | Source code or sample data to scan. |
| `filename` | `string` (1–512 chars) | No | Filename used for the finding location. |

## Output

Returns `{ summary: { total, by_severity }, findings: [...] }`. Each finding has the standard shape `{ id, module, rule, severity, cwe, title, description, location?, evidence?, remediation, references, tags, status }`; the `evidence` field carries a masked value. Findings are appended to the session report.

## Example

**Request**

```json
{ "source": "user.ssn = '123-45-6789'" }
```

**Response (excerpt)**

```json
{
  "summary": { "total": 1, "by_severity": { "high": 1 } },
  "findings": [
    {
      "rule": "us-ssn",
      "severity": "high",
      "evidence": "***-**-6789",
      "title": "US Social Security Number detected",
      "status": "open"
    }
  ]
}
```

## Detections

- Email addresses (CWE-359)
- Phone numbers (CWE-359)
- US Social Security Numbers (CWE-359)
- Credit-card-like numbers, Luhn-checked (CWE-359)
- IPv4 addresses (CWE-359)
- IBANs (CWE-359)
- Dates of birth (CWE-359)
- PII-revealing identifiers in code — names like `ssn`, `first_name`, `date_of_birth`, `passport`, `home_address` (CWE-359)

## Related tools

- [`altais_classify_data`](altais_classify_data.md) — classifies data fields by sensitivity tier
- [`altais_audit_privacy`](altais_audit_privacy.md) — audits privacy-by-design compliance
- [`altais_check_retention`](altais_check_retention.md) — reviews data-retention policies

## See also

- [`data` module](../modules/data.md)
- [Wiki home](../Home.md) · [Contributing](../Contributing.md) · [Deployment](../Deployment.md)
