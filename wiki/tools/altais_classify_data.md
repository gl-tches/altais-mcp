# `altais_classify_data`

Classifies data fields into restricted, confidential, internal, and public sensitivity tiers.

| Property | Value |
|----------|-------|
| Module | [`data`](../modules/data.md) |
| Tool type | Auditor (emits findings) |
| Annotations | `readOnlyHint: true` · `destructiveHint: false` · `idempotentHint: true` · `openWorldHint: false` |

## Description

Classifies data fields into sensitivity tiers — `restricted` (passwords, secrets, SSN, credit card, health, biometric), `confidential` (email, phone, name, address, date of birth, IP, precise location), `internal` (user_id, timestamps, internal flags), or `public` (slug, public title). It returns a per-field classification, a tier summary, and a tracked finding for every restricted or confidential field. An agent calls this when reviewing a schema or data model to understand which fields need extra protection.

## Input parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `fields` | `array` (1–500 items) | Yes | Data fields to classify by sensitivity tier. |
| `fields[].name` | `string` (1–256 chars) | Yes | Field, column, or property name. |
| `fields[].type` | `string` (1–128 chars) | No | Declared data type. |
| `fields[].description` | `string` (1–1024 chars) | No | Human description of the field. |

## Output

Returns `{ classifications, summary: { total, by_severity }, findings: [...] }`. `classifications` is a per-field array of `{ name, tier }`. Each finding has the standard shape `{ id, module, rule, severity, cwe, title, description, location?, evidence?, remediation, references, tags, status }`, emitted for every restricted or confidential field. Findings are appended to the session report.

## Example

**Request**

```json
{ "fields": [{ "name": "password" }, { "name": "email" }, { "name": "created_at" }] }
```

**Response (excerpt)**

```json
{
  "classifications": [
    { "name": "password", "tier": "restricted" },
    { "name": "email", "tier": "confidential" },
    { "name": "created_at", "tier": "internal" }
  ],
  "summary": { "total": 2 },
  "findings": ["..."]
}
```

## Detections

- Restricted-tier fields — passwords, secrets, SSN, credit card, health, biometric (CWE-359)
- Confidential-tier fields — email, phone, name, address, date of birth, IP, precise location (CWE-359)
- A tracked finding is emitted for each restricted or confidential field so it can be reviewed for protection controls.

## Related tools

- [`altais_detect_pii`](altais_detect_pii.md) — finds PII in code and sample data
- [`altais_audit_privacy`](altais_audit_privacy.md) — audits privacy-by-design compliance
- [`altais_check_retention`](altais_check_retention.md) — reviews data-retention policies

## See also

- [`data` module](../modules/data.md)
- [Wiki home](../Home.md) · [Contributing](../Contributing.md) · [Deployment](../Deployment.md)
