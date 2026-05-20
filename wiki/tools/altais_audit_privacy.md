# `altais_audit_privacy`

Checks an implementation against GDPR-aligned privacy-by-design principles.

| Property | Value |
|----------|-------|
| Module | [`data`](../modules/data.md) |
| Tool type | Auditor (emits findings) |
| Annotations | `readOnlyHint: true` · `destructiveHint: false` · `idempotentHint: true` · `openWorldHint: false` |

## Description

Checks an implementation against the GDPR-aligned privacy-by-design principles: data minimization, purpose limitation, consent mechanism, encryption at rest and in transit, private-by-default, DPO designation, DPIA, user data export (right to access / portability), user data deletion (right to erasure), and a breach-notification process. It emits a finding for every principle that is false or missing, and flags enabled third-party data sharing as a risk. An agent calls this when reviewing a system's privacy posture.

## Input parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `config` | `object` | Yes | Privacy-by-design configuration flags for the implementation. |
| `config.data_minimization` | `boolean` | No | Whether only necessary data is collected. |
| `config.purpose_limitation` | `boolean` | No | Whether data use is limited to a stated purpose. |
| `config.consent_mechanism` | `boolean` | No | Whether a consent mechanism exists. |
| `config.encryption_at_rest` | `boolean` | No | Whether stored data is encrypted. |
| `config.encryption_in_transit` | `boolean` | No | Whether data in transit is encrypted. |
| `config.default_private` | `boolean` | No | Whether settings default to private. |
| `config.dpo_designated` | `boolean` | No | Whether a Data Protection Officer is designated. |
| `config.dpia_conducted` | `boolean` | No | Whether a Data Protection Impact Assessment was conducted. |
| `config.user_data_export` | `boolean` | No | Whether users can export their data (right to access / portability). |
| `config.user_data_deletion` | `boolean` | No | Whether users can delete their data (right to erasure). |
| `config.breach_notification_process` | `boolean` | No | Whether a breach-notification process exists. |
| `config.third_party_data_sharing` | `boolean` | No | Whether data is shared with third parties. |

## Output

Returns `{ summary: { total, by_severity }, findings: [...] }`. Each finding has the standard shape `{ id, module, rule, severity, cwe, title, description, location?, evidence?, remediation, references, tags, status }`. Findings are appended to the session report.

## Example

**Request**

```json
{ "config": { "consent_mechanism": false, "user_data_deletion": false } }
```

**Response (excerpt)**

```json
{
  "summary": { "total": 2, "by_severity": { "medium": 2 } },
  "findings": [
    { "rule": "no-consent-mechanism", "severity": "medium", "status": "open" },
    { "rule": "no-data-deletion", "severity": "medium", "status": "open" }
  ]
}
```

## Detections

- Missing data minimization (CWE-359)
- Missing purpose limitation (CWE-359)
- No consent mechanism (CWE-359)
- No encryption at rest (CWE-311)
- No encryption in transit (CWE-319)
- Not private by default (CWE-1188)
- No DPO designated (CWE-359)
- No DPIA conducted (CWE-359)
- No user data export — right to access / portability (CWE-359)
- No user data deletion — right to erasure (CWE-359)
- No breach-notification process (CWE-359)
- Enabled third-party data sharing flagged as a risk (CWE-359)

## Related tools

- [`altais_detect_pii`](altais_detect_pii.md) — finds PII in code and sample data
- [`altais_classify_data`](altais_classify_data.md) — classifies data fields by sensitivity tier
- [`altais_check_retention`](altais_check_retention.md) — reviews data-retention policies

## See also

- [`data` module](../modules/data.md)
- [Wiki home](../Home.md) · [Contributing](../Contributing.md) · [Deployment](../Deployment.md)
