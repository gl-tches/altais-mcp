# `altais_check_canary`

Assesses deception-control coverage from a declarative canary-token and honeypot configuration.

| Property | Value |
|----------|-------|
| Module | [`incident`](../modules/incident.md) |
| Tool type | Auditor (emits findings) |
| Annotations | `readOnlyHint: true` · `destructiveHint: false` · `idempotentHint: true` · `openWorldHint: false` |

## Description

Reviews a declarative deception-control configuration and flags gaps: no canary tokens deployed (CWE-778), no honeypots deployed, triggers that raise no alert, alerts with no routing destination, coverage gaps for sensitive areas (databases, credential stores, file shares, cloud accounts, internal endpoints), and a missing monitored-asset inventory. An agent calls this when assessing detection-engineering maturity and early-warning controls.

## Input parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `config` | `object` | Yes | The deception-control configuration (strict — no unknown keys). |
| `config.canary_tokens_deployed` | `boolean` | No | Whether canary tokens are deployed. |
| `config.honeypots_deployed` | `boolean` | No | Whether honeypots are deployed. |
| `config.coverage_areas` | `array` of `string` (1–128 chars, max 50) | No | Areas covered by deception controls, e.g. `database`, `credentials`, `cloud`, `filesystem`, `endpoints`. |
| `config.alerting_enabled` | `boolean` | No | Whether a canary / honeypot trigger raises an alert. |
| `config.alert_routing` | `string` (1–256 chars) | No | Where trigger alerts are routed, e.g. an on-call channel. |
| `config.monitored_assets` | `array` of `string` (1–256 chars, max 200) | No | Assets the deception controls are protecting. |
| `filename` | `string` (1–512 chars) | No | Filename used for the finding location. |

## Output

Returns `{ summary: { total, by_severity }, findings: [...] }`. Each finding has the standard shape `{ id, module, rule, severity, cwe, title, description, location?, evidence?, remediation, references, tags, status }`. Findings are appended to the session report.

## Example

**Request**

```json
{ "config": { "canary_tokens_deployed": false, "alerting_enabled": false } }
```

**Response (excerpt)**

```json
{
  "summary": { "total": 2, "by_severity": { "medium": 2 } },
  "findings": [
    { "rule": "no-canary-tokens", "cwe": ["CWE-778"], "status": "open" }
  ]
}
```

## Detections

- No canary tokens deployed (CWE-778)
- No honeypots deployed
- Trigger events that raise no alert
- Alerts with no routing destination
- Coverage gaps for sensitive areas — databases, credential stores, file shares, cloud accounts, internal endpoints
- Missing monitored-asset inventory

## Related tools

- [`altais_audit_logging`](altais_audit_logging.md) — audits audit-trail completeness
- [`altais_audit_monitoring`](altais_audit_monitoring.md) — audits broader monitoring and alerting coverage
- [`altais_recommend_siem`](altais_recommend_siem.md) — recommends SIEM detections for trigger events

## See also

- [`incident` module](../modules/incident.md)
- [Wiki home](../Home.md) · [Contributing](../Contributing.md) · [Deployment](../Deployment.md)
