# `altais_recommend_siem`

Generates platform-aware SIEM integration guidance.

| Property | Value |
|----------|-------|
| Module | [`incident`](../modules/incident.md) |
| Tool type | Generator (returns an artifact) |
| Annotations | `readOnlyHint: true` · `destructiveHint: false` · `idempotentHint: true` · `openWorldHint: false` |

## Description

Produces SIEM integration guidance tailored to a chosen platform — Splunk, Elastic, CloudWatch, Microsoft Sentinel, Datadog, Chronicle / Google SecOps, or another platform. It returns recommended log sources to onboard (excluding those already configured), priority detection use-cases (excluding existing detections), recommended dashboards, and alerting guidance. An agent calls this when planning or maturing a SIEM deployment.

## Input parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `config` | `object` | Yes | The SIEM context (strict — no unknown keys). |
| `config.platform` | `enum` | Yes | The SIEM platform: `splunk`, `elastic`, `cloudwatch`, `sentinel`, `datadog`, `chronicle`, or `other`. |
| `config.log_sources` | `array` of `string` (1–256 chars, max 100) | No | Log sources already onboarded into the SIEM. |
| `config.existing_detections` | `array` of `string` (1–256 chars, max 200) | No | Detection rules / use-cases already in place. |

## Output

Returns a generated artifact as JSON. It includes the target `platform`, a `recommended_log_sources` list (omitting sources already onboarded), a `priority_detections` list of detection use-cases (omitting existing detections), a `dashboards` list of recommended dashboards, and `alerting_guidance`. No findings are emitted.

## Example

**Request**

```json
{ "config": { "platform": "splunk" } }
```

**Response (excerpt)**

```json
{
  "platform": "splunk",
  "recommended_log_sources": ["authentication", "cloud audit trail", "web access logs"],
  "priority_detections": ["impossible-travel logins", "privilege escalation"],
  "dashboards": ["authentication overview"],
  "alerting_guidance": ["Route critical detections to the on-call channel."]
}
```

## Detections

This is a generator. The artifact is platform-aware SIEM integration guidance: recommended log sources to onboard (excluding ones already configured), priority detection use-cases (excluding existing detections), recommended dashboards, and alerting guidance.

## Related tools

- [`altais_audit_logging`](altais_audit_logging.md) — audits the audit-trail that feeds the SIEM
- [`altais_audit_monitoring`](altais_audit_monitoring.md) — audits monitoring posture including SIEM integration
- [`altais_check_canary`](altais_check_canary.md) — assesses deception-control trigger coverage

## See also

- [`incident` module](../modules/incident.md)
- [Wiki home](../Home.md) · [Contributing](../Contributing.md) · [Deployment](../Deployment.md)
