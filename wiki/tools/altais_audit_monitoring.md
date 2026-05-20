# `altais_audit_monitoring`

Audits an application's monitoring and observability posture for security-event coverage.

| Property | Value |
|----------|-------|
| Module | [`runtime`](../modules/runtime.md) |
| Tool type | Auditor (emits findings) |
| Annotations | `readOnlyHint: true` · `destructiveHint: false` · `idempotentHint: true` · `openWorldHint: false` |

## Description

Reviews an application's monitoring and observability posture for security-event coverage. It flags missing security-event logging (authentication, authorization failures, input-validation failures, administrative actions), no alerting, unrouted alerts, no SIEM integration, no anomaly detection, missing metrics or dashboards, no on-call rotation, and a slow mean time to detect. It emits one finding per gap with real CWE references and actionable remediation. An agent calls this when assessing detection and response readiness.

## Input parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `config` | `object` | Yes | The monitoring-posture configuration. All boolean fields are required. |
| `config.logs_authentication` | `boolean` | Yes | Whether authentication events (login success / failure) are logged. |
| `config.logs_authorization_failures` | `boolean` | Yes | Whether authorization / access-denied failures are logged. |
| `config.logs_input_validation_failures` | `boolean` | Yes | Whether input-validation failures are logged. |
| `config.logs_admin_actions` | `boolean` | Yes | Whether administrative / privileged actions are logged. |
| `config.alerting_enabled` | `boolean` | Yes | Whether alerts fire on security events. |
| `config.alert_routing` | `boolean` | Yes | Whether alerts are routed to a responder or on-call destination. |
| `config.siem_integrated` | `boolean` | Yes | Whether logs are forwarded to a SIEM. |
| `config.metrics_collected` | `boolean` | Yes | Whether application metrics are collected. |
| `config.anomaly_detection` | `boolean` | Yes | Whether behavioral / anomaly detection is in place. |
| `config.dashboards` | `boolean` | Yes | Whether security / operations dashboards exist. |
| `config.on_call` | `boolean` | Yes | Whether an on-call rotation owns security alerts. |
| `config.mean_time_to_detect_minutes` | `integer` (0–525600) | Yes | Mean time to detect a security incident, in minutes. |
| `filename` | `string` (1–512 chars) | No | Filename used for the finding location. |

## Output

Returns `{ summary: { total, by_severity }, findings: [...] }`. Each finding has the standard shape `{ id, module, rule, severity, cwe, title, description, location?, evidence?, remediation, references, tags, status }`. One finding is emitted per monitoring gap. Findings are appended to the session report.

## Example

**Request**

```json
{
  "config": {
    "logs_authentication": false,
    "logs_authorization_failures": true,
    "logs_input_validation_failures": true,
    "logs_admin_actions": true,
    "alerting_enabled": false,
    "alert_routing": false,
    "siem_integrated": false,
    "metrics_collected": true,
    "anomaly_detection": false,
    "dashboards": true,
    "on_call": true,
    "mean_time_to_detect_minutes": 480
  }
}
```

**Response (excerpt)**

```json
{
  "summary": { "total": 4, "by_severity": { "medium": 4 } },
  "findings": [
    { "rule": "no-authentication-logging", "status": "open" },
    { "rule": "no-alerting", "status": "open" }
  ]
}
```

## Detections

- Missing security-event logging — authentication, authorization failures, input-validation failures, administrative actions
- No alerting on security events
- Alerts with no routing destination
- No SIEM integration
- No anomaly / behavioral detection
- Missing application metrics
- Missing security / operations dashboards
- No on-call rotation owning security alerts
- A slow mean time to detect security incidents

## Related tools

- [`altais_audit_logging`](altais_audit_logging.md) — audits audit-trail completeness and log injection
- [`altais_recommend_siem`](altais_recommend_siem.md) — recommends SIEM onboarding and detections
- [`altais_check_canary`](altais_check_canary.md) — assesses deception-control coverage

## See also

- [`runtime` module](../modules/runtime.md)
- [Wiki home](../Home.md) · [Contributing](../Contributing.md) · [Deployment](../Deployment.md)
