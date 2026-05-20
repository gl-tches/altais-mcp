# `altais_audit_logging`

Assesses audit-trail completeness and log-injection prevention.

| Property | Value |
|----------|-------|
| Module | [`incident`](../modules/incident.md) |
| Tool type | Auditor (emits findings) |
| Annotations | `readOnlyHint: true` · `destructiveHint: false` · `idempotentHint: true` · `openWorldHint: false` |

## Description

Reviews logging posture for security-event coverage and safe logging practices. It scans optional source code for user-controlled input concatenated into log calls (CWE-117) and sensitive values written to logs (CWE-532), and reviews an optional declarative logging-configuration object for a missing audit log, absent security-event logging (CWE-778), missing log-injection neutralization, unredacted PII, no tamper protection, no centralization, and too-short retention. An agent calls this when reviewing observability and incident-readiness controls.

## Input parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `source` | `string` (1–524288 chars) | No | Source code to scan for log-injection and sensitive-data logging. |
| `config` | `object` | No | Declarative logging-configuration object (strict — no unknown keys). |
| `config.has_audit_log` | `boolean` | No | Whether a dedicated audit log exists. |
| `config.logs_authentication` | `boolean` | No | Whether authentication events (success and failure) are logged. |
| `config.logs_authorization` | `boolean` | No | Whether authorization decisions are logged. |
| `config.logs_admin_actions` | `boolean` | No | Whether administrative and privileged actions are logged. |
| `config.log_injection_protection` | `boolean` | No | Whether untrusted input is neutralized before logging. |
| `config.centralized` | `boolean` | No | Whether logs are shipped to a centralized store. |
| `config.tamper_protection` | `boolean` | No | Whether the audit log is append-only / integrity-protected. |
| `config.retention_days` | `integer` (0–36500) | No | How many days audit logs are retained. |
| `config.logs_sensitive_data` | `boolean` | No | Whether logs contain sensitive data or PII. |
| `config.pii_redaction` | `boolean` | No | Whether PII / secret redaction is applied to log output. |
| `config.includes_timestamp` | `boolean` | No | Whether every log entry includes a timestamp. |
| `config.includes_actor` | `boolean` | No | Whether every log entry identifies the acting principal. |
| `filename` | `string` (1–512 chars) | No | Filename used for the finding location. |

At least one of `source` or `config` must be provided.

## Output

Returns `{ summary: { total, by_severity }, findings: [...] }`. Each finding has the standard shape `{ id, module, rule, severity, cwe, title, description, location?, evidence?, remediation, references, tags, status }`. Findings are appended to the session report.

## Example

**Request**

```json
{ "config": { "has_audit_log": false, "log_injection_protection": false } }
```

**Response (excerpt)**

```json
{
  "summary": { "total": 2, "by_severity": { "high": 1, "medium": 1 } },
  "findings": [
    { "rule": "no-audit-log", "cwe": ["CWE-778"], "status": "open" },
    { "rule": "no-log-injection-protection", "cwe": ["CWE-117"], "status": "open" }
  ]
}
```

## Detections

- User-controlled input concatenated into log calls — log injection (CWE-117)
- Sensitive values / PII written to logs (CWE-532)
- Missing dedicated audit log and missing security-event logging (CWE-778)
- Absent log-injection neutralization
- Unredacted PII in log output
- No tamper protection on the audit log
- Logs not centralized
- Too-short audit-log retention

## Related tools

- [`altais_check_canary`](altais_check_canary.md) — assesses deception-control coverage
- [`altais_recommend_siem`](altais_recommend_siem.md) — recommends SIEM onboarding for log sources
- [`altais_audit_monitoring`](altais_audit_monitoring.md) — audits broader monitoring and alerting coverage

## See also

- [`incident` module](../modules/incident.md)
- [Wiki home](../Home.md) · [Contributing](../Contributing.md) · [Deployment](../Deployment.md)
