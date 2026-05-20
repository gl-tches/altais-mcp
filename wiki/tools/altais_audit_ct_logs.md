# `altais_audit_ct_logs`

Checks Certificate Transparency log monitoring coverage and SCT delivery.

| Property | Value |
|----------|-------|
| Module | [`crypto`](../modules/crypto.md) |
| Tool type | Auditor (emits findings) |
| Annotations | `readOnlyHint: true` · `destructiveHint: false` · `idempotentHint: true` · `openWorldHint: false` |

## Description

Checks whether Certificate Transparency log monitoring is enabled for every owned domain, whether mis-issuance alerts are routed to a responder, whether the server delivers SCTs, and flags reliance on the deprecated `Expect-CT` header. An agent calls this when reviewing how an organization detects unauthorized or mis-issued certificates for its domains.

## Input parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `source` | `string` (1–2097152 chars) | No | Source code to scan with pattern checks. |
| `filename` | `string` (1–512 chars) | No | Filename used for the finding location. |
| `config` | `object` | No | Structured CT monitoring configuration. |
| `config.monitoring_enabled` | `boolean` | No | Whether CT log monitoring is enabled. |
| `config.owned_domains` | `array` of `string` (1–256 chars, max 512) | No | Domains the organization owns. |
| `config.monitored_domains` | `array` of `string` (1–256 chars, max 512) | No | Domains currently under CT monitoring. |
| `config.alerting_enabled` | `boolean` | No | Whether mis-issuance alerts are routed to a responder. |
| `config.requires_sct` | `boolean` | No | Whether the server requires/delivers SCTs. |

## Output

Returns `{ summary: { total, by_severity }, findings: [...] }`. Each finding has the standard shape `{ id, module, rule, severity, cwe, title, description, location?, evidence?, remediation, references, tags, status }`. Findings are appended to the session report.

## Example

**Request**

```json
{ "config": { "monitoring_enabled": false, "owned_domains": ["example.com"] } }
```

**Response (excerpt)**

```json
{
  "summary": { "total": 1, "by_severity": { "medium": 1 } },
  "findings": [
    {
      "rule": "ct-monitoring-disabled",
      "severity": "medium",
      "title": "Certificate Transparency monitoring is not enabled",
      "status": "open"
    }
  ]
}
```

## Detections

- CT log monitoring disabled (CWE-295)
- Owned domains not covered by CT monitoring (CWE-295)
- No alerting on certificate mis-issuance (CWE-778)
- SCTs not required or delivered by the server (CWE-295)
- Reliance on the deprecated `Expect-CT` header (CWE-1104)

## Related tools

- [`altais_audit_cert_pinning`](altais_audit_cert_pinning.md) — reviews certificate pinning posture
- [`altais_audit_tls`](altais_audit_tls.md) — reviews TLS configuration
- [`altais_audit_acme`](altais_audit_acme.md) — reviews ACME certificate issuance

## See also

- [`crypto` module](../modules/crypto.md)
- [Wiki home](../Home.md) · [Contributing](../Contributing.md) · [Deployment](../Deployment.md)
