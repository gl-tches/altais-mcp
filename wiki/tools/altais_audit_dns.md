# `altais_audit_dns`

Checks a DNS zone configuration for security weaknesses.

| Property | Value |
|----------|-------|
| Module | [`infra`](../modules/infra.md) |
| Tool type | Auditor (emits findings) |
| Annotations | `readOnlyHint: true` · `destructiveHint: false` · `idempotentHint: true` · `openWorldHint: false` |

## Description

This tool reviews a structured DNS zone configuration for security weaknesses. It flags DNSSEC being disabled, open zone transfers (AXFR), missing CAA records, wildcard records, and dangling records pointing to unclaimed external resources. An agent calls it when reviewing a domain's DNS posture or assessing subdomain-takeover exposure.

## Input parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `config` | `object` | Yes | The DNS configuration to audit (see below). |
| `filename` | `string` (1–512 chars) | No | Filename used for the finding location. |

The `config` object accepts these optional fields:

| Field | Type | Description |
|-------|------|-------------|
| `dnssec_enabled` | `boolean` | Whether DNSSEC is enabled for the zone. |
| `zone_transfer_allowed` | `boolean` | Whether AXFR zone transfers are allowed. |
| `allowed_to` | `string[]` (each 1–128 chars, max 256) | Hosts permitted to perform zone transfers. |
| `caa_records` | `string[]` (each 1–256 chars, max 256) | CAA records published for the zone. |
| `wildcard_records` | `boolean` or `string[]` (each 1–256 chars, max 256) | Whether wildcard records exist, or the list of wildcard record names. |
| `records` | `array` (max 5000) of record objects | DNS records to inspect for dangling external targets. |

Each entry in `records` is an object:

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `name` | `string` (1–256 chars) | Yes | Record name / FQDN. |
| `type` | `string` (1–16 chars) | Yes | Record type (e.g. `A`, `CNAME`, `MX`, `NS`). |
| `value` | `string` (1–512 chars) | Yes | Record value / target. |
| `points_to_external` | `boolean` | No | Whether the record's target is an external (third-party) resource. |

## Output

Returns `{ summary: { total, by_severity }, findings: [...] }`. Each finding has the standard shape (`id`, `module`, `rule`, `severity`, `cwe`, `title`, `description`, `location?`, `evidence?`, `remediation`, `references`, `tags`, `status`). All findings are also appended to the session report `FindingStore`.

## Example

**Request**

```json
{ "config": { "dnssec_enabled": false, "zone_transfer_allowed": true } }
```

**Response (excerpt)**

```json
{
  "summary": { "total": 2, "by_severity": { "medium": 2 } },
  "findings": [
    { "rule": "dns-dnssec-disabled", "severity": "medium", "title": "DNSSEC disabled" },
    { "rule": "dns-open-zone-transfer", "severity": "medium", "title": "Open AXFR zone transfer" }
  ]
}
```

## Detections

- `dns-dnssec-disabled` — DNSSEC disabled; responses cannot be verified (CWE-350)
- `dns-open-zone-transfer` — open zone transfers / AXFR allow full zone enumeration (CWE-200)
- `dns-missing-caa` — no CAA records; any CA may issue certificates (CWE-295)
- `dns-wildcard-record` — wildcard records broaden the attack surface (CWE-200)
- `dns-dangling-record` — record points to an unclaimed external resource (subdomain-takeover risk) (CWE-200)

## Related tools

- [`altais_audit_email_security`](altais_audit_email_security.md) — SPF / DKIM / DMARC records published in the same zone
- [`altais_audit_network`](altais_audit_network.md) — network segmentation and firewall review

## See also

- [`infra` module](../modules/infra.md)
- [Wiki home](../Home.md) · [Contributing](../Contributing.md) · [Deployment](../Deployment.md)
