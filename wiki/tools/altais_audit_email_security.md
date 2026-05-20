# `altais_audit_email_security`

Audits a domain's SPF / DKIM / DMARC email-authentication posture.

| Property | Value |
|----------|-------|
| Module | [`protocol`](../modules/protocol.md) |
| Tool type | Auditor (emits findings) |
| Annotations | `readOnlyHint: true` · `destructiveHint: false` · `idempotentHint: true` · `openWorldHint: false` |

## Description

This tool audits a domain's email-authentication posture. It parses the SPF and DMARC record strings and flags missing SPF, a permissive `+all` / `?all` or absent `all` mechanism, missing DKIM, missing DMARC, a `p=none` DMARC policy, no `rua` aggregate reporting, missing MTA-STS, and a domain without DNSSEC. An agent calls it when reviewing a domain's defenses against spoofing and phishing.

## Input parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `config` | `object` | Yes | Structured email-authentication posture for a domain (see below). |
| `filename` | `string` (1–512 chars) | No | Filename used for the finding location. |

The `config` object accepts these optional fields:

| Field | Type | Description |
|-------|------|-------------|
| `spf_record` | `string` (1–2048 chars) | The domain's published SPF TXT record. |
| `dkim_enabled` | `boolean` | Whether DKIM signing is configured. |
| `dkim_selectors` | `string[]` (each 1–128 chars, max 32) | Published DKIM selectors. |
| `dmarc_record` | `string` (1–2048 chars) | The domain's published DMARC TXT record. |
| `dmarc_policy` | enum: `none` \| `quarantine` \| `reject` | The DMARC `p=` policy. |
| `mta_sts` | `boolean` | Whether SMTP MTA-STS is enabled. |
| `dnssec` | `boolean` | Whether the zone is signed with DNSSEC. |

## Output

Returns `{ summary: { total, by_severity }, findings: [...] }`. Each finding has the standard shape (`id`, `module`, `rule`, `severity`, `cwe`, `title`, `description`, `location?`, `evidence?`, `remediation`, `references`, `tags`, `status`). All findings are also appended to the session report `FindingStore`.

## Example

**Request**

```json
{ "config": { "spf_record": "v=spf1 +all", "dmarc_policy": "none" } }
```

**Response (excerpt)**

```json
{
  "summary": { "total": 2, "by_severity": { "high": 1, "medium": 1 } },
  "findings": [
    { "rule": "email-spf-permissive-all", "severity": "high", "title": "SPF record ends in +all" },
    { "rule": "email-dmarc-policy-none", "severity": "medium", "title": "DMARC policy is p=none" }
  ]
}
```

## Detections

- `email-missing-spf` — no SPF record (CWE-290)
- `email-spf-permissive-all` — SPF ends in `+all` (CWE-290)
- `email-spf-neutral-all` — SPF ends in `?all` (CWE-290)
- `email-spf-no-all-mechanism` — SPF record with no terminating `all` (CWE-290)
- `email-missing-dkim` — no DKIM signing (CWE-345)
- `email-missing-dmarc` — no DMARC record (CWE-290)
- `email-dmarc-policy-none` — DMARC `p=none` policy (CWE-290)
- `email-dmarc-no-aggregate-reporting` — no `rua` aggregate reporting (CWE-778)
- `email-missing-mta-sts` — missing SMTP MTA-STS (CWE-319)
- `email-missing-dnssec` — domain without DNSSEC (CWE-345)

## Related tools

- [`altais_audit_dns`](altais_audit_dns.md) — DNSSEC and zone-level DNS review
- [`altais_check_webhook`](altais_check_webhook.md) — another sender-authentication audit

## See also

- [`protocol` module](../modules/protocol.md)
- [Wiki home](../Home.md) · [Contributing](../Contributing.md) · [Deployment](../Deployment.md)
