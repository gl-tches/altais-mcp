# `altais_check_webhook`

Verifies a webhook receiver's HMAC signature implementation.

| Property | Value |
|----------|-------|
| Module | [`protocol`](../modules/protocol.md) |
| Tool type | Auditor (emits findings) |
| Annotations | `readOnlyHint: true` · `destructiveHint: false` · `idempotentHint: true` · `openWorldHint: false` |

## Description

This tool verifies a webhook receiver's HMAC signature implementation from handler source code, a structured config, or both. It flags missing signature verification, a signature compared with `==` / `===` instead of a constant-time compare, weak hash algorithms, missing timestamp validation, missing replay protection, and a hardcoded signing secret. An agent calls it when reviewing an inbound webhook endpoint.

## Input parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `source` | `string` (1–524288 chars) | No* | Webhook handler source code, scanned with pattern matching. |
| `config` | `object` | No* | Structured description of the webhook verification posture (see below). |
| `filename` | `string` (1–512 chars) | No | Filename used for the finding location. |

*At least one of `source` or `config` must be provided.

The `config` object accepts these optional fields:

| Field | Type | Description |
|-------|------|-------------|
| `signature_verified` | `boolean` | Whether the inbound signature is verified before processing. |
| `hash_algorithm` | `string` (1–32 chars) | Hash algorithm backing the HMAC signature. |
| `constant_time_comparison` | `boolean` | Whether the signature is compared in constant time. |
| `timestamp_validation` | `boolean` | Whether a signed timestamp is checked against a tolerance window. |
| `replay_protection` | `boolean` | Whether delivery IDs / nonces are de-duplicated to block replays. |
| `secret_source` | enum: `env` \| `secrets_manager` \| `config_file` \| `hardcoded` | Where the webhook signing secret is loaded from. |

## Output

Returns `{ summary: { total, by_severity }, findings: [...] }`. Each finding has the standard shape (`id`, `module`, `rule`, `severity`, `cwe`, `title`, `description`, `location?`, `evidence?`, `remediation`, `references`, `tags`, `status`). All findings are also appended to the session report `FindingStore`.

## Example

**Request**

```json
{ "config": { "signature_verified": true, "constant_time_comparison": false } }
```

**Response (excerpt)**

```json
{
  "summary": { "total": 1, "by_severity": { "medium": 1 } },
  "findings": [
    { "rule": "webhook-non-constant-time-compare", "severity": "medium", "title": "Non-constant-time signature comparison" }
  ]
}
```

## Detections

- `webhook-non-constant-time-compare` — signature compared with `==` / `===` instead of a constant-time compare (CWE-208, CWE-347)
- `webhook-weak-hash-algorithm` — weak hash algorithm (MD5 / SHA-1) backing the HMAC (CWE-328, CWE-347)
- `webhook-hardcoded-secret` — hardcoded signing secret (CWE-798)
- No signature verification, missing timestamp validation, and missing replay protection are also flagged from the `config` posture.

## Related tools

- [`altais_audit_email_security`](altais_audit_email_security.md) — another sender-authentication audit
- [`altais_audit_sse`](altais_audit_sse.md) — auditing an event-stream endpoint

## See also

- [`protocol` module](../modules/protocol.md)
- [Wiki home](../Home.md) · [Contributing](../Contributing.md) · [Deployment](../Deployment.md)
