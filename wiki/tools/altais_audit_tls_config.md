# `altais_audit_tls_config`

Audits a structured TLS / mTLS configuration against RFC 9325 and RFC 8996.

| Property | Value |
|----------|-------|
| Module | [`protocol`](../modules/protocol.md) |
| Tool type | Auditor (emits findings) |
| Annotations | `readOnlyHint: true` · `destructiveHint: false` · `idempotentHint: true` · `openWorldHint: false` |

## Description

This tool audits a structured TLS / mutual-TLS configuration against RFC 9325 (TLS best practices) and RFC 8996 (deprecating TLS 1.0/1.1). It flags deprecated protocols, missing TLS 1.3, weak or non-AEAD cipher suites, missing forward secrecy, disabled OCSP stapling, insecure session resumption, weak certificate signature algorithms, mTLS with an optional client certificate, missing HSTS, and missing Certificate Transparency. An agent calls it when reviewing a server or client's TLS posture.

## Input parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `config` | `object` | Yes | Structured TLS / mTLS configuration to audit (see below). |
| `filename` | `string` (1–512 chars) | No | Filename used for the finding location. |

The `config` object accepts these optional fields:

| Field | Type | Description |
|-------|------|-------------|
| `min_version` | enum: `SSLv2` \| `SSLv3` \| `TLSv1.0` \| `TLSv1.1` \| `TLSv1.2` \| `TLSv1.3` | Lowest TLS/SSL version the endpoint accepts. |
| `enabled_versions` | array of the version enum (max 6) | All TLS/SSL versions the endpoint will negotiate. |
| `cipher_suites` | `string[]` (each 1–128 chars, max 128) | Configured cipher suite names (IANA or OpenSSL form). |
| `mtls_enabled` | `boolean` | Whether mutual TLS is configured. |
| `client_cert_required` | `boolean` | Whether a valid client certificate is mandatory to complete the handshake. |
| `ocsp_stapling` | `boolean` | Whether the server staples an OCSP response. |
| `session_resumption` | enum: `none` \| `session_id` \| `session_ticket` \| `tls13_psk` | Session resumption mechanism in use. |
| `forward_secrecy` | `boolean` | Whether the negotiated key exchange provides forward secrecy. |
| `cert_signature_algorithm` | `string` (1–64 chars) | Signature algorithm of the server certificate (e.g. `sha256WithRSA`). |
| `hsts` | `boolean` | Whether HSTS is sent for the endpoint. |
| `certificate_transparency` | `boolean` | Whether Certificate Transparency (SCTs) is enforced. |

## Output

Returns `{ summary: { total, by_severity }, findings: [...] }`. Each finding has the standard shape (`id`, `module`, `rule`, `severity`, `cwe`, `title`, `description`, `location?`, `evidence?`, `remediation`, `references`, `tags`, `status`). All findings are also appended to the session report `FindingStore`.

## Example

**Request**

```json
{ "config": { "min_version": "TLSv1.0", "forward_secrecy": false } }
```

**Response (excerpt)**

```json
{
  "summary": { "total": 2, "by_severity": { "high": 1, "medium": 1 } },
  "findings": [
    { "rule": "tls-min-version-too-low", "severity": "high", "title": "Minimum TLS version too low" }
  ]
}
```

## Detections

- `tls-min-version-too-low` / `tls-deprecated-protocol-enabled` — SSLv3 / TLS 1.0 / 1.1 (CWE-326, CWE-327)
- `tls-no-tls13` — TLS 1.3 not enabled (CWE-326)
- `tls-weak-cipher-suite` / `tls-non-aead-cipher-suite` — weak or non-AEAD cipher suites (CWE-326, CWE-327)
- `tls-no-forward-secrecy` — missing forward secrecy (CWE-326)
- `tls-no-ocsp-stapling` — OCSP stapling disabled (CWE-299)
- `tls-insecure-session-resumption` — insecure session resumption (CWE-326)
- `tls-weak-cert-signature-algorithm` — SHA-1 / MD5 certificate signature algorithm (CWE-327)
- `tls-mtls-client-cert-optional` — mTLS enabled but client certificate not required (CWE-295)
- `tls-no-hsts` — missing HSTS (CWE-319)
- `tls-no-certificate-transparency` — Certificate Transparency not enforced (CWE-295)

## Related tools

- [`altais_audit_api_gateway`](altais_audit_api_gateway.md) — edge TLS termination review
- [`altais_audit_email_security`](altais_audit_email_security.md) — SMTP MTA-STS / transport security

## See also

- [`protocol` module](../modules/protocol.md)
- [Wiki home](../Home.md) · [Contributing](../Contributing.md) · [Deployment](../Deployment.md)
