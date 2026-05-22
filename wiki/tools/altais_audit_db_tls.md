# `altais_audit_db_tls`

Audits a database's TLS / SSL configuration.

| Property | Value |
|----------|-------|
| Module | [`database`](../modules/database.md) |
| Tool type | Analyzer (emits findings) |
| Annotations | `readOnlyHint: true` · `destructiveHint: false` · `idempotentHint: true` · `openWorldHint: false` |

## Description

Reviews a supplied per-database TLS configuration object: whether TLS is enabled, the minimum protocol version, server-certificate verification, cipher-suite strength, self-signed certificates, certificate expiry, and mutual TLS. Every field is optional.

## Input parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `config` | `object` | Yes | Known TLS settings (TLS enabled, minimum protocol version, certificate verification, cipher suites, self-signed certificate, certificate expiry, mutual TLS). |
| `filename` | `string` | No | Filename used for the finding location. |

## Detections

- TLS disabled (CWE-319); a deprecated minimum protocol version — TLS 1.0 / 1.1 (CWE-326).
- Certificate verification disabled (CWE-295); weak cipher suites (CWE-327).
- A self-signed certificate (CWE-295); an expired or expiring certificate; missing mutual TLS.

## See also

- [`database` module](../modules/database.md)
- [Wiki home](../Home.md)
