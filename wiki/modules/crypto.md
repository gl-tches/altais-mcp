# `crypto` module

The `crypto` module audits the cryptography of an application end to end: algorithm and cipher usage, TLS configuration, insecure randomness, key management, post-quantum readiness, Certificate Transparency log monitoring, certificate pinning, ACME certificate issuance, and cryptographic agility. Every tool is an auditor that emits CWE-tagged findings into the session report.

| Property | Value |
|----------|-------|
| Module name | `crypto` |
| Status | Opt-in (disabled by default) |
| Config key | `[modules] crypto` in `altais.config.toml` |
| Tools | 9 |

## Tools

| Tool | Description |
|------|-------------|
| [`altais_audit_crypto`](../tools/altais_audit_crypto.md) | Audit algorithm usage — weak ciphers, deprecated hashes, ECB mode, static IVs/salts, undersized keys. |
| [`altais_audit_tls`](../tools/altais_audit_tls.md) | Review TLS configuration or source for deprecated protocols, weak ciphers, and disabled certificate verification. |
| [`altais_audit_randomness`](../tools/altais_audit_randomness.md) | Scan source for non-cryptographic PRNGs in security-sensitive contexts. |
| [`altais_audit_key_mgmt`](../tools/altais_audit_key_mgmt.md) | Scan for hardcoded keys and audit a key inventory for storage and rotation gaps. |
| [`altais_assess_pq_readiness`](../tools/altais_assess_pq_readiness.md) | Flag quantum-vulnerable primitives and harvest-now-decrypt-later exposure. |
| [`altais_audit_ct_logs`](../tools/altais_audit_ct_logs.md) | Check Certificate Transparency log monitoring coverage and SCT delivery. |
| [`altais_audit_cert_pinning`](../tools/altais_audit_cert_pinning.md) | Review certificate pinning — dead HPKP header, leaf pinning, missing backup pins. |
| [`altais_audit_acme`](../tools/altais_audit_acme.md) | Review an ACME / Let's Encrypt configuration. |
| [`altais_assess_crypto_agility`](../tools/altais_assess_crypto_agility.md) | Assess whether a cryptographic primitive can be swapped without code changes. |

## Enabling this module

All four of these modules are opt-in. Enable one by setting its key to `true` under `[modules]` in `altais.config.toml` (e.g. `crypto = true`).

## See also

- [Wiki home](../Home.md)
