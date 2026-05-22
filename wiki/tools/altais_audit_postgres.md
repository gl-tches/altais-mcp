# `altais_audit_postgres`

Audits a PostgreSQL / CockroachDB configuration.

| Property | Value |
|----------|-------|
| Module | [`database`](../modules/database.md) |
| Tool type | Analyzer (emits findings) |
| Annotations | `readOnlyHint: true` · `destructiveHint: false` · `idempotentHint: true` · `openWorldHint: false` |

## Description

Reviews a supplied PostgreSQL / CockroachDB configuration object for role, privilege, authentication, network, and logging weaknesses. Every field is optional — only settings that are present and insecure are flagged.

## Input parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `config` | `object` | Yes | Known PostgreSQL settings (superuser usage, public-schema grants, RLS, pg_hba.conf auth, password encryption, TLS, `listen_addresses`, extensions, connection logging). |
| `filename` | `string` | No | Filename used for the finding location. |

## Detections

- Application connecting as a superuser (CWE-250); PUBLIC able to CREATE in the public schema (CWE-732).
- Row-level security disabled (CWE-285); `trust` authentication in pg_hba.conf (CWE-287).
- Weak password encryption — md5 vs scram-sha-256 (CWE-327); TLS disabled (CWE-319).
- Listening on all interfaces (CWE-1327); high-risk extensions (CWE-829); connection logging disabled (CWE-778).

## See also

- [`database` module](../modules/database.md)
- [Wiki home](../Home.md)
