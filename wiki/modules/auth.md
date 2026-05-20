# `auth` module

The `auth` module audits authentication, authorization, and identity surfaces. It covers OAuth 2.1 / OIDC flows, JWT issuance and verification, session management, CSRF defenses, password hashing, RBAC / ABAC policies, FIDO2 passkeys, and non-human identities (NHI). Most tools accept either inline source code (pattern-based scanning) or a structured config object, so an agent can audit code under review or a deployment configuration without running anything. Every tool is read-only and appends its findings to the shared session report.

| Property | Value |
|----------|-------|
| Module name | `auth` |
| Status | Default-enabled |
| Config key | `[modules] auth` in `altais.config.toml` |
| Tools | 10 |

## Tools

| Tool | Description |
|------|-------------|
| [`altais_audit_oauth`](../tools/altais_audit_oauth.md) | Audits an OAuth 2.1 / OIDC implementation — implicit/password grants, missing PKCE, wildcard redirect URIs, missing state/nonce, tokens in browser storage, refresh-token rotation. |
| [`altais_audit_jwt`](../tools/altais_audit_jwt.md) | Scans code for JWT misuse, decodes a token, and audits the verifier config — `alg:none`, missing allowlist, HS/RS confusion, missing `exp`/`aud`/`iss`. |
| [`altais_audit_session`](../tools/altais_audit_session.md) | Checks session cookie flags, regeneration on login, invalidation on logout, timeouts, and session-ID entropy. |
| [`altais_audit_csrf`](../tools/altais_audit_csrf.md) | Verifies that state-changing endpoints are defended with SameSite cookies, CSRF tokens, or Origin/Referer checks. |
| [`altais_audit_password_hashing`](../tools/altais_audit_password_hashing.md) | Scans source for password-hashing patterns and flags fast hashes used in a password context. |
| [`altais_audit_rbac`](../tools/altais_audit_rbac.md) | Inspects a structured RBAC / ABAC policy for default-allow, superuser roles, self-elevation paths, and inheritance cycles. |
| [`altais_audit_passkey_impl`](../tools/altais_audit_passkey_impl.md) | Audits a FIDO2 / passkey (WebAuthn) implementation — rp_id alignment, userVerification, challenge entropy, sign-count tracking. |
| [`altais_audit_nhi`](../tools/altais_audit_nhi.md) | Audits non-human identities against the OWASP NHI Top 10 — static keys, overdue rotation, wildcard scope, credentials in repo. |
| [`altais_check_secret_lifecycle`](../tools/altais_check_secret_lifecycle.md) | Audits a structured list of secrets for rotation, expiry, and revocation gaps. |
| [`altais_check_nhi_isolation`](../tools/altais_check_nhi_isolation.md) | Verifies that non-human identities are scoped to a single environment / namespace / project. |

## Enabling this module

Both `auth` and `supply_chain` are default-enabled (on out of the box); they can be turned off by setting the key to `false` under `[modules]` in `altais.config.toml`.

```toml
[modules]
auth = false   # disable the auth module
```

## See also

- [Wiki home](../Home.md)
