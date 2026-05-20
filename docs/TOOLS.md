# altais-mcp — Tool Reference

Every tool altais-mcp exposes, grouped by module. altais-mcp ships **132 tools across 24 modules**. `core` is always loaded; `scan`, `threat_model`, `owasp`, `secrets`, `headers`, `supply_chain`, and `auth` are enabled by default; the remaining 16 modules are opt-in via `altais.config.toml`.

Every tool is read-only and declares `readOnlyHint: true`, `destructiveHint: false`, `idempotentHint: true`, `openWorldHint: false`.

Conventions used below:

- **Inputs** lists the key fields of each tool's Zod `inputSchema`. Fields marked _(optional)_ may be omitted; all others are required. String, array, and numeric fields carry length/size/range constraints in the schema.
- Most analyzer tools return `{ "summary": { "total", "by_severity" }, "findings": [...] }`, where each finding has the shape `{ id, module, rule, severity, cwe, title, description, location?, evidence?, remediation, references, tags, status }`. Generator tools return a structured artifact instead. The examples sketch a representative shape — they are not exhaustive dumps.
- Finding IDs are deterministic: `{module}:{rule}:{contentHash}`.

---

## Table of contents

- [core](#module-core)
- [scan](#module-scan)
- [threat_model](#module-threat_model)
- [owasp](#module-owasp)
- [secrets](#module-secrets)
- [headers](#module-headers)
- [supply_chain](#module-supply_chain)
- [auth](#module-auth)
- [crypto](#module-crypto)
- [container](#module-container)
- [code](#module-code)
- [data](#module-data)
- [iac](#module-iac)
- [api](#module-api)
- [compliance](#module-compliance)
- [infra](#module-infra)
- [protocol](#module-protocol)
- [vuln_db](#module-vuln_db)
- [incident](#module-incident)
- [testing](#module-testing)
- [sdlc](#module-sdlc)
- [ml_security](#module-ml_security)
- [agentic](#module-agentic)
- [runtime](#module-runtime)

---

## Module: `core`

Always loaded. Config inspection, CWE lookup, CVSS scoring, session reporting, and risk summary.

### `altais_get_config`

Return the active server config and the list of currently loaded modules.

- **Inputs:** none.

```jsonc
// Request: {}
// Response:
{
  "server": { "name": "altais-mcp", "transport": "stdio", "port": 3100, "log_level": "info" },
  "modules": { "scan": true, "secrets": true, "crypto": false /* ... */ },
  "active_modules": ["core", "scan", "secrets", "headers", "threat_model", "owasp", "supply_chain", "auth"],
  "package_version": "0.1.0"
}
```

### `altais_explain_cwe`

Look up a CWE entry from the bundled top-100 CWE database.

- **Inputs:** `cwe` — CWE identifier, e.g. `CWE-79` or `79`.

```jsonc
// Request: { "cwe": "CWE-89" }
// Response: { "id": "CWE-89", "name": "SQL Injection", "description": "...", "examples": [...], "remediation": "..." }
```

### `altais_score`

Calculate a CVSS base score from a vector string. Full v3.1 support; v4.0 vectors are accepted with a stub response.

- **Inputs:** `vector` — CVSS vector string, e.g. `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`.

```jsonc
// Request: { "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" }
// Response: { "version": "3.1", "base_score": 9.8, "severity": "critical" }
```

### `altais_report`

Aggregate every finding produced by tools this session into a consolidated markdown or JSON report.

- **Inputs:** `format` _(optional)_ `markdown` | `json` (default `markdown`); `include_info` _(optional)_ boolean (default `false`); `group_by` _(optional)_ `module` | `severity` (default `module`).

```jsonc
// Request: { "format": "json", "group_by": "module" }
// Response (json): { "findings": [...], "summary": { "total": 12, "by_severity": {...}, "by_module": {...}, "risk_score": 64 }, "by_module": [...] }
```

### `altais_risk_summary`

Return a composite risk score (0–100) and severity breakdown for the current session.

- **Inputs:** none.

```jsonc
// Request: {}
// Response: { "risk_score": 64, "total": 12, "by_severity": { "high": 3, "medium": 9 }, "by_module": { "scan": 8, "secrets": 4 } }
```

---

## Module: `scan`

Static analysis for 15 vulnerability classes across TypeScript, JavaScript, Python, Go, and Rust.

### `altais_scan_code`

Run security pattern detection against inline source code.

- **Inputs:** `source` — code to scan; `language` _(optional)_ language hint; `filename` _(optional)_ used for reporting and language detection; `rules` _(optional)_ array restricting to specific pattern IDs / categories.

```jsonc
// Request:
{ "source": "db.query('SELECT * FROM users WHERE id = ' + req.params.id)", "language": "javascript" }
// Response:
{
  "language": "javascript",
  "summary": { "total": 1, "by_severity": { "high": 1 } },
  "findings": [{ "id": "scan:sql-injection:ab12cd34ef56", "module": "scan", "rule": "sql-injection",
    "severity": "high", "cwe": ["CWE-89"], "title": "Possible SQL injection", "remediation": "Use parameterized queries.", "status": "open" }]
}
```

### `altais_scan_file`

Read a file from disk (canonicalized, inside the configured `scan_root`) and run the scan patterns against it.

- **Inputs:** `path` — file path resolved against `scan_root`; `rules` _(optional)_.

```jsonc
// Request: { "path": "src/handlers/user.ts" }
// Response: { "file": "src/handlers/user.ts", "language": "typescript", "summary": {...}, "findings": [...] }
```

### `altais_scan_diff`

Parse a unified diff and scan the touched hunks; only findings overlapping an added line are reported.

- **Inputs:** `diff` — unified diff text (e.g. `git diff` output); `rules` _(optional)_.

```jsonc
// Request: { "diff": "--- a/app.py\n+++ b/app.py\n@@ -1 +1,2 @@\n+os.system(user_input)\n" }
// Response: { "files": [{ "path": "app.py", "language": "python", "findings": 1 }], "summary": {...}, "findings": [...] }
```

---

## Module: `threat_model`

STRIDE, DREAD, attack trees, and trust-boundary analysis.

### `altais_stride`

Emit a STRIDE breakdown per component from a structured architecture.

- **Inputs:** `architecture` — `{ components: [{ name, type, description?, trust_zone?, handles_pii?, authenticates_clients? }], data_flows?: [{ from, to, data, protocol?, auth?, encrypted? }], trust_boundaries?: [{ name, description? }] }`.

```jsonc
// Request: { "architecture": { "components": [{ "name": "API", "type": "web_service" }] } }
// Response: { "components": [{ "name": "API", "stride": { "spoofing": [...], "tampering": [...], /* ... */ } }] }
```

### `altais_dread`

Compute a DREAD score from five 1–10 ratings.

- **Inputs:** `threat`; `damage`, `reproducibility`, `exploitability`, `affected_users`, `discoverability` — each 1–10; `justification` _(optional)_.

```jsonc
// Request: { "threat": "Token theft via XSS", "damage": 8, "reproducibility": 6, "exploitability": 7, "affected_users": 9, "discoverability": 5 }
// Response: { "threat": "Token theft via XSS", "total": 35, "average": 7.0, "rating": "high" }
```

### `altais_attack_tree`

Match an attacker goal to a built-in attack-tree template.

- **Inputs:** `goal` — attacker's goal in plain text; `asset` _(optional)_; `context` _(optional)_.

```jsonc
// Request: { "goal": "account takeover", "asset": "customer accounts" }
// Response: { "goal": "...", "tree": { "node": "...", "children": [{ "node": "...", "difficulty": "...", "cwe": [...], "mitigations": [...] }] } }
```

### `altais_trust_boundaries`

Identify data flows that cross trust zones and emit findings for risky crossings.

- **Inputs:** `architecture` — same shape as `altais_stride`.

```jsonc
// Request: { "architecture": { "components": [...], "data_flows": [{ "from": "Browser", "to": "API", "data": "auth token", "encrypted": false }] } }
// Response: { "crossings": [...], "findings": [{ "rule": "cleartext-boundary-crossing", "severity": "high", /* ... */ }] }
```

---

## Module: `owasp`

Coverage reports against OWASP Web/API/Mobile/Serverless Top 10 and ASVS. Each tool evaluates findings from the session `FindingStore` (or a supplied list).

Shared inputs for the four Top-10 tools: `findings` _(optional)_ array of `{ module, rule, severity, cwe?, title? }`; `use_session_findings` _(optional)_ boolean (default `true`).

### `altais_check_owasp_web`

Map findings to the OWASP Top 10:2025 categories (A01–A10).

```jsonc
// Request: { "use_session_findings": true }
// Response: { "list": "Web Top 10:2025", "categories": [{ "id": "A03", "title": "Software Supply Chain Failures", "status": "covered", "matched": [...] }], "summary": {...} }
```

### `altais_check_owasp_api`

Map findings to the OWASP API Security Top 10 (2023).

```jsonc
// Request: {}
// Response: { "list": "API Top 10:2023", "categories": [{ "id": "API1", "title": "Broken Object Level Authorization", "status": "not_covered" }] }
```

### `altais_check_owasp_mobile`

Map findings to the OWASP Mobile Top 10 (2024).

```jsonc
// Request: {}
// Response: { "list": "Mobile Top 10:2024", "categories": [...] }
```

### `altais_check_owasp_serverless`

Map findings to the OWASP Serverless Top 10.

```jsonc
// Request: {}
// Response: { "list": "Serverless Top 10", "categories": [...] }
```

### `altais_check_asvs`

Return OWASP ASVS controls at a given verification level, optionally filtered to one section.

- **Inputs:** `level` _(optional)_ `1` | `2` | `3` (default `1`); `section` _(optional)_ `V1`..`V14`; plus the shared `findings` / `use_session_findings`.

```jsonc
// Request: { "level": 2, "section": "V3" }
// Response: { "version": "4.0.3", "level": 2, "controls": [{ "id": "V3.1.1", "requirement": "...", "related_findings": [...] }] }
```

---

## Module: `secrets`

Hardcoded-credential detection by known pattern and Shannon entropy; git-history aware.

### `altais_scan_secrets`

Match input against the bundled secret-pattern database (AWS, GitHub, Slack, Stripe, GCP, JWT, PEM keys, DB DSNs, and more).

- **Inputs:** `source` — text to scan; `filename` _(optional)_; `rules` _(optional)_ restrict to specific pattern IDs.

```jsonc
// Request: { "source": "AWS_KEY = 'AKIA...EXAMPLE'" }
// Response: { "summary": { "total": 1, "by_severity": { "high": 1 } },
//   "findings": [{ "rule": "aws-access-key-id", "severity": "high", "cwe": ["CWE-798"], "evidence": "AKIA…MPLE (len 20)", /* ... */ }] }
```

### `altais_scan_entropy`

Compute Shannon entropy on candidate tokens and flag those above the configured threshold.

- **Inputs:** `source`; `filename` _(optional)_; `hex_threshold` _(optional)_; `base64_threshold` _(optional)_; `min_token_length` _(optional)_.

```jsonc
// Request: { "source": "secret = 'f8a3c91d2b4e7a6c5d0e9f1a8b3c2d4e'", "hex_threshold": 3.5 }
// Response: { "thresholds": { "hex": 3.5, "base64": 5.0, "minTokenLength": 20 }, "summary": {...}, "findings": [...] }
```

### `altais_scan_git_secrets`

Walk `git log -p` / `git diff` output, attributing findings to the originating commit and file.

- **Inputs:** `source` — output from `git log -p` or `git diff`.

```jsonc
// Request: { "source": "commit a1b2c3...\n+++ b/.env\n+API_TOKEN=sk-live-...\n" }
// Response: { "summary": {...}, "findings": [{ "rule": "stripe-secret-key", "tags": ["commit:a1b2c3"], /* ... */ }] }
```

---

## Module: `headers`

HTTP security-header audit, CSP generation, and CORS validation.

### `altais_audit_headers`

Check a response header map against current best practice (CSP, HSTS, framing, referrer, cookies, CORS).

- **Inputs:** `headers` — key/value map of HTTP response headers; `context` _(optional)_ `html-app` | `api` | `static-asset` (default `html-app`); `source` _(optional)_ label.

```jsonc
// Request: { "headers": { "Content-Type": "text/html" }, "context": "html-app" }
// Response: { "summary": {...}, "findings": [{ "rule": "missing-hsts", "severity": "medium", /* ... */ }] }
```

### `altais_generate_csp`

Build a Content-Security-Policy header from a high-level description of what the app loads. Never emits `'unsafe-inline'` or `'unsafe-eval'`.

- **Inputs:** `mode` _(optional)_ `strict` | `compatible` (default `strict`); `requires_inline_scripts`, `requires_inline_styles`, `use_workers` _(optional booleans)_; `external_scripts`, `external_styles`, `external_images`, `external_fonts`, `external_connections`, `external_frames`, `allow_form_actions` _(optional source lists)_; `report_uri`, `report_to` _(optional)_.

```jsonc
// Request: { "mode": "strict", "external_scripts": ["https://cdn.example.com"] }
// Response: { "header": "default-src 'none'; script-src https://cdn.example.com; ...", "recommendations": [...] }
```

### `altais_check_cors`

Validate a CORS policy expressed as a header map or a structured config.

- **Inputs:** `headers` _(optional)_ header map; `config` _(optional)_ `{ allowed_origins?, reflect_origin?, allow_credentials?, allowed_methods?, allowed_headers?, expose_headers?, max_age_seconds?, vary_origin? }`; `source` _(optional)_. Provide `headers` or `config`.

```jsonc
// Request: { "config": { "allowed_origins": ["*"], "allow_credentials": true } }
// Response: { "summary": {...}, "findings": [{ "rule": "wildcard-origin-with-credentials", "severity": "high", /* ... */ }] }
```

---

## Module: `supply_chain`

Lockfile vuln audit, SBOM, license/typosquat/dependency-confusion checks, SLSA + signature inspection, VEX, and CI/CD + registry config audits.

Lockfile-based tools share these inputs: `content` — raw lockfile text; `kind` _(optional)_ `npm` | `cargo` | `poetry` | `go`; `filename` _(optional)_ used for kind detection. Provide `kind` or a recognized `filename`.

### `altais_audit_deps`

Match every `(name, version)` pair in a lockfile against the bundled OSV snapshot.

```jsonc
// Request: { "content": "{ \"lockfileVersion\": 3, ... }", "kind": "npm" }
// Response: { "findings": [{ "rule": "vulnerable-dependency", "severity": "critical", "title": "lodash 4.17.11 — CVE-2019-10744", /* ... */ }], "summary": {...} }
```

### `altais_generate_sbom`

Emit a CycloneDX 1.5 or SPDX 2.3 SBOM from a lockfile.

- **Inputs:** lockfile fields plus `format` _(optional)_ `cyclonedx` | `spdx` (default `cyclonedx`); `project_name` _(optional)_; `project_version` _(optional)_.

```jsonc
// Request: { "content": "...", "kind": "cargo", "format": "cyclonedx" }
// Response: { "bomFormat": "CycloneDX", "specVersion": "1.5", "components": [{ "name": "serde", "version": "1.0.0", "purl": "pkg:cargo/serde@1.0.0" }] }
```

### `altais_check_licenses`

Classify each dependency's license against allow / warn / deny lists.

- **Inputs:** lockfile fields plus `allow`, `warn`, `deny` _(optional arrays)_.

```jsonc
// Request: { "content": "...", "kind": "npm" }
// Response: { "findings": [{ "rule": "denied-license", "severity": "high", "title": "pkg-x uses GPL-3.0" }], "summary": {...} }
```

### `altais_detect_typosquat`

Flag dependency names within edit-distance 1–2 of a popular package in the same ecosystem.

```jsonc
// Request: { "content": "...", "kind": "npm" }
// Response: { "findings": [{ "rule": "typosquat-candidate", "title": "reqeusts resembles requests", /* ... */ }] }
```

### `altais_verify_slsa`

Structurally verify a SLSA provenance attestation (DSSE envelope or in-toto Statement).

- **Inputs:** `attestation` — DSSE envelope JSON or in-toto Statement JSON.

```jsonc
// Request: { "attestation": "{ \"payloadType\": \"application/vnd.in-toto+json\", ... }" }
// Response: { "predicate_type": "...", "checks": [{ "field": "builder.id", "present": true }], "findings": [...] }
```

### `altais_verify_signatures`

Classify and inspect a cosign bundle, cosign `.sig`, or ASCII-armored GPG signature.

- **Inputs:** `signature` — signature payload text.

```jsonc
// Request: { "signature": "-----BEGIN PGP SIGNATURE-----\n..." }
// Response: { "kind": "gpg", "metadata": {...}, "findings": [...] }
```

### `altais_check_dependency_confusion`

Flag packages matching an internal name pattern but resolved from a public registry.

- **Inputs:** lockfile fields plus `internal_names`, `internal_scopes`, `internal_prefixes`, `internal_registries` _(optional arrays)_.

```jsonc
// Request: { "content": "...", "kind": "npm", "internal_scopes": ["@acme"] }
// Response: { "findings": [{ "rule": "dependency-confusion-risk", "title": "@acme/utils resolved from npmjs.org" }] }
```

### `altais_generate_vex`

Emit an OpenVEX 0.2.0 or CycloneDX 1.5 VEX document from a list of statements.

- **Inputs:** `format` _(optional)_ `openvex` | `cyclonedx-vex` (default `openvex`); `author` _(optional)_; `author_role` _(optional)_; `statements` — array of `{ vulnerability, products: [{ identifier, subcomponent_identifiers? }], status, justification?, impact_statement?, action_statement? }`.

```jsonc
// Request: { "statements": [{ "vulnerability": "CVE-2021-44228", "products": [{ "identifier": "pkg:maven/acme/app@1.0" }], "status": "not_affected", "justification": "vulnerable_code_not_present" }] }
// Response: { "@context": "https://openvex.dev/ns/v0.2.0", "statements": [...] }
```

### `altais_check_build_integrity`

Pattern-based audit of CI/CD configuration for tamper vectors.

- **Inputs:** `content` — CI/CD config text; `filename` _(optional)_.

```jsonc
// Request: { "content": "jobs:\n  build:\n    steps:\n      - uses: actions/checkout@main\n", "filename": ".github/workflows/ci.yml" }
// Response: { "findings": [{ "rule": "unpinned-action", "severity": "medium", /* ... */ }] }
```

### `altais_audit_registry`

Check a package-registry config file (`.npmrc`, `pip.conf`, `cargo` config) for HTTP registries, plaintext tokens, and disabled TLS.

- **Inputs:** `content`; `kind` _(optional)_ `npmrc` | `pip` | `cargo` | `auto` (default `auto`); `filename` _(optional)_.

```jsonc
// Request: { "content": "registry=http://internal/\n//internal/:_authToken=plain", "kind": "npmrc" }
// Response: { "findings": [{ "rule": "http-registry", "severity": "high" }, { "rule": "plaintext-auth-token" }] }
```

---

## Module: `auth`

OAuth/OIDC, JWT, session, CSRF, password hashing, RBAC, passkeys, and NHI audits. Most tools accept `source` _(optional)_ code and/or a structured `config`, plus `filename` _(optional)_.

### `altais_audit_oauth`

Audit an OAuth 2.1 / OIDC implementation.

- **Inputs:** `source` _(optional)_; `filename` _(optional)_; `config` _(optional)_ `{ flow?, pkce?, redirect_uris?, uses_state?, uses_nonce_for_oidc?, token_endpoint_auth?, token_storage?, refresh_token_rotation?, scope? }`.

```jsonc
// Request: { "config": { "flow": "authorization_code", "pkce": { "used": false }, "token_storage": "localStorage" } }
// Response: { "summary": {...}, "findings": [{ "rule": "missing-pkce", "severity": "high" }, { "rule": "token-in-localstorage" }] }
```

### `altais_audit_jwt`

Scan code for JWT misuse, decode an actual token, and/or audit the verifier config.

- **Inputs:** `source` _(optional)_; `filename` _(optional)_; `token` _(optional)_ JWT to decode; `config` _(optional)_ `{ accepted_algorithms?, required_iss?, required_aud?, clock_skew_seconds?, verify_exp?, verify_nbf?, jwks_uri? }`.

```jsonc
// Request: { "config": { "accepted_algorithms": ["none", "HS256"], "verify_exp": false } }
// Response: { "summary": {...}, "findings": [{ "rule": "alg-none-accepted", "severity": "critical" }, { "rule": "exp-not-verified" }] }
```

### `altais_audit_session`

Check session flags, regeneration, invalidation, timeouts, and ID entropy.

- **Inputs:** `source` _(optional)_; `filename` _(optional)_; `config` _(optional)_ `{ cookie?, regenerate_on_login?, invalidate_on_logout?, absolute_timeout_seconds?, idle_timeout_seconds?, id_entropy_bits? }`.

```jsonc
// Request: { "config": { "cookie": { "secure": false, "httpOnly": false }, "regenerate_on_login": false } }
// Response: { "summary": {...}, "findings": [{ "rule": "cookie-missing-secure" }, { "rule": "no-session-regeneration" }] }
```

### `altais_audit_csrf`

Verify state-changing endpoints are CSRF-defended.

- **Inputs:** `source` _(optional)_; `filename` _(optional)_; `config` _(optional)_ `{ auth_via?, samesite?, csrf_token?, checks_origin_header?, state_changing_methods? }`.

```jsonc
// Request: { "config": { "auth_via": "cookie", "samesite": false, "csrf_token": "none" } }
// Response: { "summary": {...}, "findings": [{ "rule": "no-csrf-protection", "severity": "high" }] }
```

### `altais_audit_password_hashing`

Scan source for password-hashing patterns; flags fast hashes in a password context.

- **Inputs:** `source` — code to scan; `filename` _(optional)_.

```jsonc
// Request: { "source": "hash = md5(password)" }
// Response: { "summary": {...}, "findings": [{ "rule": "weak-password-hash", "severity": "high", "cwe": ["CWE-916"] }] }
```

### `altais_audit_rbac`

Inspect a structured RBAC/ABAC policy for privilege-escalation paths.

- **Inputs:** `filename` _(optional)_; `policy` — `{ model?, default?, roles: [{ name, description?, inherits?, permissions }], assignments? }`.

```jsonc
// Request: { "policy": { "default": "allow", "roles": [{ "name": "admin", "permissions": ["*:*"] }] } }
// Response: { "summary": {...}, "findings": [{ "rule": "default-allow" }, { "rule": "superuser-role" }] }
```

### `altais_audit_passkey_impl`

Audit a FIDO2 / passkey (WebAuthn) implementation.

- **Inputs:** `source` _(optional)_; `filename` _(optional)_; `config` _(optional)_ `{ rp_id?, user_verification?, resident_key?, attestation?, origins?, challenge_entropy_bits?, stores_credential_id?, stores_aaguid?, stores_sign_count? }`.

```jsonc
// Request: { "config": { "user_verification": "discouraged", "stores_sign_count": false } }
// Response: { "summary": {...}, "findings": [{ "rule": "user-verification-discouraged" }, { "rule": "no-sign-count-tracking" }] }
```

### `altais_audit_nhi`

Audit non-human identities against the OWASP NHI Top 10.

- **Inputs:** `filename` _(optional)_; `identities` — array of `{ name, kind, environment?, owner?, credential_type?, credential_age_days?, rotation_period_days?, scopes?, scoped_to_resources?, expires_at?, mfa_enabled?, stored_in_repo?, stored_in_env_vars? }`.

```jsonc
// Request: { "identities": [{ "name": "ci-deployer", "kind": "ci_runner", "credential_type": "static_key", "stored_in_repo": true }] }
// Response: { "summary": {...}, "findings": [{ "rule": "credentials-in-repo", "severity": "critical" }, { "rule": "static-key" }] }
```

### `altais_check_secret_lifecycle`

Audit a structured list of secrets for rotation, expiry, and revocation gaps.

- **Inputs:** `filename` _(optional)_; `secrets` — array of `{ name, kind, owner?, created_at?, last_rotated_at?, expires_at?, rotation_period_days?, revocation_procedure_documented?, audit_logged?, stored_in? }`.

```jsonc
// Request: { "secrets": [{ "name": "api-signing-key", "kind": "signing_key", "last_rotated_at": "2021-01-01" }] }
// Response: { "summary": {...}, "findings": [{ "rule": "rotation-overdue" }, { "rule": "no-expiry" }] }
```

### `altais_check_nhi_isolation`

Verify non-human identities are scoped to a single environment / namespace / project.

- **Inputs:** `filename` _(optional)_; `identities` — array of `{ name, environment?, namespace?, project?, scopes?, cross_environment_access? }`.

```jsonc
// Request: { "identities": [{ "name": "staging-bot", "environment": "staging", "cross_environment_access": ["prod"] }] }
// Response: { "summary": {...}, "findings": [{ "rule": "cross-environment-access", "severity": "high" }] }
```

---

## Module: `crypto`

Algorithm/TLS/randomness/key-management audits, post-quantum readiness, CT monitoring, certificate pinning, ACME, and crypto agility. Most tools accept `source` _(optional)_, `filename` _(optional)_, and a structured `config`.

### `altais_audit_crypto`

Audit cryptographic algorithm usage — weak ciphers, deprecated hashes, ECB mode, static IVs.

- **Inputs:** `source` _(optional)_; `filename` _(optional)_; `config` _(optional)_ `{ algorithms?: [{ name, purpose?, key_size_bits? }] }`.

```jsonc
// Request: { "source": "crypto.createHash('md5')" }
// Response: { "summary": {...}, "findings": [{ "rule": "weak-hash", "severity": "high", "cwe": ["CWE-327"] }] }
```

### `altais_audit_tls`

Review a TLS configuration or client/server source.

- **Inputs:** `source` _(optional)_; `filename` _(optional)_; `config` _(optional)_ `{ min_version?, enabled_versions?, cipher_suites?, verify_certificates?, hsts?, compression? }`.

```jsonc
// Request: { "config": { "min_version": "TLSv1.0", "verify_certificates": false } }
// Response: { "summary": {...}, "findings": [{ "rule": "deprecated-tls-version" }, { "rule": "certificate-verification-disabled" }] }
```

### `altais_audit_randomness`

Scan source for non-cryptographic PRNGs; escalates to high severity near a security keyword.

- **Inputs:** `source` — code to scan; `filename` _(optional)_.

```jsonc
// Request: { "source": "const token = Math.random().toString(36)" }
// Response: { "summary": {...}, "findings": [{ "rule": "insecure-prng", "severity": "high", "cwe": ["CWE-338"] }] }
```

### `altais_audit_key_mgmt`

Scan source for hardcoded keys and audit a structured key inventory.

- **Inputs:** `source` _(optional)_; `filename` _(optional)_; `as_of` _(optional)_ ISO date; `keys` _(optional)_ array of `{ name, type?, algorithm?, key_size_bits?, storage?, rotation_period_days?, last_rotated_at?, created_at? }`.

```jsonc
// Request: { "keys": [{ "name": "root-ca", "type": "root_ca", "storage": "config_file" }] }
// Response: { "summary": {...}, "findings": [{ "rule": "high-value-key-not-in-hsm", "severity": "high" }] }
```

### `altais_assess_pq_readiness`

Flag quantum-vulnerable primitives and assess harvest-now-decrypt-later exposure.

- **Inputs:** `source` _(optional)_; `filename` _(optional)_; `config` _(optional)_ `{ algorithms?, data_retention_years?, uses_hybrid? }`.

```jsonc
// Request: { "config": { "algorithms": ["RSA-2048", "ECDH"], "data_retention_years": 25 } }
// Response: { "summary": {...}, "findings": [{ "rule": "quantum-vulnerable-primitive" }, { "rule": "harvest-now-decrypt-later" }] }
```

### `altais_audit_ct_logs`

Check Certificate Transparency log monitoring coverage.

- **Inputs:** `source` _(optional)_; `filename` _(optional)_; `config` _(optional)_ `{ monitoring_enabled?, owned_domains?, monitored_domains?, alerting_enabled?, requires_sct? }`.

```jsonc
// Request: { "config": { "monitoring_enabled": false, "owned_domains": ["example.com"] } }
// Response: { "summary": {...}, "findings": [{ "rule": "ct-monitoring-disabled" }] }
```

### `altais_audit_cert_pinning`

Review certificate pinning — flags the dead HPKP header, leaf pinning, missing backup pins.

- **Inputs:** `source` _(optional)_; `filename` _(optional)_; `config` _(optional)_ `{ pinning_enabled?, pin_type?, pin_count?, has_backup_pin?, enforced?, platform? }`.

```jsonc
// Request: { "config": { "pinning_enabled": true, "pin_type": "leaf_certificate", "has_backup_pin": false } }
// Response: { "summary": {...}, "findings": [{ "rule": "leaf-certificate-pinning" }, { "rule": "no-backup-pin" }] }
```

### `altais_audit_acme`

Review an ACME / Let's Encrypt configuration.

- **Inputs:** `filename` _(optional)_; `config` — `{ provider?, challenge_type?, auto_renewal?, renewal_threshold_days?, wildcard?, caa_configured?, key_type?, key_size_bits?, staging_endpoint?, account_key_storage? }`.

```jsonc
// Request: { "config": { "challenge_type": "http-01", "wildcard": true, "auto_renewal": false } }
// Response: { "summary": {...}, "findings": [{ "rule": "http01-for-wildcard" }, { "rule": "no-renewal-automation" }] }
```

### `altais_assess_crypto_agility`

Assess whether the system can swap a cryptographic primitive without code changes.

- **Inputs:** `source` _(optional)_; `filename` _(optional)_; `config` _(optional)_ `{ algorithm_from_config?, versioned_ciphertext?, abstraction_layer?, inventory_exists?, rotation_without_redeploy? }`.

```jsonc
// Request: { "config": { "versioned_ciphertext": false, "abstraction_layer": false } }
// Response: { "summary": {...}, "findings": [{ "rule": "unversioned-ciphertext" }, { "rule": "no-crypto-abstraction" }] }
```

---

## Module: `container`

Dockerfile, Docker Compose, and base-image hygiene audits.

### `altais_audit_dockerfile`

Analyze a Dockerfile for security best-practice violations.

- **Inputs:** `content` — Dockerfile text; `filename` _(optional)_.

```jsonc
// Request: { "content": "FROM ubuntu:latest\nRUN curl http://x | sh\n" }
// Response: { "summary": {...}, "findings": [{ "rule": "mutable-base-tag" }, { "rule": "remote-script-piped-to-shell" }] }
```

### `altais_audit_compose`

Review a Docker Compose file for security misconfigurations.

- **Inputs:** `content` — Compose file text; `filename` _(optional)_.

```jsonc
// Request: { "content": "services:\n  app:\n    privileged: true\n" }
// Response: { "summary": {...}, "findings": [{ "rule": "privileged-mode", "severity": "high" }] }
```

### `altais_check_base_image`

Assess a base-image reference for pinning, end-of-life, and bloat.

- **Inputs:** `image` — image reference, e.g. `node:20-alpine`; `filename` _(optional)_.

```jsonc
// Request: { "image": "node:latest" }
// Response: { "summary": {...}, "findings": [{ "rule": "missing-version-pin" }, { "rule": "missing-digest-pin" }] }
```

---

## Module: `code`

CERT secure-coding review, Rust `unsafe` audit, error-handling, input-validation, and memory-safety checks. Tools accept `source` and `filename` _(optional)_; several also take `language`.

### `altais_review_secure_coding`

Review source against CERT secure-coding guidance.

- **Inputs:** `source`; `language` — `c` | `cpp` | `java` | `python` | `javascript` | `typescript` | `go`; `filename` _(optional)_.

```jsonc
// Request: { "source": "printf(user_input);", "language": "c" }
// Response: { "summary": {...}, "findings": [{ "rule": "format-string", "severity": "high", "cwe": ["CWE-134"] }] }
```

### `altais_audit_unsafe`

Audit Rust `unsafe` blocks and functions for soundness.

- **Inputs:** `source`; `filename` _(optional)_.

```jsonc
// Request: { "source": "unsafe { std::mem::transmute(x) }" }
// Response: { "summary": {...}, "findings": [{ "rule": "transmute", "severity": "high" }, { "rule": "missing-safety-comment" }] }
```

### `altais_check_error_handling`

Detect error handling that leaks sensitive information or hides failures.

- **Inputs:** `source`; `language`; `filename` _(optional)_.

```jsonc
// Request: { "source": "} catch (e) { res.send(e.stack); }", "language": "javascript" }
// Response: { "summary": {...}, "findings": [{ "rule": "stack-trace-in-response", "cwe": ["CWE-209"] }] }
```

### `altais_check_input_validation`

Verify request and external input is validated before use.

- **Inputs:** `source`; `language`; `filename` _(optional)_.

```jsonc
// Request: { "source": "const id = parseInt(req.body.id)", "language": "javascript" }
// Response: { "summary": {...}, "findings": [{ "rule": "parseint-without-radix" }, { "rule": "unvalidated-request-input" }] }
```

### `altais_check_memory_safety`

Detect memory-safety defects in C / C++ / Rust.

- **Inputs:** `source`; `language` — `c` | `cpp` | `rust`; `filename` _(optional)_.

```jsonc
// Request: { "source": "strcpy(dst, src);", "language": "c" }
// Response: { "summary": {...}, "findings": [{ "rule": "unbounded-string-function", "cwe": ["CWE-120"] }] }
```

---

## Module: `data`

PII detection, data classification, privacy-by-design audit, and retention review.

### `altais_detect_pii`

Scan source or sample data for PII; raw values are masked in findings.

- **Inputs:** `source` — code or sample data; `filename` _(optional)_.

```jsonc
// Request: { "source": "user.ssn = '123-45-6789'" }
// Response: { "summary": {...}, "findings": [{ "rule": "us-ssn", "severity": "high", "evidence": "***-**-6789" }] }
```

### `altais_classify_data`

Classify data fields into restricted / confidential / internal / public tiers.

- **Inputs:** `fields` — array of `{ name, type?, description? }`.

```jsonc
// Request: { "fields": [{ "name": "password" }, { "name": "email" }, { "name": "created_at" }] }
// Response: { "classifications": [{ "name": "password", "tier": "restricted" }, { "name": "email", "tier": "confidential" }], "summary": {...}, "findings": [...] }
```

### `altais_audit_privacy`

Check an implementation against GDPR-aligned privacy-by-design principles.

- **Inputs:** `config` — `{ data_minimization?, purpose_limitation?, consent_mechanism?, encryption_at_rest?, encryption_in_transit?, default_private?, dpo_designated?, dpia_conducted?, user_data_export?, user_data_deletion?, breach_notification_process?, third_party_data_sharing? }`.

```jsonc
// Request: { "config": { "consent_mechanism": false, "user_data_deletion": false } }
// Response: { "summary": {...}, "findings": [{ "rule": "no-consent-mechanism" }, { "rule": "no-data-deletion" }] }
```

### `altais_check_retention`

Analyze data-retention policies against the GDPR storage-limitation principle.

- **Inputs:** `policies` — array of `{ data_category, retention_period_days?, deletion_method?, automated_deletion?, legal_basis?, contains_pii? }`; `source` _(optional)_; `filename` _(optional)_.

```jsonc
// Request: { "policies": [{ "data_category": "logs", "retention_period_days": -1, "contains_pii": true }] }
// Response: { "summary": {...}, "findings": [{ "rule": "indefinite-retention" }, { "rule": "missing-legal-basis" }] }
```

---

## Module: `iac`

Terraform, Kubernetes, Helm, and policy-as-code audits.

### `altais_audit_terraform`

Scan Terraform HCL for security misconfigurations.

- **Inputs:** `content` — HCL text; `filename` _(optional)_.

```jsonc
// Request: { "content": "resource \"aws_security_group_rule\" \"x\" { cidr_blocks = [\"0.0.0.0/0\"] from_port = 22 }" }
// Response: { "summary": {...}, "findings": [{ "rule": "world-open-ssh", "severity": "high" }] }
```

### `altais_audit_k8s_manifest`

Check a Kubernetes manifest against the Pod Security Standards.

- **Inputs:** `content` — manifest YAML; `filename` _(optional)_.

```jsonc
// Request: { "content": "spec:\n  containers:\n  - securityContext:\n      privileged: true\n" }
// Response: { "summary": {...}, "findings": [{ "rule": "privileged-container", "severity": "high" }] }
```

### `altais_audit_helm_chart`

Review a Helm chart's `values.yaml` (optionally with templates) for insecure defaults.

- **Inputs:** `content` — chart text; `filename` _(optional)_.

```jsonc
// Request: { "content": "image:\n  tag: latest\nrbac:\n  create: false\n" }
// Response: { "summary": {...}, "findings": [{ "rule": "latest-image-tag" }, { "rule": "rbac-disabled" }] }
```

### `altais_check_policy_as_code`

Validate an OPA/Rego or Kyverno policy.

- **Inputs:** `content` — policy text; `policy_type` — `rego` | `kyverno`; `filename` _(optional)_.

```jsonc
// Request: { "content": "default allow = true", "policy_type": "rego" }
// Response: { "summary": {...}, "findings": [{ "rule": "default-allow", "severity": "high" }] }
```

---

## Module: `api`

OpenAPI spec, rate-limiting, and API-gateway hardening audits.

### `altais_audit_openapi_spec`

Validate a JSON OpenAPI 3.x specification for security gaps.

- **Inputs:** `spec` — JSON OpenAPI 3.x document (YAML not supported); `filename` _(optional)_.

```jsonc
// Request: { "spec": "{ \"openapi\": \"3.0.0\", \"paths\": { ... } }" }
// Response: { "summary": {...}, "findings": [{ "rule": "no-security-scheme" }, { "rule": "http-server-url" }] }
```

### `altais_audit_rate_limiting`

Check a rate-limiting configuration for coverage gaps.

- **Inputs:** `config` — `{ enabled?, strategy?, scope?, limit?, window_seconds?, applies_to_auth_endpoints?, burst?, returns_429?, has_retry_after_header? }`; `source` _(optional)_; `filename` _(optional)_.

```jsonc
// Request: { "config": { "enabled": true, "scope": "global", "applies_to_auth_endpoints": false } }
// Response: { "summary": {...}, "findings": [{ "rule": "auth-endpoints-unthrottled", "severity": "high" }] }
```

### `altais_audit_api_gateway`

Review an API gateway's security configuration.

- **Inputs:** `config` — `{ authentication_enabled?, authorization_enabled?, tls_enabled?, min_tls_version?, waf_enabled?, request_validation?, request_size_limit_bytes?, timeout_seconds?, rate_limiting_enabled?, logging_enabled?, cors?, ip_allowlist_enabled?, mtls_enabled?, api_keys_rotated?, backend_tls? }`; `filename` _(optional)_.

```jsonc
// Request: { "config": { "authentication_enabled": false, "waf_enabled": false, "backend_tls": false } }
// Response: { "summary": {...}, "findings": [{ "rule": "authentication-disabled" }, { "rule": "no-waf" }, { "rule": "cleartext-backend" }] }
```

---

## Module: `compliance`

Map findings to 16 compliance frameworks, gap analysis, and evidence packs. All three tools accept `framework` — one of the bundled framework ids (`owasp-asvs`, `owasp-samm`, `owasp-dsomm`, `nist-800-53`, `nist-ssdf`, `nist-ai-rmf`, `iso-27001`, `soc2`, `gdpr`, `pci-dss`, `nis2`, `dora`, `cra`, `cisa-sbd`, `eo-14028`, `fda-524b`) — and an optional `findings` array (`{ rule, cwe?, title?, severity? }`); when `findings` is omitted the session `FindingStore` is used.

### `altais_map_findings`

Map security findings to a framework's controls by CWE intersection and keyword match.

```jsonc
// Request: { "framework": "nist-800-53" }
// Response: { "framework_name": "NIST SP 800-53", "mappings": [{ "control": { "id": "AC-3", "title": "..." }, "status": "addressed", "matched_findings": [...] }], "summary": {...} }
```

### `altais_gap_analysis`

Classify every control as `addressed` or `gap` and report coverage statistics.

```jsonc
// Request: { "framework": "pci-dss" }
// Response: { "framework_name": "PCI-DSS", "coverage": { "total_controls": 8, "addressed": 3, "gap": 5, "coverage_pct": 37.5 }, "gap_controls": [...] }
```

### `altais_generate_evidence`

Generate a structured audit evidence pack per control.

- **Inputs:** `framework`; `control_ids` _(optional)_ array; `findings` _(optional)_.

```jsonc
// Request: { "framework": "soc2", "control_ids": ["CC6.1"] }
// Response: { "framework_name": "SOC 2", "summary": { "controls_in_pack": 1, "addressed": 1, "gap": 0 }, "evidence": [{ "control_id": "CC6.1", "status": "addressed", "evidence_statement": "...", "evidence_findings": [...] }] }
```

---

## Module: `infra`

Network/firewall, DNS, zero-trust, and CIS-benchmark hardening audits.

### `altais_audit_network`

Review a network configuration for segmentation and firewall weaknesses.

- **Inputs:** `config` — `{ firewall_rules?: [{ direction, source, destination?, port?, protocol?, action }], zones?, segments?, egress_filtering? }`; `filename` _(optional)_.

```jsonc
// Request: { "config": { "firewall_rules": [{ "direction": "ingress", "source": "0.0.0.0/0", "port": 22, "action": "allow" }] } }
// Response: { "summary": {...}, "findings": [{ "rule": "world-open-admin-port", "severity": "high" }] }
```

### `altais_audit_dns`

Check a DNS zone configuration for security weaknesses.

- **Inputs:** `config` — `{ dnssec_enabled?, zone_transfer_allowed?, allowed_to?, caa_records?, wildcard_records?, records? }`; `filename` _(optional)_.

```jsonc
// Request: { "config": { "dnssec_enabled": false, "zone_transfer_allowed": true } }
// Response: { "summary": {...}, "findings": [{ "rule": "dnssec-disabled" }, { "rule": "open-zone-transfer" }] }
```

### `altais_check_zero_trust`

Assess an architecture against the NIST SP 800-207 zero-trust tenets.

- **Inputs:** `config` — `{ verify_explicitly?, least_privilege_access?, assume_breach?, mfa_enforced?, microsegmentation?, device_trust_verification?, continuous_verification?, no_implicit_network_trust?, encrypted_internal_traffic?, per_request_authorization?, centralized_policy_engine? }`; `filename` _(optional)_.

```jsonc
// Request: { "config": { "mfa_enforced": false, "microsegmentation": false } }
// Response: { "summary": {...}, "findings": [{ "rule": "mfa-not-enforced" }, { "rule": "no-microsegmentation" }], "maturity": {...} }
```

### `altais_check_hardening`

Check a system's settings against CIS-benchmark-style controls.

- **Inputs:** `platform` — `linux` | `windows` | `docker` | `kubernetes` | `aws` | `gcp` | `azure`; `settings` — map of setting keys to observed values (boolean / number / string).

```jsonc
// Request: { "platform": "linux", "settings": { "ssh_root_login": "yes", "firewall_enabled": false } }
// Response: { "summary": {...}, "findings": [{ "rule": "ssh-root-login-enabled" }, { "rule": "host-firewall-disabled" }] }
```

---

## Module: `protocol`

Deep TLS/mTLS, webhook, email, WebSocket, GraphQL, gRPC, and SSE audits. Several tools accept `source` _(optional)_ and/or a structured `config`; all accept `filename` _(optional)_.

### `altais_audit_tls_config`

Audit a structured TLS / mTLS configuration against RFC 9325 and RFC 8996.

- **Inputs:** `config` — `{ min_version?, enabled_versions?, cipher_suites?, mtls_enabled?, client_cert_required?, ocsp_stapling?, session_resumption?, forward_secrecy?, cert_signature_algorithm?, hsts?, certificate_transparency? }`; `filename` _(optional)_.

```jsonc
// Request: { "config": { "min_version": "TLSv1.0", "forward_secrecy": false } }
// Response: { "summary": {...}, "findings": [{ "rule": "deprecated-protocol" }, { "rule": "no-forward-secrecy" }] }
```

### `altais_check_webhook`

Verify a webhook receiver's HMAC signature implementation.

- **Inputs:** `source` _(optional)_; `config` _(optional)_ `{ signature_verified?, hash_algorithm?, constant_time_comparison?, timestamp_validation?, replay_protection?, secret_source? }`; `filename` _(optional)_. Provide `source` or `config`.

```jsonc
// Request: { "config": { "signature_verified": true, "constant_time_comparison": false } }
// Response: { "summary": {...}, "findings": [{ "rule": "non-constant-time-comparison", "severity": "medium" }] }
```

### `altais_audit_email_security`

Audit a domain's SPF / DKIM / DMARC posture.

- **Inputs:** `config` — `{ spf_record?, dkim_enabled?, dkim_selectors?, dmarc_record?, dmarc_policy?, mta_sts?, dnssec? }`; `filename` _(optional)_.

```jsonc
// Request: { "config": { "spf_record": "v=spf1 +all", "dmarc_policy": "none" } }
// Response: { "summary": {...}, "findings": [{ "rule": "spf-permissive-all" }, { "rule": "dmarc-policy-none" }] }
```

### `altais_audit_websocket`

Review a WebSocket server or client.

- **Inputs:** `source` _(optional)_; `config` _(optional)_ `{ tls?, origin_validation?, authentication?, message_size_limit?, rate_limiting?, csrf_protection? }`; `filename` _(optional)_. Provide `source` or `config`.

```jsonc
// Request: { "config": { "tls": false, "origin_validation": false } }
// Response: { "summary": {...}, "findings": [{ "rule": "plaintext-websocket" }, { "rule": "no-origin-validation" }] }
```

### `altais_audit_graphql`

Audit a GraphQL API.

- **Inputs:** `source` _(optional)_; `config` _(optional)_ `{ introspection_enabled?, query_depth_limit?, query_complexity_limit?, batching_enabled?, field_suggestions?, rate_limiting?, production? }`; `filename` _(optional)_. Provide `source` or `config`.

```jsonc
// Request: { "config": { "introspection_enabled": true, "production": true, "query_depth_limit": false } }
// Response: { "summary": {...}, "findings": [{ "rule": "introspection-in-production" }, { "rule": "no-query-depth-limit" }] }
```

### `altais_audit_grpc`

Audit a gRPC service or client.

- **Inputs:** `source` _(optional)_; `config` _(optional)_ `{ tls_enabled?, insecure_channel?, auth_interceptor?, deadline_propagation?, reflection_enabled?, max_message_size?, production? }`; `filename` _(optional)_. Provide `source` or `config`.

```jsonc
// Request: { "config": { "insecure_channel": true, "auth_interceptor": false } }
// Response: { "summary": {...}, "findings": [{ "rule": "insecure-channel" }, { "rule": "no-auth-interceptor" }] }
```

### `altais_audit_sse`

Audit a Server-Sent Events endpoint.

- **Inputs:** `source` _(optional)_; `config` _(optional)_ `{ origin_validation?, authentication?, tls?, reconnection_backoff?, cors_restricted?, per_connection_limit? }`; `filename` _(optional)_. Provide `source` or `config`.

```jsonc
// Request: { "config": { "tls": false, "authentication": false } }
// Response: { "summary": {...}, "findings": [{ "rule": "plaintext-sse" }, { "rule": "no-authentication" }] }
```

---

## Module: `vuln_db`

Offline CVE/CWE lookup, a CVSS v3.1+v4.0 calculator, and MITRE ATT&CK mapping. These are lookup/calculation tools — they return structured JSON and do not push findings into the session store.

### `altais_lookup_cve`

Look up a CVE by identifier in the bundled offline snapshot of high-impact CVEs.

- **Inputs:** `cve_id` — a CVE identifier, e.g. `CVE-2021-44228`.

```jsonc
// Request: { "cve_id": "CVE-2021-44228" }
// Response: { "id": "CVE-2021-44228", "description": "Log4Shell ...", "cvss_v31": { "vector": "...", "score": 10.0 }, "severity": "critical", "cwe": ["CWE-502"], "remediation": "...", "references": [...] }
```

### `altais_lookup_cwe`

Full CWE taxonomy lookup with related weaknesses.

- **Inputs:** `cwe_id` — a CWE identifier in any form (`79`, `CWE-79`).

```jsonc
// Request: { "cwe_id": "CWE-79" }
// Response: { "entry": { "id": "CWE-79", "name": "Cross-site Scripting", "description": "...", "examples": [...], "remediation": "..." }, "related": [{ "id": "CWE-116", "relation": "peer" }] }
```

### `altais_calculate_cvss`

Parse and score a CVSS v3.1 or v4.0 vector.

- **Inputs:** `vector` — a CVSS vector string starting with `CVSS:3.1/` or `CVSS:4.0/`.

```jsonc
// Request: { "vector": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N" }
// Response: { "version": "4.0", "score": 9.3, "severity": "critical", "macro_vector": "...", "metric_groups": {...} }
```

### `altais_map_attack`

Map a CWE and/or a free-text description to MITRE ATT&CK techniques.

- **Inputs:** `cwe` _(optional)_; `description` _(optional)_; `limit` _(optional)_ 1–30 (default 10). Provide `cwe` or `description`.

```jsonc
// Request: { "cwe": "CWE-89", "limit": 3 }
// Response: { "techniques": [{ "id": "T1190", "name": "Exploit Public-Facing Application", "tactic": "initial-access", "confidence": 0.82, "reasons": [...] }] }
```

---

## Module: `incident`

Logging and canary audits, plus generators for IR playbooks, security.txt, advisories, SIEM guidance, and disclosure programs. Auditors push findings; generators return a self-contained artifact.

### `altais_audit_logging`

Assess audit-trail completeness and log-injection prevention.

- **Inputs:** `source` _(optional)_; `config` _(optional)_ `{ has_audit_log?, logs_authentication?, logs_authorization?, logs_admin_actions?, log_injection_protection?, centralized?, tamper_protection?, retention_days?, logs_sensitive_data?, pii_redaction?, includes_timestamp?, includes_actor? }`; `filename` _(optional)_. Provide `source` or `config`.

```jsonc
// Request: { "config": { "has_audit_log": false, "log_injection_protection": false } }
// Response: { "summary": {...}, "findings": [{ "rule": "no-audit-log", "cwe": ["CWE-778"] }, { "rule": "no-log-injection-protection", "cwe": ["CWE-117"] }] }
```

### `altais_generate_playbook`

Generate a scenario-specific incident-response playbook along the NIST SP 800-61 lifecycle.

- **Inputs:** `scenario` — `ransomware` | `data-breach` | `account-takeover` | `ddos` | `supply-chain-compromise` | `insider-threat` | `credential-leak` | `malware` | `phishing`; `context` _(optional)_.

```jsonc
// Request: { "scenario": "ransomware" }
// Response: { "scenario": "ransomware", "phases": { "preparation": [...], "detection_and_analysis": [...], "containment": [...], "eradication": [...], "recovery": [...], "post_incident": [...] }, "roles": [...] }
```

### `altais_generate_security_txt`

Generate an RFC 9116 `security.txt` file body.

- **Inputs:** `config` — `{ contact, encryption?, policy?, acknowledgments?, preferred_languages?, canonical?, hiring?, expires_days? }`.

```jsonc
// Request: { "config": { "contact": "mailto:security@example.com" } }
// Response: { "content": "Contact: mailto:security@example.com\nExpires: 2027-05-20T00:00:00Z\n", "placement": "/.well-known/security.txt" }
```

### `altais_draft_advisory`

Draft a security advisory in GitHub Security Advisory (GHSA) markdown format.

- **Inputs:** `config` — `{ title, severity, cve?, cwe?, affected_versions?, patched_version?, description?, impact?, cvss_vector?, credits? }`.

```jsonc
// Request: { "config": { "title": "SSRF in image proxy", "severity": "high", "affected_versions": "< 2.4.1" } }
// Response: { "markdown": "## SSRF in image proxy\n\n**Severity:** High\n..." }
```

### `altais_check_canary`

Assess deception-control (canary token / honeypot) coverage.

- **Inputs:** `config` — `{ canary_tokens_deployed?, honeypots_deployed?, coverage_areas?, alerting_enabled?, alert_routing?, monitored_assets? }`; `filename` _(optional)_.

```jsonc
// Request: { "config": { "canary_tokens_deployed": false, "alerting_enabled": false } }
// Response: { "summary": {...}, "findings": [{ "rule": "no-canary-tokens", "cwe": ["CWE-778"] }] }
```

### `altais_recommend_siem`

Generate platform-aware SIEM integration guidance.

- **Inputs:** `config` — `{ platform, log_sources?, existing_detections? }` where `platform` is `splunk` | `elastic` | `cloudwatch` | `sentinel` | `datadog` | `chronicle` | `other`.

```jsonc
// Request: { "config": { "platform": "splunk" } }
// Response: { "platform": "splunk", "recommended_log_sources": [...], "priority_detections": [...], "dashboards": [...], "alerting_guidance": [...] }
```

### `altais_generate_disclosure_program`

Generate a coordinated-vulnerability-disclosure or bug-bounty policy document.

- **Inputs:** `config` — `{ organization, contact, scope_in?, scope_out?, safe_harbor?, bounty?, response_sla_days? }`.

```jsonc
// Request: { "config": { "organization": "Acme", "contact": "security@acme.example" } }
// Response: { "markdown": "# Acme Vulnerability Disclosure Policy\n..." }
```

---

## Module: `testing`

Seven generators for security-testing artifacts. Each parses a request and returns a generated artifact as JSON; none push findings.

### `altais_generate_fuzz_config`

Generate a fuzz-testing setup — harness skeleton, runner, sanitizer recommendation, corpus guidance.

- **Inputs:** `language` — `c` | `cpp` | `rust` | `go` | `python` | `javascript` | `java`; `fuzzer` _(optional)_ `libfuzzer` | `afl++` | `cargo-fuzz` | `go-fuzz` | `atheris` | `jazzer` | `jsfuzz`; `target_function` _(optional)_.

```jsonc
// Request: { "language": "rust", "fuzzer": "cargo-fuzz", "target_function": "parse_header" }
// Response: { "fuzzer": "cargo-fuzz", "harness": "...", "runner_script": "...", "sanitizers": [...], "corpus_guidance": "..." }
```

### `altais_generate_sast_config`

Generate a ready-to-use static-analysis tool configuration.

- **Inputs:** `tool` — `semgrep` | `codeql` | `bandit` | `gosec` | `eslint-security` | `brakeman`; `languages` — array of target languages.

```jsonc
// Request: { "tool": "semgrep", "languages": ["python"] }
// Response: { "tool": "semgrep", "config_file": "...", "rule_packs": [...], "ci_snippet": "..." }
```

### `altais_generate_pentest_scope`

Generate a penetration-test scoping document.

- **Inputs:** `config` — `{ application_type, assets, environment, constraints, objectives }` where `application_type` is `web` | `api` | `mobile` | `network` | `cloud` | `thick-client` and `environment` is `production` | `staging` | `isolated`.

```jsonc
// Request: { "config": { "application_type": "web", "assets": ["app.example.com"], "environment": "staging", "constraints": [], "objectives": ["prove access to PII"] } }
// Response: { "in_scope": [...], "out_of_scope": [...], "rules_of_engagement": [...], "methodology": "...", "checklist": [...] }
```

### `altais_generate_security_tests`

Generate security-focused test cases for a vulnerability class.

- **Inputs:** `vulnerability_class` — `injection` | `xss` | `auth` | `access-control` | `ssrf` | `csrf` | `crypto` | `business-logic`; `language`; `framework` _(optional)_.

```jsonc
// Request: { "vulnerability_class": "xss", "language": "javascript", "framework": "jest" }
// Response: { "framework": "jest", "test_code": "...", "positive_cases": [...], "negative_cases": [...] }
```

### `altais_generate_chaos_config`

Generate a security chaos-engineering / fault-injection configuration.

- **Inputs:** `config` — `{ platform, experiments }` where `platform` is `kubernetes` | `aws` | `linux-host` | `application` and `experiments` is an array of `network-latency` | `dependency-failure` | `credential-expiry` | `pod-kill` | `iam-revocation`.

```jsonc
// Request: { "config": { "platform": "kubernetes", "experiments": ["pod-kill"] } }
// Response: { "platform": "kubernetes", "experiments": [{ "name": "pod-kill", "steady_state_hypothesis": "...", "blast_radius": "...", "rollback": "..." }] }
```

### `altais_scope_red_team`

Generate a red-team / adversary-simulation engagement scope.

- **Inputs:** `config` — `{ objectives, threat_actor_profile, duration_weeks, constraints, assumed_breach }` where `threat_actor_profile` is `opportunistic` | `organized-crime` | `nation-state` | `insider`.

```jsonc
// Request: { "config": { "objectives": ["exfiltrate crown-jewel data"], "threat_actor_profile": "nation-state", "duration_weeks": 6, "constraints": [], "assumed_breach": true } }
// Response: { "objectives": [...], "ttps": [{ "attack_id": "T1078", "name": "..." }], "rules_of_engagement": [...], "success_criteria": [...] }
```

### `altais_generate_iast_config`

Generate an Interactive Application Security Testing setup.

- **Inputs:** `tool` — `contrast` | `seeker` | `dynatrace` | `open-source`; `language`; `framework` _(optional)_.

```jsonc
// Request: { "tool": "contrast", "language": "java", "framework": "spring-boot" }
// Response: { "tool": "contrast", "agent_setup": [...], "instrumentation_config": "...", "ci_workflow": "...", "coverage_guidance": "..." }
```

---

## Module: `sdlc`

Secure-SDLC tooling: generators for pre-commit and review checklists, plus auditors/assessors for CI/CD, release integrity, signing, branch protection, SLSA, and CODEOWNERS.

### `altais_generate_precommit`

Generate a `.pre-commit-config.yaml` wiring the requested security and quality checks.

- **Inputs:** `config` — `{ languages, checks }` where `checks` is an array of `secrets` | `lint` | `format` | `sast` | `dependency-audit` | `large-files` | `private-key`.

```jsonc
// Request: { "config": { "languages": ["python"], "checks": ["secrets", "sast"] } }
// Response: { "yaml": "repos:\n  - repo: ...\n", "setup_notes": [...] }
```

### `altais_audit_ci_cd`

Review a CI/CD pipeline for the security gates that should block an insecure change.

- **Inputs:** `content` _(optional)_ pipeline YAML; `config` _(optional)_ `{ has_sast?, has_dependency_scan?, has_secret_scan?, has_container_scan?, has_dast?, blocks_on_failure?, signed_artifacts? }`; `filename` _(optional)_. Provide `content` or `config`.

```jsonc
// Request: { "config": { "has_sast": false, "blocks_on_failure": false } }
// Response: { "summary": {...}, "findings": [{ "rule": "no-sast-gate", "cwe": ["CWE-1395"] }] }
```

### `altais_generate_review_checklist`

Generate a security code-review checklist tailored to the change.

- **Inputs:** `config` — `{ change_type, languages, sensitivity }` where `change_type` is `feature` | `bugfix` | `dependency` | `infrastructure` | `auth` | `crypto` and `sensitivity` is `low` | `medium` | `high`.

```jsonc
// Request: { "config": { "change_type": "auth", "languages": ["typescript"], "sensitivity": "high" } }
// Response: { "checklist": [{ "category": "authorization", "items": [...], "mandatory": true }] }
```

### `altais_check_release_integrity`

Verify a release process carries the controls that let a consumer trust an artifact.

- **Inputs:** `config` — `{ artifacts_signed?, checksums_published?, reproducible_build?, sbom_published?, provenance_attestation?, release_from_protected_branch?, changelog_maintained?, tags_signed? }`; `filename` _(optional)_.

```jsonc
// Request: { "config": { "artifacts_signed": false, "sbom_published": false } }
// Response: { "summary": {...}, "findings": [{ "rule": "unsigned-artifacts", "cwe": ["CWE-353"] }] }
```

### `altais_check_signed_commits`

Verify commits are GPG/SSH signed and that signing is enforced.

- **Inputs:** `git_log` _(optional)_ `git log` output with signature markers; `config` _(optional)_ `{ signing_enforced?, total_commits?, signed_commits?, verified_commits? }`; `filename` _(optional)_. Provide `git_log` or `config`.

```jsonc
// Request: { "config": { "signing_enforced": false, "total_commits": 100, "signed_commits": 12 } }
// Response: { "summary": {...}, "findings": [{ "rule": "signing-not-enforced", "cwe": ["CWE-347"] }] }
```

### `altais_audit_branch_protection`

Audit a repository's default-branch protection settings.

- **Inputs:** `config` — `{ required_reviews?, dismiss_stale_reviews?, required_status_checks?, require_up_to_date?, enforce_for_admins?, restrict_force_push?, restrict_deletions?, require_signed_commits?, require_linear_history?, require_conversation_resolution? }`; `filename` _(optional)_.

```jsonc
// Request: { "config": { "required_reviews": 0, "restrict_force_push": false } }
// Response: { "summary": {...}, "findings": [{ "rule": "no-required-review", "cwe": ["CWE-1269"] }] }
```

### `altais_assess_slsa_level`

Assess the achieved SLSA v1.2 Build Track level (0–3) from build-process facts.

- **Inputs:** `config` — `{ scripted_build?, build_service?, provenance_generated?, provenance_authenticated?, provenance_service_generated?, isolated_build?, hermetic?, parameterless? }`; `filename` _(optional)_.

```jsonc
// Request: { "config": { "scripted_build": true, "build_service": true, "provenance_generated": true } }
// Response: { "summary": {...}, "findings": [{ "rule": "slsa-level", "title": "Build Track Level 1", "description": "...requirements to reach Level 2..." }] }
```

### `altais_check_codeowners`

Verify a CODEOWNERS file gives security-sensitive paths a required reviewer.

- **Inputs:** `content` — CODEOWNERS file body; `sensitive_paths` _(optional)_ array; `filename` _(optional)_.

```jsonc
// Request: { "content": "* @team\n" }
// Response: { "summary": {...}, "findings": [{ "rule": "sensitive-path-uncovered", "cwe": ["CWE-1220"] }] }
```

---

## Module: `ml_security`

ML/LLM security audits. Auditors push findings; coverage tools also return a `categories` array.

### `altais_audit_ml_pipeline`

Audit an ML training pipeline for data poisoning, insecure model deserialization, and provenance gaps.

- **Inputs:** `source` _(optional)_; `config` _(optional)_ `{ training_data_source?, data_validation?, data_provenance_tracked?, model_format?, model_signed?, pinned_dependencies?, secrets_in_notebooks?, lineage_tracked? }`; `filename` _(optional)_.

```jsonc
// Request: { "source": "model = torch.load('m.pt')" }
// Response: { "summary": {...}, "findings": [{ "rule": "insecure-model-deserialization", "cwe": ["CWE-502"] }] }
```

### `altais_audit_inference_api`

Check a model-serving API for model-extraction and adversarial-evasion risk.

- **Inputs:** `source` _(optional)_; `config` _(optional)_ `{ rate_limited?, authentication?, returns_confidence_scores?, returns_logits?, input_validation?, batch_endpoint?, monitoring?, query_logging? }`; `filename` _(optional)_.

```jsonc
// Request: { "config": { "rate_limited": false, "returns_logits": true } }
// Response: { "summary": {...}, "findings": [{ "rule": "no-rate-limiting", "cwe": ["CWE-770"] }, { "rule": "logits-exposed" }] }
```

### `altais_audit_model_supply_chain`

Verify the provenance and integrity of a model artifact.

- **Inputs:** `config` — `{ source?, format?, signed?, checksum_verified?, scanned_for_malware?, pinned_revision? }`; `filename` _(optional)_.

```jsonc
// Request: { "config": { "format": "pickle", "signed": false } }
// Response: { "summary": {...}, "findings": [{ "rule": "pickle-format-model", "cwe": ["CWE-502"] }, { "rule": "unsigned-model" }] }
```

### `altais_check_owasp_ml`

Check an ML system against the OWASP ML Security Top 10 (ML01–ML10).

- **Inputs:** `config` _(optional)_ — boolean flags keyed to ML01–ML10 controls; `filename` _(optional)_.

```jsonc
// Request: { "config": { "input_validation": false } }
// Response: { "summary": {...}, "categories": [{ "id": "ML01", "status": "needs_review" }], "findings": [...] }
```

### `altais_check_llm_top10`

Audit an LLM application against the OWASP Top 10 for LLM Applications (2025).

- **Inputs:** `source` _(optional)_; `config` _(optional)_ — boolean flags keyed to LLM01–LLM10 controls; `filename` _(optional)_.

```jsonc
// Request: { "config": { "prompt_injection_defenses": false, "agency_limited": false } }
// Response: { "summary": {...}, "categories": [{ "id": "LLM01", "status": "needs_review" }], "findings": [...] }
```

### `altais_audit_prompt_injection`

Analyze prompt construction for injection vulnerabilities (OWASP LLM01).

- **Inputs:** `source` _(optional)_; `config` _(optional)_ `{ instruction_data_separation?, input_filtering?, output_validation?, tool_output_sanitized? }`; `filename` _(optional)_.

```jsonc
// Request: { "source": "prompt = f'You are a bot. {user_input}'" }
// Response: { "summary": {...}, "findings": [{ "rule": "untrusted-input-in-prompt", "cwe": ["CWE-1427"] }] }
```

### `altais_audit_agent_permissions`

Check an LLM agent for excessive agency (OWASP LLM06).

- **Inputs:** `config` — `{ tools?, tool_count?, has_destructive_tools?, human_approval_required?, permission_scopes?, autonomous?, can_spend_money?, can_modify_data?, can_execute_code? }`; `filename` _(optional)_.

```jsonc
// Request: { "config": { "can_modify_data": true, "human_approval_required": false, "autonomous": true } }
// Response: { "summary": {...}, "findings": [{ "rule": "destructive-action-no-approval", "cwe": ["CWE-862"] }] }
```

### `altais_audit_output_handling`

Verify LLM output is sanitized before downstream use (OWASP LLM05).

- **Inputs:** `source` _(optional)_; `config` _(optional)_ `{ html_encoded?, sql_parameterized?, shell_safe?, schema_validated?, treated_as_trusted? }`; `filename` _(optional)_.

```jsonc
// Request: { "source": "element.innerHTML = llmResponse" }
// Response: { "summary": {...}, "findings": [{ "rule": "llm-output-to-dom", "cwe": ["CWE-79"] }] }
```

---

## Module: `agentic`

Ten auditors against the OWASP Agentic Applications Security Top 10 (2026), ASI01–ASI10. Every tool accepts `source` _(optional)_, `filename` _(optional)_, and a structured `config`.

### `altais_audit_goal_hijack`

Audit against ASI01 (Agent Goal Hijacking).

- **Inputs:** `config` _(optional)_ `{ instruction_data_separation?, goal_validation?, untrusted_tool_output_to_planner?, untrusted_data_to_planner?, system_prompt_protected?, plan_review? }`.

```jsonc
// Request: { "config": { "instruction_data_separation": false, "plan_review": false } }
// Response: { "summary": {...}, "findings": [{ "rule": "no-instruction-data-separation", "tags": ["owasp:asi01"] }] }
```

### `altais_audit_tool_misuse`

Audit against ASI02 (Tool Misuse & Exploitation).

- **Inputs:** `config` _(optional)_ `{ tools?, tool_allowlist?, tool_descriptors_verified?, over_permissioned_apis?, input_validation_on_tool_args?, tool_output_validation?, rate_limited? }`.

```jsonc
// Request: { "config": { "tool_allowlist": false, "tool_descriptors_verified": false } }
// Response: { "summary": {...}, "findings": [{ "rule": "no-tool-allowlist" }, { "rule": "unverified-tool-descriptors" }] }
```

### `altais_audit_agent_identity`

Audit against ASI03 (Identity & Privilege Abuse).

- **Inputs:** `config` _(optional)_ `{ per_agent_identity?, privilege_inheritance?, can_escalate_privileges?, confused_deputy_protection?, cross_session_credential_retention?, scoped_credentials?, human_user_distinct_from_agent? }`.

```jsonc
// Request: { "config": { "privilege_inheritance": true, "confused_deputy_protection": false } }
// Response: { "summary": {...}, "findings": [{ "rule": "privilege-inheritance" }, { "rule": "no-confused-deputy-protection" }] }
```

### `altais_audit_agentic_supply_chain`

Audit against ASI04 (Agentic Supply Chain Vulnerabilities).

- **Inputs:** `config` _(optional)_ `{ mcp_servers?, manifests_signed?, plugins_verified?, agent_cards_verified?, registry_pinned?, typosquat_checked?, provenance_attestation? }`.

```jsonc
// Request: { "config": { "manifests_signed": false, "plugins_verified": false } }
// Response: { "summary": {...}, "findings": [{ "rule": "unsigned-manifests" }, { "rule": "unverified-plugins" }] }
```

### `altais_audit_code_execution`

Audit against ASI05 (Unexpected Code Execution).

- **Inputs:** `config` _(optional)_ `{ executes_generated_code?, sandboxed?, sandbox_type?, allowlist_enforced?, network_access_in_sandbox?, filesystem_access_in_sandbox?, resource_limits? }`.

```jsonc
// Request: { "config": { "executes_generated_code": true, "sandboxed": false } }
// Response: { "summary": {...}, "findings": [{ "rule": "generated-code-no-sandbox", "severity": "critical" }] }
```

### `altais_audit_memory_poisoning`

Audit against ASI06 (Memory & Context Poisoning).

- **Inputs:** `config` _(optional)_ `{ memory_validation?, memory_isolation_per_user?, rag_source_trust_verified?, shared_state_between_agents?, memory_provenance?, untrusted_content_persisted? }`.

```jsonc
// Request: { "config": { "memory_validation": false, "memory_isolation_per_user": false } }
// Response: { "summary": {...}, "findings": [{ "rule": "no-memory-validation" }, { "rule": "cross-user-memory-bleed" }] }
```

### `altais_audit_inter_agent_comms`

Audit against ASI07 (Insecure Inter-Agent Communication).

- **Inputs:** `config` _(optional)_ `{ message_authentication?, message_integrity?, origin_validation?, encrypted_channel?, message_signing?, replay_protection? }`.

```jsonc
// Request: { "config": { "message_authentication": false, "encrypted_channel": false } }
// Response: { "summary": {...}, "findings": [{ "rule": "unauthenticated-messages" }, { "rule": "cleartext-channel" }] }
```

### `altais_audit_cascading_failures`

Audit against ASI08 (Cascading Agent Failures).

- **Inputs:** `config` _(optional)_ `{ kill_switch?, circuit_breakers?, blast_radius_limits?, agent_isolation?, failure_detection?, rate_limits_between_agents?, max_agent_chain_depth? }`.

```jsonc
// Request: { "config": { "kill_switch": false, "circuit_breakers": false } }
// Response: { "summary": {...}, "findings": [{ "rule": "no-kill-switch" }, { "rule": "no-circuit-breakers" }] }
```

### `altais_audit_trust_exploitation`

Audit against ASI09 (Human-Agent Trust Exploitation).

- **Inputs:** `config` _(optional)_ `{ consent_separation?, approval_flow_independent?, action_attribution_clear?, high_risk_actions_need_confirmation?, agent_cannot_render_own_approval_ui?, deceptive_output_controls? }`.

```jsonc
// Request: { "config": { "approval_flow_independent": false, "agent_cannot_render_own_approval_ui": false } }
// Response: { "summary": {...}, "findings": [{ "rule": "non-independent-approval-flow" }] }
```

### `altais_audit_rogue_agents`

Audit against ASI10 (Rogue Agents).

- **Inputs:** `config` _(optional)_ `{ behavioral_baseline?, anomaly_detection?, anomaly_detection_coverage?, agent_inventory?, agent_governance_policy?, sandboxing?, audit_logging?, revocation_capability? }`.

```jsonc
// Request: { "config": { "anomaly_detection": false, "revocation_capability": false } }
// Response: { "summary": {...}, "findings": [{ "rule": "no-anomaly-detection" }, { "rule": "no-revocation-capability" }] }
```

---

## Module: `runtime`

Runtime application protection: a WAF rule generator, a RASP recommender, and a monitoring auditor. The two generators return artifacts; `altais_audit_monitoring` pushes findings.

### `altais_generate_waf_rules`

Generate a ready-to-use WAF rule set for a chosen platform.

- **Inputs:** `config` — `{ platform, protect_against, paths_to_protect? }` where `platform` is `modsecurity` | `cloudflare` | `aws-waf` | `nginx-naxsi` and `protect_against` is an array of `sql-injection` | `xss` | `path-traversal` | `rce` | `ssrf` | `scanner` | `rate-abuse`.

```jsonc
// Request: { "config": { "platform": "modsecurity", "protect_against": ["sql-injection", "xss"] } }
// Response: { "platform": "modsecurity", "rules": [...], "deployment_note": "...", "recommendation": "Run in detection mode before enforcing." }
```

### `altais_recommend_rasp`

Recommend a RASP configuration for an application's stack.

- **Inputs:** `config` — `{ language, framework, deployment, risk_tolerance }` where `language` is `java` | `dotnet` | `node` | `python` | `ruby` | `go`, `deployment` is `container` | `vm` | `serverless`, and `risk_tolerance` is `low` | `medium` | `high`.

```jsonc
// Request: { "config": { "language": "java", "framework": "spring-boot", "deployment": "container", "risk_tolerance": "medium" } }
// Response: { "product_category": "...", "protections": [{ "name": "sql-injection", "mode": "block" }], "instrumentation_steps": [...], "performance_considerations": [...] }
```

### `altais_audit_monitoring`

Audit an application's monitoring posture for security-event coverage.

- **Inputs:** `config` — `{ logs_authentication, logs_authorization_failures, logs_input_validation_failures, logs_admin_actions, alerting_enabled, alert_routing, siem_integrated, metrics_collected, anomaly_detection, dashboards, on_call, mean_time_to_detect_minutes }`; `filename` _(optional)_.

```jsonc
// Request: { "config": { "logs_authentication": false, "alerting_enabled": false, "siem_integrated": false, "mean_time_to_detect_minutes": 480, /* ... */ } }
// Response: { "summary": {...}, "findings": [{ "rule": "no-authentication-logging" }, { "rule": "no-alerting" }] }
```
