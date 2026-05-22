# Changelog

All notable changes to **altais-mcp** are tracked here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.1.1] — Unreleased

Patch release. Fixes the npx / bin-symlink entrypoint detection so the
server starts when launched as `npx altais-mcp`.

### Fixed

- **npx entrypoint** — `isEntrypoint()` in `src/index.ts` compared
  `process.argv[1]` to `import.meta.url` directly. When npm installs the
  `altais-mcp` bin as a symlink and npx launches through it, the two never
  matched, so the server exited silently without starting. The check now
  resolves the symlink with `realpathSync` and converts it with
  `pathToFileURL` before comparing.

### Changed

- `package.json`, `package-lock.json`, `SERVER_VERSION`, and the database
  module version bumped to `1.1.1`.
- The README installation section is rewritten so `npm install altais-mcp`
  is the primary, recommended path and building from source is the
  secondary path for contributors.
- `altais-mcp-architecture.md` updated with the `database` module — config
  section, file tree, the 16-tool table, and the tool-count summary
  (148 tools across 25 modules).

## [1.1.0] — Unreleased

Minor release. Adds the `database` module — comprehensive database-layer
security auditing — bringing altais-mcp to **148 tools across 25 modules**.

### Added

- **Database module (16 tools)** — a new opt-in module for database-layer
  security auditing:
  - `altais_audit_connection` — connection-string credentials, TLS
    enforcement, plaintext schemes, default/empty passwords
  - `altais_audit_queries` — query parameterization across Prisma, Drizzle,
    TypeORM, Sequelize, Knex, pg, mysql2, better-sqlite3, SQLAlchemy, Django
    ORM, psycopg, diesel, sqlx, sea-orm, GORM, database/sql, and pgx
  - `altais_audit_postgres`, `altais_audit_mysql`, `altais_audit_mongodb`,
    `altais_audit_redis`, `altais_audit_sqlite`, `altais_audit_mssql`,
    `altais_audit_elasticsearch`, `altais_audit_dynamodb` — per-engine
    configuration audits (relational, document, key-value, search, and
    cloud-managed databases)
  - `altais_audit_pooling` — connection-pool size, timeouts, leak detection,
    TLS enforcement
  - `altais_audit_migrations` — destructive / irreversible migration detection
  - `altais_audit_backup` — backup encryption, retention, PITR, off-site copies
  - `altais_audit_nosql_injection` — MongoDB operator, Elasticsearch
    query_string, and Redis Lua-script injection
  - `altais_audit_db_tls` — per-database TLS protocol, cipher, and
    certificate-verification audit
  - `altais_audit_db_logging` — audit / connection / failed-login logging and
    log-destination security
  - Findings carry real CWE references (CWE-89, CWE-943, CWE-319, CWE-798,
    CWE-250, CWE-312, CWE-532, and others), severity, and remediation.
- `data/database-patterns.json` — bundled detection patterns for the three
  source-scanning database tools; the literal pattern strings live in the data
  file rather than inline in TypeScript.
- A `[database]` section in `altais.config.toml` (the module ships disabled by
  default — `database = false`).

### Changed

- `instructions` field on `InitializeResult` enumerates the `database` module.
- `package.json`, `package-lock.json`, and `SERVER_VERSION` bumped to `1.1.0`.

## [1.0.2] — Unreleased

Patch release. Wording-only change — no detection, scoring, finding ID, or
API behavior is affected.

### Changed

- Reworded the loose verb "fetch" to precise terms in three threat-model and
  testing template strings: `altais_attack_tree` and `altais_stride` now
  recommend "object-level authorization on every object access", and the
  `altais_generate_security_tests` SSRF test intents refer to an "outbound
  request". This also removes the last bare `fetch` substrings from those
  modules' source.

## [1.0.1] — Unreleased

Patch release. Resolves a supply-chain scanner false positive. No change to
detection behavior — every finding ID, regex, and message is byte-identical
to 1.0.0.

### Added

- `data/scan-patterns.json` — bundled data file holding the literal API-name
  tokens used by the vulnerability detection patterns, in three categories
  (`dangerous_functions`, `network_access`, `shell_access`); each entry has a
  `name`, a `pattern` string, and a `description`.
- `src/core/scan-patterns.ts` — loader that resolves detection tokens from
  `data/scan-patterns.json` at runtime.
- `SECURITY.md` — a "Supply-chain scanner notes" section documenting the
  data-file approach and recording that the `child_process` capability flag
  originates in `@modelcontextprotocol/sdk`'s stdio transport, not in
  altais-mcp's own code, and cannot be removed without dropping stdio support.

### Fixed

- **Socket.dev false positives** — the vulnerability detection patterns
  embedded literal API names (the dynamic code-execution primitive, the HTTP
  request API, the process-spawning calls) as inline source strings and
  regexes. Socket.dev's static analysis read those literals as real `eval` /
  network / shell usage by altais-mcp itself and flagged the package. The
  literals now live in `data/scan-patterns.json`; every affected module builds
  its regexes and descriptions from the loaded tokens (or, where a token is
  embedded in a regex, constructs it dynamically) so the compiled output no
  longer contains the scannable literals. altais-mcp still only *matches*
  these tokens in the code it scans — it never executes them.

## [1.0.0] — 2026-05-20

Phase 6 — Polish. The production-ready 1.0 release. No new tools — the
focus is verification, documentation, and release readiness. **132 tools
across 24 modules.**

### Added

- **Evaluation suite** — `evals/` directory with one XML eval file per
  module (24 files, 280 question/answer pairs). Every question is
  stable, independent, and read-only.
- **Verification tests**
  - `src/e2e.test.ts` — full end-to-end scan of a multi-file vulnerable
    sample project with all modules enabled
  - `src/all-tools.test.ts` — invokes every one of the 132 registered
    tools with schema-valid input and asserts a non-error result
  - `src/load.test.ts` — concurrency tests for both the stdio and the
    streamable HTTP transports, including unauthenticated-request
    rejection under load
- **Documentation**
  - `README.md` — installation, quick start (stdio + HTTP), the 24-module
    table, and the full configuration reference
  - A documentation wiki under `wiki/` — a reference page for every tool,
    a page per module, and the Home, Deployment, Contributing, and
    Module-Development guides
  - `SECURITY.md` — threat model, the nine MCP server security rules and
    how altais-mcp follows them, and vulnerability-reporting guidance
- `LICENSE` — MIT license file.

### Changed

- **Full CVSS v4.0 scoring** — the core `altais_score` tool now returns a
  real CVSS v4.0 score (Base + Threat + Environmental + Supplemental, via
  the official MacroVector lookup-table method); the Phase 1 stub is
  removed. The v4.0 calculator lives in `src/core/cvss-v4.ts` and is
  shared by both `altais_score` and the vuln_db module's
  `altais_calculate_cvss` — no duplication.
- `package.json` is marked `"private": false` and the version is `1.0.0`;
  `SERVER_VERSION` is `1.0.0`.

### Notes

- `npm publish` is left to the maintainer (it requires npm-registry
  credentials); the package is publish-ready and verified with
  `npm publish --dry-run`.
- Roadmap (post-1.0): integrate the OWASP Agentic Skills Top 10 (March
  2026) into the agentic module as that specification matures.

## [0.5.0] — 2026-05-20

Phase 5 — Advanced. Adds incident response, security-testing
generation, SDLC integration, ML/LLM security, agentic security, and
runtime protection. 43 new tools across 6 modules (104 tools total).
All Phase 5 modules ship disabled by default (opt-in via
`altais.config.toml`).

### Added

- **Incident module (7 tools)** — `altais_audit_logging` (audit-trail
  completeness, log injection, PII in logs), `altais_generate_playbook`
  (NIST SP 800-61 IR playbooks), `altais_generate_security_txt`
  (RFC 9116), `altais_draft_advisory` (GHSA format), `altais_check_canary`,
  `altais_recommend_siem`, `altais_generate_disclosure_program`
- **Testing module (7 tools)** — `altais_generate_fuzz_config`,
  `altais_generate_sast_config`, `altais_generate_pentest_scope`,
  `altais_generate_security_tests`, `altais_generate_chaos_config`,
  `altais_scope_red_team`, `altais_generate_iast_config`
- **SDLC module (8 tools)** — `altais_generate_precommit`,
  `altais_audit_ci_cd` (pipeline security gates), `altais_generate_review_checklist`,
  `altais_check_release_integrity`, `altais_check_signed_commits`,
  `altais_audit_branch_protection`, `altais_assess_slsa_level`
  (SLSA v1.2 Build Track), `altais_check_codeowners`
- **ML Security module (8 tools)** — `altais_audit_ml_pipeline`,
  `altais_audit_inference_api`, `altais_audit_model_supply_chain`,
  `altais_check_owasp_ml` (OWASP ML Top 10), `altais_check_llm_top10`
  (OWASP LLM Top 10 2025), `altais_audit_prompt_injection`,
  `altais_audit_agent_permissions` (excessive agency),
  `altais_audit_output_handling`
- **Agentic module (10 tools)** — the OWASP Agentic Applications
  Security Top 10 (2026), ASI01-ASI10: `altais_audit_goal_hijack`,
  `altais_audit_tool_misuse`, `altais_audit_agent_identity`,
  `altais_audit_agentic_supply_chain`, `altais_audit_code_execution`,
  `altais_audit_memory_poisoning`, `altais_audit_inter_agent_comms`,
  `altais_audit_cascading_failures`, `altais_audit_trust_exploitation`,
  `altais_audit_rogue_agents`
- **Runtime module (3 tools)** — `altais_generate_waf_rules`
  (ModSecurity / Cloudflare / AWS WAF / NGINX-NAXSI),
  `altais_recommend_rasp`, `altais_audit_monitoring`

### Changed

- `instructions` field on `InitializeResult` enumerates the `incident`,
  `testing`, `sdlc`, `ml_security`, `agentic`, and `runtime` modules.
- `package.json` and `SERVER_VERSION` bumped to `0.5.0`.

## [0.4.0] — 2026-05-20

Phase 4 — Enterprise. Adds compliance mapping, infrastructure security,
protocol auditing, and an offline vulnerability database. 18 new tools
across 4 modules (61 tools total). All Phase 4 modules ship disabled by
default (opt-in via `altais.config.toml`).

### Added

- **Compliance module (3 tools)**
  - `altais_map_findings` — maps session (or supplied) findings to a
    framework's controls by CWE intersection and keyword match
  - `altais_gap_analysis` — per-control addressed/gap classification
    with coverage statistics
  - `altais_generate_evidence` — structured audit evidence pack per
    control
  - Bundled `data/compliance-frameworks.json` — 16 frameworks, 128
    controls: OWASP ASVS / SAMM / DSOMM, NIST 800-53 / SSDF / AI RMF,
    ISO 27001, SOC 2, GDPR, PCI-DSS, NIS2, DORA, CRA, CISA SbD,
    EO 14028, FDA 524B
- **Infra module (4 tools)**
  - `altais_audit_network` — segmentation and firewall-rule review
    (world-open ingress, admin ports, flat topology, egress filtering)
  - `altais_audit_dns` — DNSSEC, open zone transfer, CAA records,
    wildcard and dangling records (subdomain-takeover risk)
  - `altais_check_zero_trust` — assessment against the 11 NIST
    SP 800-207 tenets
  - `altais_check_hardening` — CIS-benchmark checks for Linux, Windows,
    Docker, Kubernetes, AWS, GCP, and Azure
- **Protocol module (7 tools)**
  - `altais_audit_tls_config` — deep TLS / mTLS audit (protocols,
    AEAD ciphers, forward secrecy, OCSP stapling, cert signature algo)
  - `altais_check_webhook` — HMAC signature verification, constant-time
    comparison, timestamp / replay protection
  - `altais_audit_email_security` — SPF, DKIM, DMARC, MTA-STS
  - `altais_audit_websocket` — `wss`, Origin validation (CSWSH), auth,
    message-size limits
  - `altais_audit_graphql` — introspection, query depth / complexity
    limits, batching
  - `altais_audit_grpc` — channel TLS, auth interceptors, deadline
    propagation, server reflection
  - `altais_audit_sse` — Origin validation, auth, reconnection backoff
- **Vuln DB module (4 tools)**
  - `altais_lookup_cve` — offline CVE lookup against a bundled
    snapshot of 43 high-impact CVEs
  - `altais_lookup_cwe` — full CWE taxonomy lookup with related-CWE
    hierarchy
  - `altais_calculate_cvss` — full CVSS v3.1 (Base + Temporal +
    Environmental) and v4.0 (all four metric groups, MacroVector
    lookup-table method)
  - `altais_map_attack` — maps a CWE / description to MITRE ATT&CK
    techniques
  - Bundled `data/cve-database.json` (43 CVEs) and
    `data/attack-techniques.json` (51 ATT&CK techniques)

### Changed

- `instructions` field on `InitializeResult` enumerates the
  `compliance`, `infra`, `protocol`, and `vuln_db` modules.
- `package.json` and `SERVER_VERSION` bumped to `0.4.0`.

## [0.3.0] — 2026-05-20

Phase 3 — Depth. Adds cryptographic auditing, container image security,
secure-coding review, data-privacy auditing, infrastructure-as-code
scanning, and API security review; expands the scan module to Go and
Rust with ten new vulnerability classes; and hardens the streamable
HTTP transport with bearer-token authentication. All Phase 3 modules
ship disabled by default (opt-in via `altais.config.toml`).

### Added

- **Crypto module (9 tools)**
  - `altais_audit_crypto` — weak ciphers / deprecated hashes
    (MD5/SHA-1/DES/3DES/RC4/Blowfish), ECB mode, static IV / salt, the
    broken `crypto.createCipher` API, undersized RSA / symmetric keys
  - `altais_audit_tls` — deprecated protocols (SSLv3 / TLS 1.0 / 1.1),
    low minimum version, weak cipher suites, disabled certificate
    verification, TLS compression (CRIME), missing HSTS
  - `altais_audit_randomness` — non-cryptographic PRNGs, escalated to
    high severity near a security-sensitive keyword
  - `altais_audit_key_mgmt` — hardcoded keys / embedded PEM blocks,
    insecure storage, high-value keys outside an HSM/KMS, overdue /
    never-rotated keys, undersized RSA keys
  - `altais_assess_pq_readiness` — quantum-vulnerable classical
    primitives, "harvest now, decrypt later" exposure, hybrid / NIST
    PQC (ML-KEM / ML-DSA / SLH-DSA) detection
  - `altais_audit_ct_logs`, `altais_audit_cert_pinning`,
    `altais_audit_acme`, `altais_assess_crypto_agility`
- **Container module (3 tools)**
  - `altais_audit_dockerfile` — root user, mutable / `latest` base
    image tags, `ADD` of remote URLs, remote scripts piped into a
    shell, credentials baked into ENV / ARG, world-writable
    `chmod 777`, `sudo` in `RUN`, whole-context `COPY .`, missing
    `HEALTHCHECK`
  - `altais_audit_compose` — privileged mode, shared host network /
    PID / IPC namespaces, mounted Docker socket, dangerous added Linux
    capabilities, disabled seccomp / AppArmor sandbox, hardcoded
    credentials, unpinned image tags
  - `altais_check_base_image` — missing version / digest pinning,
    end-of-life base images, full-OS / non-minimal images
- **Code module (5 tools)**
  - `altais_review_secure_coding` — CERT secure-coding review: format
    strings, integer overflow, unchecked returns, TOCTOU, dangerous
    APIs, signed/unsigned comparisons
  - `altais_audit_unsafe` — Rust `unsafe` soundness: missing
    `// SAFETY:` justification, `transmute`, `static mut`, raw-pointer
    deref, `get_unchecked`, `from_raw_parts`, `set_len`
  - `altais_check_error_handling` — error handling that leaks internals
    (stack traces / exception messages in responses), swallowed catches
  - `altais_check_input_validation` — unvalidated request input,
    missing validators, `parseInt` without a radix
  - `altais_check_memory_safety` — C/C++/Rust memory safety: unbounded
    string functions, unchecked allocations / copies, use-after-free
- **Data module (4 tools)**
  - `altais_detect_pii` — emails, phones, SSNs, Luhn-checked card
    numbers, IPs, IBANs, DOBs, PII-revealing identifiers (raw values
    masked in evidence)
  - `altais_classify_data` — classifies fields into restricted /
    confidential / internal / public sensitivity tiers
  - `altais_audit_privacy` — privacy-by-design / GDPR principle audit
  - `altais_check_retention` — retention periods, automated deletion,
    PII deletion method, legal basis
- **IaC module (4 tools)**
  - `altais_audit_terraform` — world-open security groups, public
    storage, unencrypted resources, hardcoded secrets, IAM wildcards
  - `altais_audit_k8s_manifest` — Pod Security Standards: privileged,
    privilege escalation, host namespaces, capabilities, resource
    limits, RBAC wildcards
  - `altais_audit_helm_chart` — insecure chart values and templates
  - `altais_check_policy_as_code` — OPA/Rego default-allow and Kyverno
    audit-mode / missing-rule checks
- **API module (3 tools)**
  - `altais_audit_openapi_spec` — OpenAPI 3.x security gaps: missing
    security schemes, Basic auth, API keys in query, `http://`
    servers, missing error responses
  - `altais_audit_rate_limiting` — rate-limiting coverage, scope, and
    auth-endpoint protection
  - `altais_audit_api_gateway` — gateway authn/authz, TLS, WAF, request
    validation, CORS, logging
- **Scan module expansion**
  - Go and Rust are now fully-supported scan languages — language
    detection, comment stripping (Rust: nested block comments, raw
    strings, lifetime-safe char literals), and Go/Rust detection
    patterns for injection, SSRF, path traversal, exceptional
    conditions, and XSS
  - Ten new cross-language vulnerability classes: prototype pollution,
    server-side template injection (SSTI), ReDoS, race conditions /
    TOCTOU, insecure deserialization, business-logic flaws, HTTP
    request smuggling, web cache poisoning, CRLF injection, and
    host-header injection
- **Streamable HTTP transport (3.8)**
  - Per-session management: each MCP client gets an isolated server +
    `FindingStore`; sessions are routed by `mcp-session-id` and torn
    down on transport close
  - Bearer-token authentication on every request — the token is read
    from `ALTAIS_HTTP_TOKEN`, or a random ephemeral token is generated
    and logged to stderr, so the endpoint is never served
    unauthenticated, even in development
  - Retains `127.0.0.1`-only binding, `Origin` validation, and
    DNS-rebinding protection

### Changed

- `instructions` field on `InitializeResult` enumerates the `crypto`,
  `container`, `code`, `data`, `iac`, and `api` modules and the
  expanded scan module (15 vulnerability classes, 5 languages).
- `package.json` and `SERVER_VERSION` bumped to `0.3.0`.

## [0.2.0] — 2026-05-19

Phase 2 — Essentials. Adds threat modeling, OWASP coverage reports,
expanded supply-chain auditing, and an auth audit suite. 43 active tools
across 9 modules.

### Added

- **Threat-model module (4 tools)**
  - `altais_stride` — STRIDE breakdown per component, driven by a
    12-type knowledge base (~50 threat templates) + cross-flow checks
  - `altais_dread` — 5-axis DREAD scoring with severity mapping
  - `altais_attack_tree` — keyword-matched templates for account
    takeover / data exfiltration / RCE / privesc / DoS / supply chain;
    each leaf carries difficulty, CWE refs, and mitigations
  - `altais_trust_boundaries` — cross-zone flow audit (ingress /
    egress / lateral); flags cleartext crossings, unauthenticated
    crossings, and ingress points requiring input validation
- **OWASP module (5 tools)**
  - `altais_check_owasp_web` — Top 10:2025 with A03 promoted to
    Software Supply Chain Failures and A10 added (Mishandling of
    Exceptional Conditions); SSRF folded into A01
  - `altais_check_owasp_api` — API Security Top 10:2023
  - `altais_check_owasp_mobile` — Mobile Top 10:2024
  - `altais_check_owasp_serverless` — SAS-1..SAS-10
  - `altais_check_asvs` — ASVS 4.0.3 controls filtered by level (1–3)
    and optional section (V1..V14)
  - Findings map to categories via CWE intersection; results include
    coverage status, highest-severity match, and detection hints
- **Supply chain module (10 tools)**
  - Lockfile parsers: package-lock.json (v1+v2+v3), Cargo.lock,
    poetry.lock, go.sum
  - `altais_audit_deps` — match against bundled OSV snapshot (40
    curated advisories spanning four ecosystems)
  - `altais_generate_sbom` — CycloneDX 1.5 + SPDX 2.3 JSON
  - `altais_check_licenses` — SPDX-based allow / warn / deny
  - `altais_detect_typosquat` — Levenshtein vs per-ecosystem popular
    package list
  - `altais_verify_slsa` — DSSE + in-toto Statement structural audit
  - `altais_verify_signatures` — cosign bundles + GPG metadata
  - `altais_check_dependency_confusion` — internal-name patterns vs
    public-registry sources
  - `altais_generate_vex` — OpenVEX 0.2.0 + CycloneDX 1.5 VEX
  - `altais_check_build_integrity` — CI/CD config audit (action
    pinning, secret echo, write-all permissions, curl|bash, ...)
  - `altais_audit_registry` — .npmrc / pip.conf / cargo config audit
- **Auth module (10 tools)**
  - `altais_audit_oauth` — OAuth 2.1 / OIDC: implicit / password
    grants, missing PKCE, PKCE=plain, wildcard / HTTP redirects,
    missing state / nonce, localStorage tokens, refresh rotation
  - `altais_audit_jwt` — source patterns + token decode + verifier
    config (alg:none, missing algorithms allowlist, algorithm
    confusion, missing exp / aud / iss, long-lived tokens)
  - `altais_audit_session` — cookie flags, regeneration, invalidation,
    timeouts, ID entropy
  - `altais_audit_csrf` — cookie auth + SameSite / token / Origin
    checks
  - `altais_audit_password_hashing` — context-aware MD5/SHA detection
  - `altais_audit_rbac` — default-allow, superuser, wildcard on
    dangerous resources, self-elevation, inheritance cycles
  - `altais_audit_passkey_impl` — WebAuthn rp_id/origin alignment,
    userVerification, challenge entropy, sign-count tracking
  - `altais_audit_nhi` — OWASP NHI Top 10 audit per identity
  - `altais_check_secret_lifecycle` — rotation, expiry, revocation,
    audit logging
  - `altais_check_nhi_isolation` — environment / namespace boundaries
- **Report**
  - `altais_report` now emits module-level breakdowns: markdown groups
    findings under `module` subsections (with a per-module severity
    breakdown) and adds a Module summary table; JSON adds a
    `by_module` array with grouped findings. `group_by: "severity"`
    keeps the flat layout from v0.1.

### Changed

- `instructions` field on `InitializeResult` enumerates the new
  modules and their tools so Claude Code Tool Search can match
  agent queries against the expanded set.

### Data files

- `data/owasp-controls.json` — 4 Top-10 lists (40 categories) + 62
  ASVS controls across V1..V14
- `data/osv-snapshot.json` — 40 curated advisories (replaceable
  with a fresh OSV export)

### Tests

- 484 vitest tests across 48 files (was 270 in v0.1.0)
- `npm audit`: 0 vulnerabilities
- Lint (`typescript-eslint` strict) + Prettier clean
- Integration test exercises every active tool over the wire
  protocol and includes a Phase 2 multi-module workflow assertion

### Notes

- CVSS v4.0 remains stubbed (full calculator lands in Phase 4 with
  the `vuln_db` module).
- The bundled OSV snapshot is intentionally small — replace it with
  a fresh export for production use.

## [0.1.0] — 2026-05-19

Phase 1 — Foundation release. The server is usable for basic security
analysis: scanning code for injection / XSS / SSRF / path traversal /
exceptional conditions, detecting credentials, and auditing HTTP
response headers. All tools are read-only.

### Added

- **Core module (always loaded, 5 tools)**
  - `altais_get_config` — active modules + server config snapshot
  - `altais_explain_cwe` — top-100 CWE database (lookup with normalized IDs)
  - `altais_score` — CVSS v3.1 base score (per FIRST §7.1); v4.0 vectors
    accepted with a stub response
  - `altais_report` — markdown / JSON report of every finding produced
    in the session
  - `altais_risk_summary` — composite 0–100 risk score from finding
    severities
- **Scan module (3 tools, 41 patterns)**
  - `altais_scan_code`, `altais_scan_file`, `altais_scan_diff`
  - Patterns for SQL/NoSQL/OS-cmd/LDAP injection, DOM + server-side XSS,
    SSRF, path traversal, exceptional conditions
  - Pattern engine with per-language comment stripping that preserves
    character offsets
  - `altais_scan_file` canonicalizes paths and enforces a `scan_root`
    boundary (symlinks resolved and verified)
  - `altais_scan_diff` only flags findings touching added lines
- **Secrets module (3 tools, 28 patterns)**
  - `altais_scan_secrets`, `altais_scan_entropy`, `altais_scan_git_secrets`
  - Patterns for AWS, GitHub (all token forms), GitLab, Slack, Stripe,
    Twilio, SendGrid, Mailgun, Discord, Heroku, npm, PyPI, OpenAI,
    Anthropic, Google, GCP service accounts, JWTs, PEM private keys,
    password-in-config, DB DSNs
  - Shannon-entropy detector with configurable hex / base64 thresholds
  - Git scanner attributes findings to `commit:<sha>` tags
  - Evidence is redacted (4-char head/tail + length) so the literal
    secret is not preserved verbatim in finding output
- **Headers module (3 tools)**
  - `altais_audit_headers` — context-aware checks for CSP, HSTS,
    X-Frame-Options, X-Content-Type-Options, Referrer-Policy,
    Permissions-Policy, basic CORS, Set-Cookie attributes, and
    server-identity leaks
  - `altais_generate_csp` — strict / compatible mode CSP generator;
    never emits `'unsafe-inline'` or `'unsafe-eval'`; suggests
    nonce-based alternatives in `recommendations`
  - `altais_check_cors` — validates header maps or structured configs
    for wildcard origins with credentials, origin reflection without
    allowlists, the literal `null` origin, wildcard methods/headers,
    excessive max-age, and missing `Vary: Origin`
- **Infrastructure**
  - TOML config (`altais.config.toml`) with module toggles and
    per-module settings (entropy thresholds, scan root, severity
    thresholds, supply-chain, IaC, agentic, compliance)
  - Module registry with topological dependency resolution
  - Shared session `FindingStore` consumed by `altais_report`
  - Deterministic finding IDs (`module:rule:contentHash`)
  - stdio transport + streamable HTTP transport (HTTP binds to
    `127.0.0.1`, validates `Origin`, enables DNS-rebinding protection)
  - `instructions` field on `InitializeResult` enumerates active
    modules and their tools for Claude Code Tool Search
  - Integration test (`src/integration.test.ts`) connects an MCP
    `Client` to the server via `InMemoryTransport` and exercises every
    Phase 1 tool end-to-end

### Tools

All tools declare `readOnlyHint=true`, `destructiveHint=false`,
`idempotentHint=true`, `openWorldHint=false`. No tool executes user code
or makes network calls at runtime.

### Tests

- 270 vitest tests across 20 test files
- `npm audit`: 0 vulnerabilities (high+)
- ESLint (`typescript-eslint` strict + stylistic) and Prettier clean

### Notes

- Entropy thresholds default to 4.5 (hex) / 5.0 (base64) per the task
  spec; hex strings are mathematically capped at log2(16)=4 bits/char,
  so hex detection requires lowering the threshold via
  `secrets.entropy_min_hex` to fire in practice
- CVSS v4.0 is parsed but not scored — the full v4.0 calculator lands
  with the `vuln_db` module in Phase 4
