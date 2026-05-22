# altais-mcp Wiki

**altais-mcp** is a modular, open-source [Model Context Protocol](https://modelcontextprotocol.io) server that gives AI coding agents comprehensive, **read-only** security analysis. It scans code, models threats, audits dependencies, checks compliance, and generates remediation guidance — it analyzes, it never modifies your code.

- **132 tools** across **24 modules**
- Every tool is `readOnlyHint: true` — no code execution, no runtime network calls
- Transports: stdio (local) and streamable HTTP (remote, bearer-token authenticated)
- License: MIT

## Start here

- [**Deployment**](Deployment.md) — install and run altais-mcp (stdio, HTTP, Docker, systemd)
- [**Contributing**](Contributing.md) — branch naming, commit conventions, the PR process
- [**Module development**](Module-Development.md) — add a new module to altais-mcp
- [Project README](../README.md) · [Security policy](../SECURITY.md) · [Tool reference](#all-tools)

## Modules

Seven modules plus `core` are enabled by default; the rest are opt-in via `altais.config.toml`.

| Module | Status | Tools | Purpose |
|--------|--------|-------|---------|
| [`core`](modules/core.md) | Always loaded | 5 | Config, CWE lookup, CVSS scoring, session reporting, risk score. |
| [`scan`](modules/scan.md) | Default | 3 | Static analysis — 15 vulnerability classes across TS/JS/Python/Go/Rust. |
| [`secrets`](modules/secrets.md) | Default | 3 | Secret detection: token patterns, Shannon entropy, git history. |
| [`headers`](modules/headers.md) | Default | 3 | HTTP security headers, CSP generation, CORS validation. |
| [`threat_model`](modules/threat_model.md) | Default | 4 | STRIDE, DREAD, attack trees, trust-boundary analysis. |
| [`owasp`](modules/owasp.md) | Default | 5 | OWASP Top 10 coverage — Web, API, Mobile, Serverless, ASVS. |
| [`supply_chain`](modules/supply_chain.md) | Default | 10 | Dependency auditing, SBOM, licenses, typosquatting, SLSA, signatures. |
| [`auth`](modules/auth.md) | Default | 10 | OAuth/OIDC, JWT, sessions, CSRF, RBAC, passkeys, non-human identities. |
| [`crypto`](modules/crypto.md) | Opt-in | 9 | Cipher/hash usage, TLS, randomness, key management, post-quantum. |
| [`container`](modules/container.md) | Opt-in | 3 | Dockerfile, Docker Compose, and base-image security. |
| [`code`](modules/code.md) | Opt-in | 5 | Secure-coding review, Rust unsafe, error handling, memory safety. |
| [`data`](modules/data.md) | Opt-in | 4 | PII detection, data classification, privacy-by-design, retention. |
| [`iac`](modules/iac.md) | Opt-in | 4 | Terraform, Kubernetes, Helm, and policy-as-code auditing. |
| [`api`](modules/api.md) | Opt-in | 3 | OpenAPI specs, rate limiting, API gateway configuration. |
| [`compliance`](modules/compliance.md) | Opt-in | 3 | Maps findings to 16 compliance frameworks; gap analysis; evidence. |
| [`infra`](modules/infra.md) | Opt-in | 4 | Network segmentation, DNS, zero-trust, CIS hardening. |
| [`protocol`](modules/protocol.md) | Opt-in | 7 | Deep TLS/mTLS, webhooks, email security, WebSocket, GraphQL, gRPC, SSE. |
| [`vuln_db`](modules/vuln_db.md) | Opt-in | 4 | Offline CVE/CWE lookup, full CVSS calculator, MITRE ATT&CK mapping. |
| [`incident`](modules/incident.md) | Opt-in | 7 | Audit logging, IR playbooks, security.txt, advisories, SIEM, disclosure. |
| [`testing`](modules/testing.md) | Opt-in | 7 | Fuzz/SAST/IAST config, pentest & red-team scoping, chaos, test generation. |
| [`sdlc`](modules/sdlc.md) | Opt-in | 8 | Pre-commit, CI/CD gates, review checklists, release integrity, SLSA, CODEOWNERS. |
| [`ml_security`](modules/ml_security.md) | Opt-in | 8 | ML pipelines, inference APIs, model supply chain, OWASP ML & LLM Top 10. |
| [`agentic`](modules/agentic.md) | Opt-in | 10 | OWASP Agentic Applications Security Top 10 (ASI01-ASI10). |
| [`runtime`](modules/runtime.md) | Opt-in | 3 | WAF rule generation, RASP recommendations, monitoring coverage. |

## All tools

Every tool has its own reference page.

### [`core`](modules/core.md)

- [`altais_get_config`](tools/altais_get_config.md)
- [`altais_explain_cwe`](tools/altais_explain_cwe.md)
- [`altais_score`](tools/altais_score.md)
- [`altais_report`](tools/altais_report.md)
- [`altais_risk_summary`](tools/altais_risk_summary.md)

### [`scan`](modules/scan.md)

- [`altais_scan_code`](tools/altais_scan_code.md)
- [`altais_scan_file`](tools/altais_scan_file.md)
- [`altais_scan_diff`](tools/altais_scan_diff.md)

### [`secrets`](modules/secrets.md)

- [`altais_scan_secrets`](tools/altais_scan_secrets.md)
- [`altais_scan_entropy`](tools/altais_scan_entropy.md)
- [`altais_scan_git_secrets`](tools/altais_scan_git_secrets.md)

### [`headers`](modules/headers.md)

- [`altais_audit_headers`](tools/altais_audit_headers.md)
- [`altais_generate_csp`](tools/altais_generate_csp.md)
- [`altais_check_cors`](tools/altais_check_cors.md)

### [`threat_model`](modules/threat_model.md)

- [`altais_stride`](tools/altais_stride.md)
- [`altais_dread`](tools/altais_dread.md)
- [`altais_attack_tree`](tools/altais_attack_tree.md)
- [`altais_trust_boundaries`](tools/altais_trust_boundaries.md)

### [`owasp`](modules/owasp.md)

- [`altais_check_owasp_web`](tools/altais_check_owasp_web.md)
- [`altais_check_owasp_api`](tools/altais_check_owasp_api.md)
- [`altais_check_owasp_mobile`](tools/altais_check_owasp_mobile.md)
- [`altais_check_owasp_serverless`](tools/altais_check_owasp_serverless.md)
- [`altais_check_asvs`](tools/altais_check_asvs.md)

### [`supply_chain`](modules/supply_chain.md)

- [`altais_audit_deps`](tools/altais_audit_deps.md)
- [`altais_generate_sbom`](tools/altais_generate_sbom.md)
- [`altais_check_licenses`](tools/altais_check_licenses.md)
- [`altais_detect_typosquat`](tools/altais_detect_typosquat.md)
- [`altais_verify_slsa`](tools/altais_verify_slsa.md)
- [`altais_verify_signatures`](tools/altais_verify_signatures.md)
- [`altais_check_dependency_confusion`](tools/altais_check_dependency_confusion.md)
- [`altais_generate_vex`](tools/altais_generate_vex.md)
- [`altais_check_build_integrity`](tools/altais_check_build_integrity.md)
- [`altais_audit_registry`](tools/altais_audit_registry.md)

### [`auth`](modules/auth.md)

- [`altais_audit_oauth`](tools/altais_audit_oauth.md)
- [`altais_audit_jwt`](tools/altais_audit_jwt.md)
- [`altais_audit_session`](tools/altais_audit_session.md)
- [`altais_audit_csrf`](tools/altais_audit_csrf.md)
- [`altais_audit_password_hashing`](tools/altais_audit_password_hashing.md)
- [`altais_audit_rbac`](tools/altais_audit_rbac.md)
- [`altais_audit_passkey_impl`](tools/altais_audit_passkey_impl.md)
- [`altais_audit_nhi`](tools/altais_audit_nhi.md)
- [`altais_check_secret_lifecycle`](tools/altais_check_secret_lifecycle.md)
- [`altais_check_nhi_isolation`](tools/altais_check_nhi_isolation.md)

### [`crypto`](modules/crypto.md)

- [`altais_audit_crypto`](tools/altais_audit_crypto.md)
- [`altais_audit_tls`](tools/altais_audit_tls.md)
- [`altais_audit_randomness`](tools/altais_audit_randomness.md)
- [`altais_audit_key_mgmt`](tools/altais_audit_key_mgmt.md)
- [`altais_assess_pq_readiness`](tools/altais_assess_pq_readiness.md)
- [`altais_audit_ct_logs`](tools/altais_audit_ct_logs.md)
- [`altais_audit_cert_pinning`](tools/altais_audit_cert_pinning.md)
- [`altais_audit_acme`](tools/altais_audit_acme.md)
- [`altais_assess_crypto_agility`](tools/altais_assess_crypto_agility.md)

### [`container`](modules/container.md)

- [`altais_audit_dockerfile`](tools/altais_audit_dockerfile.md)
- [`altais_audit_compose`](tools/altais_audit_compose.md)
- [`altais_check_base_image`](tools/altais_check_base_image.md)

### [`code`](modules/code.md)

- [`altais_review_secure_coding`](tools/altais_review_secure_coding.md)
- [`altais_audit_unsafe`](tools/altais_audit_unsafe.md)
- [`altais_check_error_handling`](tools/altais_check_error_handling.md)
- [`altais_check_input_validation`](tools/altais_check_input_validation.md)
- [`altais_check_memory_safety`](tools/altais_check_memory_safety.md)

### [`data`](modules/data.md)

- [`altais_detect_pii`](tools/altais_detect_pii.md)
- [`altais_classify_data`](tools/altais_classify_data.md)
- [`altais_audit_privacy`](tools/altais_audit_privacy.md)
- [`altais_check_retention`](tools/altais_check_retention.md)

### [`iac`](modules/iac.md)

- [`altais_audit_terraform`](tools/altais_audit_terraform.md)
- [`altais_audit_k8s_manifest`](tools/altais_audit_k8s_manifest.md)
- [`altais_audit_helm_chart`](tools/altais_audit_helm_chart.md)
- [`altais_check_policy_as_code`](tools/altais_check_policy_as_code.md)

### [`api`](modules/api.md)

- [`altais_audit_openapi_spec`](tools/altais_audit_openapi_spec.md)
- [`altais_audit_rate_limiting`](tools/altais_audit_rate_limiting.md)
- [`altais_audit_api_gateway`](tools/altais_audit_api_gateway.md)

### [`compliance`](modules/compliance.md)

- [`altais_map_findings`](tools/altais_map_findings.md)
- [`altais_gap_analysis`](tools/altais_gap_analysis.md)
- [`altais_generate_evidence`](tools/altais_generate_evidence.md)

### [`infra`](modules/infra.md)

- [`altais_audit_network`](tools/altais_audit_network.md)
- [`altais_audit_dns`](tools/altais_audit_dns.md)
- [`altais_check_zero_trust`](tools/altais_check_zero_trust.md)
- [`altais_check_hardening`](tools/altais_check_hardening.md)

### [`protocol`](modules/protocol.md)

- [`altais_audit_tls_config`](tools/altais_audit_tls_config.md)
- [`altais_check_webhook`](tools/altais_check_webhook.md)
- [`altais_audit_email_security`](tools/altais_audit_email_security.md)
- [`altais_audit_websocket`](tools/altais_audit_websocket.md)
- [`altais_audit_graphql`](tools/altais_audit_graphql.md)
- [`altais_audit_grpc`](tools/altais_audit_grpc.md)
- [`altais_audit_sse`](tools/altais_audit_sse.md)

### [`vuln_db`](modules/vuln_db.md)

- [`altais_lookup_cve`](tools/altais_lookup_cve.md)
- [`altais_lookup_cwe`](tools/altais_lookup_cwe.md)
- [`altais_calculate_cvss`](tools/altais_calculate_cvss.md)
- [`altais_map_attack`](tools/altais_map_attack.md)

### [`incident`](modules/incident.md)

- [`altais_audit_logging`](tools/altais_audit_logging.md)
- [`altais_generate_playbook`](tools/altais_generate_playbook.md)
- [`altais_generate_security_txt`](tools/altais_generate_security_txt.md)
- [`altais_draft_advisory`](tools/altais_draft_advisory.md)
- [`altais_check_canary`](tools/altais_check_canary.md)
- [`altais_recommend_siem`](tools/altais_recommend_siem.md)
- [`altais_generate_disclosure_program`](tools/altais_generate_disclosure_program.md)

### [`testing`](modules/testing.md)

- [`altais_generate_fuzz_config`](tools/altais_generate_fuzz_config.md)
- [`altais_generate_sast_config`](tools/altais_generate_sast_config.md)
- [`altais_generate_pentest_scope`](tools/altais_generate_pentest_scope.md)
- [`altais_generate_security_tests`](tools/altais_generate_security_tests.md)
- [`altais_generate_chaos_config`](tools/altais_generate_chaos_config.md)
- [`altais_scope_red_team`](tools/altais_scope_red_team.md)
- [`altais_generate_iast_config`](tools/altais_generate_iast_config.md)

### [`sdlc`](modules/sdlc.md)

- [`altais_generate_precommit`](tools/altais_generate_precommit.md)
- [`altais_audit_ci_cd`](tools/altais_audit_ci_cd.md)
- [`altais_generate_review_checklist`](tools/altais_generate_review_checklist.md)
- [`altais_check_release_integrity`](tools/altais_check_release_integrity.md)
- [`altais_check_signed_commits`](tools/altais_check_signed_commits.md)
- [`altais_audit_branch_protection`](tools/altais_audit_branch_protection.md)
- [`altais_assess_slsa_level`](tools/altais_assess_slsa_level.md)
- [`altais_check_codeowners`](tools/altais_check_codeowners.md)

### [`ml_security`](modules/ml_security.md)

- [`altais_audit_ml_pipeline`](tools/altais_audit_ml_pipeline.md)
- [`altais_audit_inference_api`](tools/altais_audit_inference_api.md)
- [`altais_audit_model_supply_chain`](tools/altais_audit_model_supply_chain.md)
- [`altais_check_owasp_ml`](tools/altais_check_owasp_ml.md)
- [`altais_check_llm_top10`](tools/altais_check_llm_top10.md)
- [`altais_audit_prompt_injection`](tools/altais_audit_prompt_injection.md)
- [`altais_audit_agent_permissions`](tools/altais_audit_agent_permissions.md)
- [`altais_audit_output_handling`](tools/altais_audit_output_handling.md)

### [`agentic`](modules/agentic.md)

- [`altais_audit_goal_hijack`](tools/altais_audit_goal_hijack.md)
- [`altais_audit_tool_misuse`](tools/altais_audit_tool_misuse.md)
- [`altais_audit_agent_identity`](tools/altais_audit_agent_identity.md)
- [`altais_audit_agentic_supply_chain`](tools/altais_audit_agentic_supply_chain.md)
- [`altais_audit_code_execution`](tools/altais_audit_code_execution.md)
- [`altais_audit_memory_poisoning`](tools/altais_audit_memory_poisoning.md)
- [`altais_audit_inter_agent_comms`](tools/altais_audit_inter_agent_comms.md)
- [`altais_audit_cascading_failures`](tools/altais_audit_cascading_failures.md)
- [`altais_audit_trust_exploitation`](tools/altais_audit_trust_exploitation.md)
- [`altais_audit_rogue_agents`](tools/altais_audit_rogue_agents.md)

### [`runtime`](modules/runtime.md)

- [`altais_generate_waf_rules`](tools/altais_generate_waf_rules.md)
- [`altais_recommend_rasp`](tools/altais_recommend_rasp.md)
- [`altais_audit_monitoring`](tools/altais_audit_monitoring.md)

---

_This wiki is generated for altais-mcp v1.0.2. Tool and module pages are kept in `wiki/tools/` and `wiki/modules/`._
