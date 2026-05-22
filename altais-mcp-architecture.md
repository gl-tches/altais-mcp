# altais-mcp — Architecture Document

## Overview

A modular, open-source MCP server that provides comprehensive security analysis for any AI coding agent. Developers deploy it and enable only the modules they need via configuration. Agents call tools to scan code, model threats, audit dependencies, verify compliance, and generate remediation guidance.

**Language**: TypeScript (MCP SDK ecosystem, agent compatibility, Zod schemas)  
**Transport**: stdio (local/Claude Code) + streamable HTTP (remote/multi-agent)  
**License**: MIT  
**Package**: `altais-mcp` (npm)  
**Repository**: `altais-mcp`

---

## Design Principles

1. **Modular** — each security domain is an independent module with its own tools, loadable at startup via config
2. **Agent-native** — tools return structured findings with severity, CWE IDs, remediation steps, and references so agents can act on results without human interpretation
3. **Zero external dependencies at runtime** — no SaaS APIs required; all analysis runs locally against source code and configs passed in by the agent
4. **Opinionated defaults** — ships with a sensible default module set; advanced modules opt-in
5. **Composable** — modules can reference each other's findings (e.g., compliance module maps scan findings to NIST controls)

---

## Configuration

```toml
# altais.config.toml

[server]
name = "altais-mcp"
transport = "stdio"           # "stdio" | "http"
port = 3100                   # only used with http transport
log_level = "info"

[modules]
# Core (always loaded, cannot be disabled)
# core = true

# Default modules (enabled out of the box)
scan = true
threat_model = true
owasp = true
secrets = true
headers = true
supply_chain = true           # formerly "deps" — expanded per OWASP A03:2025
auth = true

# Opt-in modules
crypto = false
container = false
code = false
data = false
compliance = false
infra = false
protocol = false
incident = false
testing = false
vuln_db = false
ml_security = false
sdlc = false
iac = false
agentic = false
api = false
runtime = false
database = false

[scan]
max_file_size_kb = 512
exclude_patterns = ["node_modules", "dist", ".git", "vendor"]
languages = ["typescript", "javascript", "python", "rust", "go"]

[supply_chain]
check_licenses = true
cvss_threshold = 7.0          # minimum CVSS to flag
sbom_format = "cyclonedx"     # "cyclonedx" | "spdx"
slsa_level = 2                # minimum acceptable SLSA Build Track level (1-3, per v1.2)
verify_signatures = true
max_dependency_age_days = 30  # flag deps published < 30 days ago

[compliance]
frameworks = ["owasp-asvs", "nist-800-53", "nist-ssdf", "cisa-sbd", "nis2"]

[severity]
critical_cvss_min = 9.0
high_cvss_min = 7.0
medium_cvss_min = 4.0

[iac]
providers = ["terraform", "kubernetes", "docker-compose"]
k8s_pod_security_level = "restricted"  # "baseline" | "restricted" | "privileged"

[agentic]
check_goal_hijack = true       # ASI01
check_tool_misuse = true       # ASI02
check_identity_abuse = true    # ASI03
check_supply_chain = true      # ASI04
check_code_execution = true    # ASI05
check_memory_poisoning = true  # ASI06
check_inter_agent = true       # ASI07
check_cascading = true         # ASI08
check_trust_exploitation = true # ASI09
check_rogue_agents = true      # ASI10

[database]
drivers = ["postgres", "mysql", "mongodb", "redis", "sqlite", "mssql", "elasticsearch", "dynamodb"]
check_connection_strings = true
check_parameterization = true
check_migrations = true
check_backup = true
check_nosql_injection = true
```

---

## Module Architecture

```
altais-mcp/
├── src/
│   ├── index.ts                  # Server entry, module loader
│   ├── config.ts                 # Config parser (TOML)
│   ├── core/
│   │   ├── types.ts              # Shared types: Finding, Severity, CWE, etc.
│   │   ├── scoring.ts            # CVSS v3.1 + v4.0 calculator (Base/Threat/Environmental/Supplemental), risk scoring
│   │   ├── report.ts             # Finding aggregation, report generation
│   │   ├── registry.ts           # Module registry, tool registration
│   │   └── utils.ts              # File parsing, pattern matching helpers
│   ├── modules/
│   │   ├── scan/
│   │   │   ├── index.ts
│   │   │   ├── patterns/
│   │   │   │   ├── injection.ts
│   │   │   │   ├── xss.ts
│   │   │   │   ├── ssrf.ts              # SSRF now under access control per A01:2025
│   │   │   │   ├── path-traversal.ts
│   │   │   │   ├── prototype-pollution.ts
│   │   │   │   ├── ssti.ts
│   │   │   │   ├── redos.ts
│   │   │   │   ├── race-condition.ts
│   │   │   │   ├── deserialization.ts
│   │   │   │   ├── business-logic.ts
│   │   │   │   ├── exceptional-conditions.ts  # A10:2025 — fail-open, stack trace leakage, unhandled exceptions
│   │   │   │   ├── request-smuggling.ts
│   │   │   │   ├── cache-poisoning.ts
│   │   │   │   ├── crlf-injection.ts
│   │   │   │   └── host-header-injection.ts
│   │   │   └── analyzers/
│   │   │       ├── typescript.ts
│   │   │       ├── python.ts
│   │   │       ├── rust.ts
│   │   │       └── go.ts
│   │   ├── threat-model/
│   │   │   ├── index.ts
│   │   │   ├── stride.ts
│   │   │   ├── dread.ts
│   │   │   ├── attack-tree.ts
│   │   │   └── trust-boundary.ts
│   │   ├── owasp/
│   │   │   ├── index.ts
│   │   │   ├── web-top10.ts              # OWASP Top 10:2025 (confirmed January 2026)
│   │   │   ├── api-top10.ts              # OWASP API Security Top 10 (2023, current)
│   │   │   ├── mobile-top10.ts           # OWASP Mobile Top 10 (2024)
│   │   │   ├── serverless-top10.ts
│   │   │   ├── ml-top10.ts               # Loaded only if ml_security also enabled
│   │   │   ├── llm-top10.ts              # OWASP LLM Top 10 (2025)
│   │   │   ├── nhi-top10.ts              # OWASP Non-Human Identities Top 10 (2025)
│   │   │   └── agentic-top10.ts          # OWASP Agentic Applications Top 10 (2026)
│   │   ├── secrets/
│   │   │   ├── index.ts
│   │   │   ├── patterns.ts
│   │   │   ├── entropy.ts
│   │   │   └── git-history.ts
│   │   ├── headers/
│   │   │   ├── index.ts
│   │   │   ├── csp.ts
│   │   │   ├── cors.ts
│   │   │   ├── hsts.ts
│   │   │   └── meta.ts
│   │   ├── supply-chain/                 # Expanded from "deps" — matches A03:2025
│   │   │   ├── index.ts
│   │   │   ├── lockfile.ts
│   │   │   ├── cve-check.ts              # CVE database lookup (local OSV DB)
│   │   │   ├── sbom.ts                   # CycloneDX / SPDX generation
│   │   │   ├── license.ts
│   │   │   ├── typosquat.ts
│   │   │   ├── slsa.ts                   # SLSA v1.2 provenance attestation verification (Build Track + Source Track)
│   │   │   ├── signatures.ts             # sigstore/cosign, GPG signature verification
│   │   │   ├── confusion.ts              # Dependency confusion / substitution detection
│   │   │   ├── vex.ts                    # VEX statement generation
│   │   │   ├── build-integrity.ts        # Build pipeline tamper detection
│   │   │   └── registry.ts               # Package registry configuration audit
│   │   ├── auth/
│   │   │   ├── index.ts
│   │   │   ├── oauth.ts
│   │   │   ├── jwt.ts
│   │   │   ├── session.ts
│   │   │   ├── csrf.ts
│   │   │   ├── password.ts
│   │   │   ├── rbac.ts
│   │   │   ├── passkeys.ts              # FIDO2/passkey implementation audit (A07:2025)
│   │   │   ├── nhi.ts                   # Non-human identity lifecycle audit
│   │   │   ├── nhi-isolation.ts         # Environment isolation for service accounts
│   │   │   └── credential-stuffing.ts   # Rate limiting + account enumeration checks
│   │   ├── crypto/
│   │   │   ├── index.ts
│   │   │   ├── algorithms.ts
│   │   │   ├── tls.ts
│   │   │   ├── key-mgmt.ts
│   │   │   ├── randomness.ts
│   │   │   ├── post-quantum.ts
│   │   │   ├── ct-monitoring.ts         # Certificate transparency log monitoring
│   │   │   ├── cert-pinning.ts          # HPKP successor patterns
│   │   │   ├── acme.ts                  # ACME / Let's Encrypt config review
│   │   │   └── agility.ts              # Cryptographic agility assessment
│   │   ├── container/
│   │   │   ├── index.ts
│   │   │   ├── dockerfile.ts
│   │   │   ├── compose.ts
│   │   │   ├── secrets.ts
│   │   │   ├── image.ts
│   │   │   ├── k8s-pod-security.ts      # Pod Security Standards, NetworkPolicy
│   │   │   ├── k8s-serviceaccount.ts    # Token automounting, privilege detection
│   │   │   └── image-provenance.ts      # cosign/sigstore, distroless, multi-stage
│   │   ├── code/
│   │   │   ├── index.ts
│   │   │   ├── cert/
│   │   │   │   ├── c-cpp.ts
│   │   │   │   ├── java.ts
│   │   │   │   ├── python.ts
│   │   │   │   └── rust.ts
│   │   │   ├── memory-safety.ts
│   │   │   ├── error-handling.ts
│   │   │   └── input-validation.ts
│   │   ├── data/
│   │   │   ├── index.ts
│   │   │   ├── pii.ts
│   │   │   ├── classification.ts
│   │   │   ├── privacy.ts
│   │   │   └── retention.ts
│   │   ├── compliance/
│   │   │   ├── index.ts
│   │   │   ├── mapper.ts
│   │   │   ├── frameworks/
│   │   │   │   ├── owasp-asvs.ts
│   │   │   │   ├── owasp-samm.ts        # Software Assurance Maturity Model
│   │   │   │   ├── owasp-dsomm.ts       # DevSecOps Maturity Model
│   │   │   │   ├── nist-800-53.ts
│   │   │   │   ├── nist-ssdf.ts
│   │   │   │   ├── nist-ai-rmf.ts       # AI Risk Management Framework
│   │   │   │   ├── iso-27001.ts
│   │   │   │   ├── soc2.ts
│   │   │   │   ├── gdpr.ts
│   │   │   │   ├── pci-dss.ts            # PCI-DSS v4.0.1 (mandatory since March 2025)
│   │   │   │   ├── openssf.ts
│   │   │   │   ├── nis2.ts              # EU Network and Information Security Directive
│   │   │   │   ├── dora.ts              # EU Digital Operational Resilience Act
│   │   │   │   ├── cra.ts               # EU Cyber Resilience Act
│   │   │   │   ├── cisa-sbd.ts          # CISA Secure by Design
│   │   │   │   ├── eo-14028.ts          # US Executive Order on Cybersecurity
│   │   │   │   └── fda-524b.ts          # Medical device software
│   │   │   └── report.ts
│   │   ├── infra/
│   │   │   ├── index.ts
│   │   │   ├── zero-trust.ts
│   │   │   ├── network.ts
│   │   │   ├── dns.ts
│   │   │   └── hardening.ts
│   │   ├── protocol/
│   │   │   ├── index.ts
│   │   │   ├── tls.ts
│   │   │   ├── webhook.ts
│   │   │   ├── email.ts
│   │   │   ├── websocket.ts
│   │   │   ├── graphql.ts
│   │   │   ├── grpc.ts                  # TLS, auth interceptors, deadline propagation
│   │   │   ├── sse.ts                   # Server-Sent Events security
│   │   │   └── mcp-transport.ts         # MCP-specific transport security
│   │   ├── incident/
│   │   │   ├── index.ts
│   │   │   ├── logging.ts
│   │   │   ├── playbook.ts
│   │   │   ├── security-txt.ts
│   │   │   ├── advisory.ts
│   │   │   ├── canary.ts               # Canary tokens / honeypot detection
│   │   │   ├── siem.ts                 # SIEM integration guidance
│   │   │   └── disclosure.ts           # Vulnerability disclosure program + bug bounty
│   │   ├── testing/
│   │   │   ├── index.ts
│   │   │   ├── fuzz.ts
│   │   │   ├── sast.ts
│   │   │   ├── dast.ts
│   │   │   ├── pentest.ts
│   │   │   ├── chaos.ts               # Security chaos engineering
│   │   │   ├── red-team.ts            # Full adversary simulation scoping
│   │   │   └── iast.ts                # Interactive Application Security Testing
│   │   ├── vuln-db/
│   │   │   ├── index.ts
│   │   │   ├── cwe.ts
│   │   │   ├── cvss.ts                # CVSS v3.1 + v4.0 (four metric groups in v4.0)
│   │   │   ├── remediation.ts
│   │   │   └── mitre.ts
│   │   ├── ml-security/
│   │   │   ├── index.ts
│   │   │   ├── model-security.ts
│   │   │   ├── data-pipeline.ts
│   │   │   ├── inference.ts
│   │   │   ├── supply-chain.ts
│   │   │   ├── llm-top10.ts           # OWASP LLM Top 10 checks
│   │   │   ├── prompt-injection.ts    # Prompt injection analysis
│   │   │   ├── agent-permissions.ts   # Excessive agency checks
│   │   │   └── output-handling.ts     # Output sanitization verification
│   │   ├── sdlc/
│   │   │   ├── index.ts
│   │   │   ├── ci-cd.ts
│   │   │   ├── pre-commit.ts
│   │   │   ├── review.ts
│   │   │   ├── release.ts
│   │   │   ├── signed-commits.ts      # GPG / SSH commit signing
│   │   │   ├── branch-protection.ts   # Required reviews, status checks, force push
│   │   │   ├── slsa-assessment.ts     # SLSA level assessment
│   │   │   └── codeowners.ts          # Security-sensitive path reviewer verification
│   │   ├── iac/                        # NEW MODULE
│   │   │   ├── index.ts
│   │   │   ├── terraform.ts
│   │   │   ├── kubernetes.ts
│   │   │   ├── helm.ts
│   │   │   ├── cloudformation.ts
│   │   │   ├── docker-compose.ts
│   │   │   └── policy.ts             # OPA/Rego, Kyverno
│   │   ├── agentic/                    # NEW MODULE — OWASP Agentic Top 10 (2026)
│   │   │   ├── index.ts
│   │   │   ├── goal-hijack.ts          # ASI01: Agent Goal Hijack
│   │   │   ├── tool-misuse.ts          # ASI02: Tool Misuse & Exploitation
│   │   │   ├── identity-privilege.ts   # ASI03: Identity & Privilege Abuse
│   │   │   ├── supply-chain.ts         # ASI04: Agentic Supply Chain Vulnerabilities
│   │   │   ├── code-execution.ts       # ASI05: Unexpected Code Execution
│   │   │   ├── memory-poisoning.ts     # ASI06: Memory & Context Poisoning
│   │   │   ├── inter-agent.ts          # ASI07: Insecure Inter-Agent Communication
│   │   │   ├── cascading.ts            # ASI08: Cascading Agent Failures
│   │   │   ├── trust-exploitation.ts   # ASI09: Human-Agent Trust Exploitation
│   │   │   └── rogue-agents.ts         # ASI10: Rogue Agents
│   │   ├── api/                        # NEW MODULE
│   │   │   ├── index.ts
│   │   │   ├── openapi.ts
│   │   │   ├── rate-limiting.ts
│   │   │   ├── schema.ts
│   │   │   ├── versioning.ts
│   │   │   ├── gateway.ts
│   │   │   └── pagination.ts
│   │   ├── runtime/                    # NEW MODULE
│   │   │   ├── index.ts
│   │   │   ├── rasp.ts
│   │   │   ├── waf.ts
│   │   │   ├── sbom-runtime.ts
│   │   │   └── monitoring.ts
│   │   └── database/                   # NEW MODULE
│   │       ├── index.ts
│   │       ├── finding.ts
│   │       ├── connection.ts
│   │       ├── queries.ts
│   │       ├── postgres.ts
│   │       ├── mysql.ts
│   │       ├── mongodb.ts
│   │       ├── redis.ts
│   │       ├── sqlite.ts
│   │       ├── mssql.ts
│   │       ├── elasticsearch.ts
│   │       ├── dynamodb.ts
│   │       ├── pooling.ts
│   │       ├── migrations.ts
│   │       ├── backup.ts
│   │       ├── nosql-injection.ts
│   │       ├── tls.ts
│   │       └── logging.ts
│   └── data/
│       ├── cwe-database.json
│       ├── secret-patterns.json
│       └── owasp-controls.json         # Updated to 2025 mappings
├── altais.config.toml
├── package.json
├── tsconfig.json
└── README.md
```

---

## Core Types

```typescript
// core/types.ts

export type Severity = "critical" | "high" | "medium" | "low" | "info";

export type FindingStatus = "open" | "confirmed" | "false_positive" | "mitigated";

export interface Finding {
  id: string;                       // unique finding ID: {module}:{rule}:{hash}
  module: string;
  rule: string;
  severity: Severity;
  cvss?: number;                    // CVSS 3.1 or 4.0 score
  cvss_version?: "3.1" | "4.0";    // Which CVSS version was used
  cwe?: string[];                   // CWE IDs (e.g., ["CWE-79", "CWE-116"])
  title: string;
  description: string;
  location?: FindingLocation;
  evidence?: string;
  remediation: string;
  references: string[];
  tags: string[];                   // ["owasp:a03", "nist:ac-6", "pci:6.5.1"]
  status: FindingStatus;
}

export interface FindingLocation {
  file: string;
  line_start: number;
  line_end?: number;
  column?: number;
}

export interface ScanResult {
  findings: Finding[];
  summary: ScanSummary;
  metadata: ScanMetadata;
}

export interface ScanSummary {
  total: number;
  by_severity: Record<Severity, number>;
  by_module: Record<string, number>;
  risk_score: number;               // 0-100 composite risk score
}

export interface ScanMetadata {
  scanned_at: string;               // ISO 8601
  duration_ms: number;
  files_scanned: number;
  modules_active: string[];
  config_hash: string;
}

export interface ModuleDefinition {
  name: string;
  description: string;
  version: string;
  dependencies?: string[];
  tools: ToolDefinition[];
  init: (config: ModuleConfig) => Promise<void>;
}
```

---

## OWASP Top 10:2025 (Web)

The `owasp/web-top10.ts` module targets the 2025 edition. Announced November 2025 at OWASP Global AppSec (Washington, D.C.), final version released January 2026. Based on 175,000+ CVEs and 248 mapped CWEs across 515k+ applications.

| # | Category | Change from 2021 |
|---|----------|-----------------|
| A01 | Broken Access Control | Stays #1. SSRF consolidated here (was A10 in 2021) |
| A02 | Security Misconfiguration | Moved up from #5. Cloud-specific misconfigs added |
| A03 | Software Supply Chain Failures | NEW — replaces "Vulnerable and Outdated Components." Covers dependencies, build systems, distribution |
| A04 | Cryptographic Failures | Was #2, dropped to #4 |
| A05 | Injection | Was #3, dropped to #5 |
| A06 | Insecure Design | Was #4, dropped to #6 |
| A07 | Authentication Failures | Renamed. FIDO2/passkeys now expected |
| A08 | Software and Data Integrity Failures | Expanded CI/CD pipeline coverage |
| A09 | Security Logging & Alerting Failures | Renamed — emphasizes alerting, not just logging |
| A10 | Mishandling of Exceptional Conditions | NEW — improper error handling, failing open, unsafe fallback. 24 CWEs including CWE-209, CWE-476, CWE-636 |

---

## Additional OWASP Lists

### OWASP Top 10 for LLM Applications (2025)

Covered by `ml_security` module.

| # | Risk |
|---|------|
| LLM01 | Prompt Injection (direct and indirect) |
| LLM02 | Sensitive Information Disclosure |
| LLM03 | Supply Chain Vulnerabilities (model-specific) |
| LLM04 | Data and Model Poisoning |
| LLM05 | Improper Output Handling |
| LLM06 | Excessive Agency (functionality, permissions, autonomy) |
| LLM07 | System Prompt Leakage |
| LLM08 | Vector and Embedding Weaknesses |
| LLM09 | Misinformation |
| LLM10 | Unbounded Consumption |

### OWASP Top 10 for Agentic Applications (2026)

Covered by `agentic` module. Core principles: **Least Agency** (minimum autonomy required for the task) and **Strong Observability** (comprehensive logging of goal state, tool-use patterns, decision pathways).

| # | Risk | Description |
|---|------|-------------|
| ASI01 | Agent Goal Hijack | Attacker manipulates agent objectives, task selection, or decision pathways via prompt injection, deceptive tool outputs, poisoned data, or forged inter-agent messages |
| ASI02 | Tool Misuse & Exploitation | Agent uses authorized tools in unsafe/unintended ways — deleting data, over-invoking costly APIs, exfiltrating information. Includes tool poisoning via corrupted MCP descriptors/schemas |
| ASI03 | Identity & Privilege Abuse | Agents inherit, misuse, or retain privileges improperly across sessions, users, or delegated workflows. Confused deputy attacks, cross-user data leaks |
| ASI04 | Agentic Supply Chain Vulnerabilities | Compromised third-party tools, plugins, MCP servers, agent cards, or dynamic runtime components. Rug pulls, typosquatting, unsigned manifests |
| ASI05 | Unexpected Code Execution | Agent generates, modifies, or runs code/commands creating security or operational risk. Natural-language execution paths enabling RCE |
| ASI06 | Memory & Context Poisoning | Retrieved or stored context is poisoned, misleading, stale, or tampered with, influencing future agent behavior across sessions |
| ASI07 | Insecure Inter-Agent Communication | Spoofed, tampered, or unauthenticated messages between agents misdirecting workflows or injecting malicious instructions |
| ASI08 | Cascading Agent Failures | Failure in one agent propagates across multi-agent systems. Hallucinations spreading like contagion, amplifying minor errors into systemic failures |
| ASI09 | Human-Agent Trust Exploitation | Attackers exploit human trust in fluent, persuasive agents to induce approval of malicious actions or disclosure of sensitive data |
| ASI10 | Rogue Agents | Compromised or misaligned agents acting harmfully while appearing legitimate. Self-repeating actions, persistent exfiltration, silent approval of unsafe operations |

### OWASP Non-Human Identities (NHI) Top 10 (2025)

Covered by `auth` module (NHI tools).

| # | Risk |
|---|------|
| NHI1 | Improper Offboarding |
| NHI2 | Secret Leakage |
| NHI3 | Vulnerable Third-Party NHI |
| NHI4 | Insecure Authentication |
| NHI5 | Overprivileged NHI |
| NHI6 | Insecure Cloud Deployment Configurations |
| NHI7 | Long-Lived Secrets |
| NHI8 | Environment Isolation |
| NHI9 | NHI Reuse |
| NHI10 | Human Use of NHI |

### OWASP Agentic Skills Top 10 (March 2026)

Tracked for integration into the `agentic` module as it matures. Covers skill supply-chain security, provenance tracking, permission manifests, and shadow AI / unauthorized agent deployment.

---

## Module → Tool Mapping

### core (always loaded)

| Tool | Description |
|------|-------------|
| `altais_get_config` | Return current module configuration and active modules |
| `altais_report` | Generate aggregated security report from all findings in current session |
| `altais_score` | Calculate CVSS v3.1/v4.0 score from vector string or individual metrics |
| `altais_explain_cwe` | Look up CWE by ID, return description, examples, and remediation |
| `altais_risk_summary` | Return composite risk score and top findings from a scan result |

### scan

| Tool | Description |
|------|-------------|
| `altais_scan_code` | Analyze source code for security vulnerabilities. Returns findings with CWE, severity, location, remediation |
| `altais_scan_file` | Scan a single file by path for all enabled vulnerability patterns |
| `altais_scan_diff` | Scan a git diff for newly introduced security issues only |

### threat_model

| Tool | Description |
|------|-------------|
| `altais_stride` | Generate STRIDE threat model from architecture description |
| `altais_dread` | Score a threat using DREAD metrics |
| `altais_attack_tree` | Generate attack tree for a given asset or threat scenario |
| `altais_trust_boundaries` | Identify and annotate trust boundary crossings |

### owasp

| Tool | Description |
|------|-------------|
| `altais_check_owasp_web` | Check against OWASP Web Top 10 (2025) |
| `altais_check_owasp_api` | Check API implementation against OWASP API Security Top 10 (2023, current as of 2026) |
| `altais_check_owasp_mobile` | Check mobile app code against OWASP Mobile Top 10 (2024) |
| `altais_check_owasp_serverless` | Check serverless function against OWASP Serverless Top 10 |
| `altais_check_asvs` | Verify code against OWASP ASVS controls at specified level (1/2/3) |

### secrets

| Tool | Description |
|------|-------------|
| `altais_scan_secrets` | Detect hardcoded secrets, API keys, tokens, passwords in code |
| `altais_scan_entropy` | Find high-entropy strings that may be secrets |
| `altais_scan_git_secrets` | Scan git history for previously committed secrets |

### headers

| Tool | Description |
|------|-------------|
| `altais_audit_headers` | Audit HTTP security headers from a header map or server config |
| `altais_generate_csp` | Generate Content-Security-Policy for given application requirements |
| `altais_check_cors` | Validate CORS configuration for overly permissive origins |

### supply_chain (formerly deps)

| Tool | Description |
|------|-------------|
| `altais_audit_deps` | Scan lockfile for known CVEs in dependencies |
| `altais_generate_sbom` | Generate SBOM (CycloneDX/SPDX) from lockfile |
| `altais_check_licenses` | Check dependency licenses against allowed/denied lists |
| `altais_detect_typosquat` | Check package names for potential typosquatting |
| `altais_verify_slsa` | Verify SLSA provenance attestations (v1.2 Build Track, levels 1-3) |
| `altais_verify_signatures` | Check artifact signatures (sigstore/cosign, GPG) |
| `altais_check_dependency_confusion` | Detect dependency confusion / substitution attack vectors |
| `altais_generate_vex` | Generate VEX (Vulnerability Exploitability eXchange) statements |
| `altais_check_build_integrity` | Verify build pipeline hasn't been tampered with |
| `altais_audit_registry` | Check package registry configuration security |

### auth

| Tool | Description |
|------|-------------|
| `altais_audit_oauth` | Review OAuth 2.1 / OIDC implementation |
| `altais_audit_jwt` | Analyze JWT implementation (algorithm, expiry, audience, claims) |
| `altais_audit_session` | Check session management (flags, rotation, invalidation, fixation) |
| `altais_audit_csrf` | Verify CSRF protection implementation |
| `altais_audit_password_hashing` | Check password hashing algorithm and parameters |
| `altais_audit_rbac` | Review RBAC/ABAC policy definitions for privilege escalation |
| `altais_audit_passkey_impl` | Audit FIDO2/passkey implementation (A07:2025) |
| `altais_audit_nhi` | Audit non-human identities against OWASP NHI Top 10 |
| `altais_check_secret_lifecycle` | Verify secret rotation, expiry, and revocation practices |
| `altais_check_nhi_isolation` | Verify environment isolation for service accounts and API keys |

### crypto

| Tool | Description |
|------|-------------|
| `altais_audit_crypto` | Audit cryptographic algorithm usage (weak ciphers, deprecated hashes) |
| `altais_audit_tls` | Review TLS configuration (protocol versions, cipher suites) |
| `altais_audit_randomness` | Detect insecure random number generation |
| `altais_audit_key_mgmt` | Review key storage, rotation, and lifecycle |
| `altais_assess_pq_readiness` | Assess post-quantum cryptography readiness |
| `altais_audit_ct_logs` | Certificate transparency log monitoring |
| `altais_audit_cert_pinning` | Certificate pinning audit (HPKP successor patterns) |
| `altais_audit_acme` | ACME / Let's Encrypt configuration review |
| `altais_assess_crypto_agility` | Can the system swap algorithms without code changes? |

### container

| Tool | Description |
|------|-------------|
| `altais_audit_dockerfile` | Analyze Dockerfile for security best practices |
| `altais_audit_compose` | Review Docker Compose file for security misconfigurations |
| `altais_check_base_image` | Assess base image for known issues and bloat |

### code

| Tool | Description |
|------|-------------|
| `altais_review_secure_coding` | Review code against CERT secure coding standards |
| `altais_audit_unsafe` | Audit Rust unsafe blocks for soundness issues |
| `altais_check_error_handling` | Detect error handling that leaks sensitive information |
| `altais_check_input_validation` | Verify input validation and sanitization patterns |
| `altais_check_memory_safety` | Detect memory safety issues in C/C++/Rust code |

### data

| Tool | Description |
|------|-------------|
| `altais_detect_pii` | Scan code and data for PII |
| `altais_classify_data` | Classify data fields by sensitivity level |
| `altais_audit_privacy` | Check implementation against privacy-by-design principles |
| `altais_check_retention` | Analyze data retention and deletion implementation |

### compliance

| Tool | Description |
|------|-------------|
| `altais_map_findings` | Map scan findings to compliance framework controls |
| `altais_gap_analysis` | Generate compliance gap report for specified framework |
| `altais_generate_evidence` | Generate evidence artifacts for compliance audits |

### infra

| Tool | Description |
|------|-------------|
| `altais_audit_network` | Review network segmentation and firewall rules |
| `altais_audit_dns` | Check DNS configuration security (DNSSEC, rebinding) |
| `altais_check_zero_trust` | Assess architecture against zero trust principles |
| `altais_check_hardening` | Check against CIS benchmark for specified platform |

### protocol

| Tool | Description |
|------|-------------|
| `altais_audit_tls_config` | Deep TLS/mTLS configuration audit |
| `altais_check_webhook` | Verify webhook HMAC signature implementation |
| `altais_audit_email_security` | Check SPF, DKIM, DMARC configuration |
| `altais_audit_websocket` | Review WebSocket security |
| `altais_audit_graphql` | Check GraphQL for introspection exposure, depth limits, batching |
| `altais_audit_grpc` | gRPC security (TLS, auth interceptors, deadline propagation) |
| `altais_audit_sse` | Server-Sent Events security (origin, reconnection) |

### incident

| Tool | Description |
|------|-------------|
| `altais_audit_logging` | Check audit trail completeness and log injection prevention |
| `altais_generate_playbook` | Generate incident response playbook for a threat scenario |
| `altais_generate_security_txt` | Generate security.txt and vulnerability disclosure policy |
| `altais_draft_advisory` | Draft security advisory in GHSA format |
| `altais_check_canary` | Canary token / honeypot detection |
| `altais_recommend_siem` | SIEM integration guidance (Splunk, CloudWatch, etc.) |
| `altais_generate_disclosure_program` | Vulnerability disclosure + bug bounty program template |

### testing

| Tool | Description |
|------|-------------|
| `altais_generate_fuzz_config` | Generate fuzz testing configuration |
| `altais_generate_sast_config` | Generate SAST tool configuration (semgrep, CodeQL) |
| `altais_generate_pentest_scope` | Generate penetration testing scope and checklist |
| `altais_generate_security_tests` | Generate security-focused unit/integration test cases |
| `altais_generate_chaos_config` | Security chaos engineering / fault injection |
| `altais_scope_red_team` | Red team / full adversary simulation scoping |
| `altais_generate_iast_config` | Interactive Application Security Testing setup |

### vuln_db

| Tool | Description |
|------|-------------|
| `altais_lookup_cve` | Look up CVE by ID with full details and remediation |
| `altais_lookup_cwe` | Full CWE taxonomy lookup with hierarchy |
| `altais_calculate_cvss` | CVSS v3.1/v4.0 score calculation (v4.0 uses Base+Threat+Environmental+Supplemental metric groups) |
| `altais_map_attack` | Map vulnerability to MITRE ATT&CK techniques |

### ml_security

| Tool | Description |
|------|-------------|
| `altais_audit_ml_pipeline` | Audit ML training pipeline for security issues |
| `altais_audit_inference_api` | Check inference API for model extraction, evasion |
| `altais_audit_model_supply_chain` | Verify model provenance, checkpoint integrity |
| `altais_check_owasp_ml` | Check against OWASP ML Security Top 10 |
| `altais_check_llm_top10` | Audit LLM application against OWASP LLM Top 10 |
| `altais_audit_prompt_injection` | Analyze prompt handling for injection vulnerabilities |
| `altais_audit_agent_permissions` | Check excessive agency (tool scope, permission levels) |
| `altais_audit_output_handling` | Verify output sanitization before downstream use |

### sdlc

| Tool | Description |
|------|-------------|
| `altais_generate_precommit` | Generate pre-commit hook configuration for security checks |
| `altais_audit_ci_cd` | Review CI/CD pipeline for security gates |
| `altais_generate_review_checklist` | Generate security-focused code review checklist |
| `altais_check_release_integrity` | Verify release process (signing, checksums, reproducible builds) |
| `altais_check_signed_commits` | GPG / SSH commit signing verification |
| `altais_audit_branch_protection` | Required reviews, status checks, force push protection |
| `altais_assess_slsa_level` | What SLSA v1.2 Build Track level does this project meet? (levels 1-3) |
| `altais_check_codeowners` | Verify security-sensitive paths have required reviewers |

### iac (NEW)

| Tool | Description |
|------|-------------|
| `altais_audit_terraform` | Scan Terraform HCL for security misconfigurations |
| `altais_audit_k8s_manifest` | Check Kubernetes manifests against pod security standards |
| `altais_audit_helm_chart` | Review Helm charts for security issues |
| `altais_check_policy_as_code` | Validate OPA/Rego or Kyverno policies |

### agentic (NEW)

| Tool | Description | Maps to |
|------|-------------|---------|
| `altais_audit_goal_hijack` | Analyze agent architecture for goal manipulation vectors (prompt injection, deceptive tool outputs, poisoned data) | ASI01 |
| `altais_audit_tool_misuse` | Check tool integration for misuse paths — over-permissioned APIs, tool poisoning via MCP descriptors, unsafe invocation patterns | ASI02 |
| `altais_audit_agent_identity` | Audit agent identity/privilege model for inheritance, escalation, confused deputy, and cross-session credential retention | ASI03 |
| `altais_audit_agentic_supply_chain` | Verify provenance of runtime MCP servers, plugins, agent cards, tool registries. Check for unsigned manifests and typosquatting | ASI04 |
| `altais_audit_code_execution` | Analyze agent code generation/execution paths for RCE risk. Sandbox verification, allowlist enforcement | ASI05 |
| `altais_audit_memory_poisoning` | Check for context/memory poisoning vectors across sessions, RAG pipelines, and shared state | ASI06 |
| `altais_audit_inter_agent_comms` | Verify agent-to-agent message authentication, integrity, and origin validation | ASI07 |
| `altais_audit_cascading_failures` | Analyze failure propagation paths in multi-agent systems. Blast-radius assessment, kill-switch verification | ASI08 |
| `altais_audit_trust_exploitation` | Check for human-agent trust exploitation vectors — consent separation, approval flow independence from agent UI | ASI09 |
| `altais_audit_rogue_agents` | Behavioral baseline verification, anomaly detection coverage, agent governance and sandboxing review | ASI10 |

### api (NEW)

| Tool | Description |
|------|-------------|
| `altais_audit_openapi_spec` | Validate OpenAPI spec for security gaps |
| `altais_audit_rate_limiting` | Check rate limiting implementation and configuration |
| `altais_audit_api_gateway` | Review API gateway security configuration |

### runtime (NEW)

| Tool | Description |
|------|-------------|
| `altais_generate_waf_rules` | Generate WAF rules based on scan findings |
| `altais_recommend_rasp` | Recommend RASP configuration based on application stack |
| `altais_audit_monitoring` | Check application monitoring for security event coverage |

### database (NEW)

| Tool | Description |
|------|-------------|
| `altais_audit_connection` | Audit database connection strings for embedded credentials, disabled TLS, and plaintext schemes |
| `altais_audit_queries` | Detect unsafe query construction across the supported ORMs and raw drivers |
| `altais_audit_postgres` | Audit a PostgreSQL / CockroachDB configuration (roles, RLS, pg_hba.conf, TLS, extensions) |
| `altais_audit_mysql` | Audit a MySQL / MariaDB configuration (privileges, skip-grant-tables, bind-address, sql_mode) |
| `altais_audit_mongodb` | Audit a MongoDB configuration (auth, bind_ip, SCRAM, journaling, roles) |
| `altais_audit_redis` | Audit a Redis / Memcached configuration (auth, ACLs, dangerous commands, protected-mode) |
| `altais_audit_sqlite` | Audit a SQLite configuration (file permissions, encryption, extension loading, ATTACH) |
| `altais_audit_mssql` | Audit a SQL Server configuration (sa account, xp_cmdshell, CLR, linked servers) |
| `altais_audit_elasticsearch` | Audit an Elasticsearch configuration (security plugin, anonymous access, TLS, scripting) |
| `altais_audit_dynamodb` | Audit an AWS DynamoDB configuration (encryption, PITR, VPC endpoints, IAM scoping) |
| `altais_audit_pooling` | Audit a connection-pool configuration (size, timeouts, leak detection, TLS) |
| `altais_audit_migrations` | Detect destructive or unsafe database migrations |
| `altais_audit_backup` | Audit a database backup configuration (encryption, retention, PITR, off-site copies) |
| `altais_audit_nosql_injection` | Detect NoSQL injection sinks (MongoDB operators, Elasticsearch, Redis) |
| `altais_audit_db_tls` | Audit a database's TLS / SSL configuration (protocol version, ciphers, certificate verification) |
| `altais_audit_db_logging` | Audit a database's audit-logging configuration |

---

## Module Registration Pattern

Each module exports a standard interface:

```typescript
// modules/scan/index.ts

import { ModuleDefinition } from "../../core/types.js";
import { z } from "zod";

export default {
  name: "scan",
  description: "Static analysis security scanning for source code",
  version: "1.0.0",
  dependencies: [],

  tools: [
    {
      name: "altais_scan_code",
      description: "Analyze source code for security vulnerabilities...",
      schema: z.object({
        code: z.string().describe("Source code to analyze"),
        language: z.enum(["typescript", "javascript", "python", "rust", "go"]),
        rules: z.array(z.string()).optional().describe("Specific rule IDs to check"),
      }),
      annotations: {
        readOnlyHint: true,
        destructiveHint: false,
        idempotentHint: true,
        openWorldHint: false,
      },
    },
    // ... more tools
  ],

  async init(config) {
    // load patterns, warm up analyzers
  },
} satisfies ModuleDefinition;
```

---

## Implementation Phases

### Phase 1 — Foundation (v0.1)
- Core framework: config loader, module registry, finding types, CVSS v3.1 + v4.0 scoring
- `scan` module: injection, XSS, SSRF, path traversal, exceptional conditions patterns for TS/Python
- `secrets` module: regex + entropy-based secret detection
- `headers` module: security header audit
- stdio transport
- README, config docs

**~14 tools**

### Phase 2 — Essentials (v0.2)
- `threat_model` module: STRIDE + DREAD
- `owasp` module: Web Top 10 (2025 edition) + API Top 10
- `supply_chain` module (expanded from deps): lockfile parsing, CVE check (OSV), SBOM, SLSA, VEX, dependency confusion, signature verification
- `auth` module: JWT, session, CSRF, password hashing, FIDO2/passkeys, NHI audit, credential stuffing
- Report generation (markdown + JSON output)

**~29 tools**

### Phase 3 — Depth (v0.3)
- `crypto` module: algorithm audit, TLS, randomness, PQ readiness, CT monitoring, crypto agility
- `container` module: Dockerfile, Compose, K8s pod security, image provenance
- `code` module: CERT standards, unsafe audit, memory safety
- `data` module: PII detection, classification
- `iac` module (NEW): Terraform, Kubernetes, Helm, CloudFormation, OPA/Rego
- `api` module (NEW): OpenAPI validation, rate limiting, gateway audit
- Streamable HTTP transport
- Add Go and Rust analyzer support in scan module

**~28 tools**

### Phase 4 — Enterprise (v0.4)
- `compliance` module: OWASP ASVS + SAMM + DSOMM, NIST 800-53 + SSDF + AI RMF, SOC 2, GDPR, NIS2, DORA, CRA, CISA SbD, PCI-DSS, EO 14028
- `infra` module: network, DNS, zero trust, CIS benchmarks
- `protocol` module: TLS, webhooks, email, WebSocket, GraphQL, gRPC, SSE, MCP transport
- `vuln_db` module: CWE/CVE lookup, CVSS v3.1/v4.0 calculator, ATT&CK mapping

**~18 tools**

### Phase 5 — Advanced (v0.5)
- `incident` module: logging audit, IR playbooks, security.txt, advisories, canary tokens, SIEM, disclosure programs
- `testing` module: fuzz config, SAST config, pentest scopes, security test gen, chaos engineering, red team, IAST
- `sdlc` module: pre-commit hooks, CI/CD gates, review checklists, release integrity, signed commits, branch protection, SLSA assessment, CODEOWNERS
- `ml_security` module: pipeline audit, inference API, model supply chain, LLM Top 10, prompt injection, agent permissions, output handling
- `agentic` module (NEW): Full OWASP Agentic Top 10 (ASI01–ASI10) coverage — goal hijack, tool misuse, identity/privilege abuse, supply chain, code execution, memory poisoning, inter-agent comms, cascading failures, trust exploitation, rogue agents
- `runtime` module (NEW): WAF rule generation, RASP recommendations, monitoring audit

**~43 tools**

### Phase 6 — Polish (v1.0)
- MCP Inspector integration tests
- Evaluation suite (10+ eval questions per module)
- npm publish as `altais-mcp`
- Documentation site
- `instructions` field in InitializeResult for Claude Code tool search discoverability

---

## Tool Count Summary

| Module | Tools | Phase |
|--------|-------|-------|
| core | 5 | 1 |
| scan | 3 | 1 |
| secrets | 3 | 1 |
| headers | 3 | 1 |
| threat_model | 4 | 2 |
| owasp | 5 | 2 |
| supply_chain | 10 | 2 |
| auth | 10 | 2 |
| crypto | 9 | 3 |
| container | 3 | 3 |
| code | 5 | 3 |
| data | 4 | 3 |
| iac | 4 | 3 |
| api | 3 | 3 |
| compliance | 3 | 4 |
| infra | 4 | 4 |
| protocol | 7 | 4 |
| vuln_db | 4 | 4 |
| incident | 7 | 5 |
| testing | 7 | 5 |
| sdlc | 8 | 5 |
| ml_security | 8 | 5 |
| agentic | 10 | 5 |
| runtime | 3 | 5 |
| database | 16 | 6 |
| **Total** | **148** | |

---

## Standards & Frameworks Coverage

**OWASP:**
- Web Top 10 (2025 edition — confirmed January 2026)
- API Security Top 10 (2023 — current as of 2026)
- Mobile Top 10 (2024)
- Serverless Top 10
- ML Top 10
- LLM Top 10 (2025)
- Agentic Applications Top 10 (2026 — ASI01–ASI10)
- Non-Human Identities Top 10 (2025)
- Agentic Skills Top 10 (March 2026) — tracked
- ASVS
- SAMM
- DSOMM

**NIST:**
- NIST 800-53
- NIST SSDF (Secure Software Development Framework)
- NIST AI RMF (AI Risk Management Framework)

**Supply Chain:**
- CycloneDX / SPDX SBOM
- OpenSSF Scorecard
- SLSA v1.2 (Build Track levels 1-3, Source Track)
- VEX (Vulnerability Exploitability eXchange)
- sigstore / cosign
- ML-BOM (Model Bill of Materials)

**Regulatory:**
- SOC 2
- ISO 27001
- GDPR
- PCI-DSS v4.0.1 (fully mandatory since March 2025)
- NIS2
- DORA
- CRA (EU Cyber Resilience Act)
- EO 14028
- FDA 524B

**Industry:**
- MITRE ATT&CK
- CWE
- CVSS v3.1 + v4.0 (NVD publishes both for new CVEs as of 2026; plan to handle dual scoring for 3-5 years)
- CISA Secure by Design
- CIS Benchmarks

**Database:**
- OWASP Database Security Cheat Sheet
- OWASP SQL Injection / NoSQL Injection Prevention Cheat Sheets
- Per-engine hardening guidance — PostgreSQL / CockroachDB, MySQL / MariaDB, MongoDB, Redis / Memcached, SQLite, SQL Server, Elasticsearch, AWS DynamoDB

---

## Notes

- The `instructions` field in MCP `InitializeResult` is critical for Claude Code discoverability — include a concise description of all active modules so Tool Search surfaces the right tools
- All tools are `readOnlyHint: true` — this MCP analyzes, it never modifies code
- Finding IDs are deterministic (module + rule + content hash) so duplicate scans don't produce duplicate findings
- The bundled CWE/pattern databases ship with the package — no network calls required at runtime
- Consider publishing each module as a separate npm package for tree-shaking: `@altais/core`, `@altais/scan`, `@altais/supply-chain`, etc.
- CVSS v4.0 support alongside v3.1 throughout — findings include `cvss_version` field. v4.0 uses four metric groups (Base, Threat, Environmental, Supplemental) replacing v3.1's three (Base, Temporal, Environmental). The `altais_score` tool handles both scoring systems.
