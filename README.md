# altais-mcp
> **Why "Altais"?** Altais (δ Draconis) is a star in the tail of Draco, the dragon constellation that wraps around the north celestial pole. In Greek mythology, Draco was the guardian that never slept. The name felt right for a security tool, something that sits quietly in the background, watching everything that passes through.

---

**altais-mcp** is a modular, open-source [Model Context Protocol](https://modelcontextprotocol.io) server that provides comprehensive security analysis for AI coding agents. It exposes 132 tools across 24 modules: agents call them to scan code, model threats, audit dependencies, verify compliance, and generate remediation guidance. Every tool is **read-only** (`readOnlyHint: true`) — altais-mcp analyzes code, configuration, and architecture; it never modifies, executes, or transmits the code it inspects.

- **License:** MIT
- **Language:** TypeScript (ES modules, strict mode)
- **SDK:** `@modelcontextprotocol/sdk`
- **Transports:** stdio (local / Claude Code) and streamable HTTP (remote / multi-agent)
- **Config format:** TOML (`altais.config.toml`)
- **Wiki:** [`wiki/Home.md`](./wiki/Home.md) — a reference page for every tool, plus [deployment](./wiki/Deployment.md) and [contributing](./wiki/Contributing.md) guides

altais-mcp performs static analysis and advisory generation only. It does not execute, `eval`, import, or dynamically load any code passed to it, and it makes no network calls at runtime — all CWE, OWASP, OSV, and pattern databases ship inside the package. See [`SECURITY.md`](./SECURITY.md) for the full security model.

---

## Installation

altais-mcp requires **Node.js >= 20** and nothing else — no native modules, no external services.

```bash
git clone https://github.com/gl-tches/altais-mcp.git
cd altais-mcp
npm install
npm run build
```

The build emits `dist/index.js`, which is the server entry point.

---

## Quick start

### stdio (local / Claude Code)

Add altais-mcp to your MCP client's server configuration, pointing at the built entry point. For Claude Code (`.mcp.json` or the client's MCP settings):

```json
{
  "mcpServers": {
    "altais": {
      "command": "node",
      "args": ["/absolute/path/to/altais-mcp/dist/index.js"]
    }
  }
}
```

To load a non-default configuration file, pass `--config`:

```json
{
  "mcpServers": {
    "altais": {
      "command": "node",
      "args": [
        "/absolute/path/to/altais-mcp/dist/index.js",
        "--config",
        "/absolute/path/to/altais.config.toml"
      ]
    }
  }
}
```

With no config file present, the server runs entirely on schema defaults (see [Configuration reference](#configuration-reference)).

### Streamable HTTP (remote / multi-agent)

Set `transport = "http"` in the `[server]` section of `altais.config.toml`, then start the server:

```bash
npm start
```

The HTTP transport:

- binds to **`127.0.0.1` only** — never `0.0.0.0`;
- validates the `Origin` header and enables DNS-rebinding protection;
- **requires a bearer token on every request.** The token is read from the `ALTAIS_HTTP_TOKEN` environment variable. If that variable is unset, the server generates a random ephemeral token at startup and logs it to **stderr** — the MCP endpoint is never served unauthenticated, even in development.

```bash
export ALTAIS_HTTP_TOKEN="$(openssl rand -hex 32)"
npm start
# -> [altais-mcp] http transport listening on http://127.0.0.1:3100/mcp
```

Clients connect to `http://127.0.0.1:<port>/mcp` and send `Authorization: Bearer <token>` with every request.

---

## Module list

altais-mcp has 24 modules. `core` is always loaded. Seven modules ship enabled by default; the rest are opt-in. Toggle modules in the `[modules]` section of `altais.config.toml`.

| Module          | Default | Tools | Purpose                                                                                 |
| --------------- | ------- | ----- | --------------------------------------------------------------------------------------- |
| `core`          | always  | 5     | Config inspection, CWE lookup, CVSS scoring, session reporting, composite risk summary  |
| `scan`          | on      | 3     | Static analysis for 15 vulnerability classes across TS/JS/Python/Go/Rust                |
| `threat_model`  | on      | 4     | STRIDE, DREAD, attack trees, trust-boundary analysis                                    |
| `owasp`         | on      | 5     | Coverage reports vs. OWASP Web/API/Mobile/Serverless Top 10 and ASVS                     |
| `secrets`       | on      | 3     | Hardcoded-credential detection by pattern and Shannon entropy, git-history aware        |
| `headers`       | on      | 3     | HTTP security-header audit, CSP generation, CORS validation                             |
| `supply_chain`  | on      | 10    | Lockfile vuln audit, SBOM, SLSA, signatures, VEX, typosquat, dependency confusion       |
| `auth`          | on      | 10    | OAuth/OIDC, JWT, session, CSRF, password hashing, RBAC, passkeys, NHI audits            |
| `crypto`        | opt-in  | 9     | Algorithm/TLS/randomness/key-management audits, post-quantum readiness, crypto agility   |
| `container`     | opt-in  | 3     | Dockerfile, Docker Compose, and base-image hygiene audits                               |
| `code`          | opt-in  | 5     | CERT secure-coding review, Rust `unsafe` audit, error handling, input/memory safety     |
| `data`          | opt-in  | 4     | PII detection, data classification, privacy-by-design audit, retention review           |
| `iac`           | opt-in  | 4     | Terraform, Kubernetes, Helm, and OPA/Kyverno policy-as-code audits                      |
| `api`           | opt-in  | 3     | OpenAPI spec, rate-limiting, and API-gateway hardening audits                           |
| `compliance`    | opt-in  | 3     | Map findings to 16 compliance frameworks, gap analysis, evidence packs                  |
| `infra`         | opt-in  | 4     | Network/firewall, DNS, zero-trust (NIST 800-207), CIS-benchmark hardening audits        |
| `protocol`      | opt-in  | 7     | Deep TLS/mTLS, webhook, email (SPF/DKIM/DMARC), WebSocket, GraphQL, gRPC, SSE audits     |
| `vuln_db`       | opt-in  | 4     | Offline CVE/CWE lookup, CVSS v3.1+v4.0 calculator, MITRE ATT&CK mapping                 |
| `incident`      | opt-in  | 7     | Logging/canary audits; playbook, security.txt, advisory, SIEM, disclosure generators    |
| `testing`       | opt-in  | 7     | Generators for fuzz, SAST, pentest, security-test, chaos, red-team, and IAST artifacts  |
| `sdlc`          | opt-in  | 8     | Pre-commit, CI/CD, review-checklist, release-integrity, signing, branch-protection, SLSA |
| `ml_security`   | opt-in  | 8     | ML pipeline, inference API, model supply chain, OWASP ML/LLM Top 10, prompt injection   |
| `agentic`       | opt-in  | 10    | OWASP Agentic Applications Top 10 (ASI01–ASI10) audits                                  |
| `runtime`       | opt-in  | 3     | WAF rule generation, RASP recommendations, monitoring-coverage audit                    |

The set of active modules is summarized in the `instructions` field of the MCP `InitializeResult` so a client's tool search can surface the right tools.

---

## Configuration reference

altais-mcp reads `altais.config.toml` (or the path given via `--config`). **The file is optional** — if it is missing, every section and key falls back to a default baked into the config schema (`src/config.ts`). All values shown below are the defaults.

### `[server]`

```toml
[server]
name = "altais-mcp"
transport = "stdio"   # "stdio" | "http"
port = 3100           # only used with the http transport
log_level = "info"    # "debug" | "info" | "warn" | "error"
```

### `[modules]` — module toggles

Core is always loaded and cannot be disabled. The seven default modules are `true`; the seventeen opt-in modules are `false`.

```toml
[modules]
# Default modules (enabled out of the box)
scan = true
threat_model = true
owasp = true
secrets = true
headers = true
supply_chain = true
auth = true

# Opt-in modules (disabled by default)
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
```

### Per-module sections

```toml
[scan]
max_file_size_kb = 512
exclude_patterns = ["node_modules", "dist", ".git", "vendor"]
languages = ["typescript", "javascript", "python", "rust", "go"]
# Root directory altais_scan_file may read from. Empty = server CWD at startup.
# Absolute paths only; any path resolving outside this root is rejected.
scan_root = ""
# Cap on inline source passed to altais_scan_code / altais_scan_diff (bytes).
max_source_bytes = 2097152

[secrets]
entropy_min_hex = 4.5       # bits/char threshold for hex-charset tokens
entropy_min_base64 = 5.0    # bits/char threshold for base64-charset tokens
min_token_length = 20

[supply_chain]
check_licenses = true
cvss_threshold = 7.0
sbom_format = "cyclonedx"   # "cyclonedx" | "spdx"
slsa_level = 2              # SLSA v1.2 Build Track level (1-3)
verify_signatures = true
max_dependency_age_days = 30

[severity]
critical_cvss_min = 9.0
high_cvss_min = 7.0
medium_cvss_min = 4.0

[compliance]
frameworks = ["owasp-asvs", "nist-800-53", "nist-ssdf", "cisa-sbd", "nis2"]

[iac]
providers = ["terraform", "kubernetes", "docker-compose"]
k8s_pod_security_level = "restricted"   # "baseline" | "restricted" | "privileged"

[agentic]
check_goal_hijack = true        # ASI01
check_tool_misuse = true        # ASI02
check_identity_abuse = true     # ASI03
check_supply_chain = true       # ASI04
check_code_execution = true     # ASI05
check_memory_poisoning = true   # ASI06
check_inter_agent = true        # ASI07
check_cascading = true          # ASI08
check_trust_exploitation = true # ASI09
check_rogue_agents = true       # ASI10
```

The `scan_root` boundary is a security control: `altais_scan_file` canonicalizes every requested path (resolving symlinks) and rejects anything outside `scan_root`. See [`SECURITY.md`](./SECURITY.md#safe-use-for-operators).

---

## Tool count

| Tier             | Modules                                                                                  | Tools   |
| ---------------- | ---------------------------------------------------------------------------------------- | ------- |
| Core             | `core`                                                                                   | 5       |
| Default          | `scan`, `threat_model`, `owasp`, `secrets`, `headers`, `supply_chain`, `auth`             | 38      |
| Opt-in           | `crypto`, `container`, `code`, `data`, `iac`, `api`, `compliance`, `infra`, `protocol`, `vuln_db`, `incident`, `testing`, `sdlc`, `ml_security`, `agentic`, `runtime` | 89      |
| **Total**        | **24 modules**                                                                           | **132** |

Every tool has its own reference page in the [project wiki](./wiki/Home.md) — its name, input fields, output shape, and a representative request/response example.

---

## Security model

altais-mcp is built to safely ingest untrusted code and configuration:

- **Static analysis only.** Code is read as text and matched against patterns or parsed structurally. No `eval`, `new Function`, `vm`, or `child_process`.
- **No runtime network calls.** All CWE / OWASP / OSV / ATT&CK databases ship bundled. The only network activity is the MCP transport itself.
- **Input validation everywhere.** Every tool input is validated with a Zod schema carrying explicit length, range, and enum constraints. `altais_scan_file` canonicalizes paths and enforces the `scan_root` boundary.
- **Deterministic finding IDs.** Every finding ID is `{module}:{rule}:{contentHash}` — duplicate scans produce identical IDs, never duplicate findings.
- **Accurate annotations.** Every tool declares `readOnlyHint: true`, `destructiveHint: false`, `idempotentHint: true`, `openWorldHint: false`.

Full details, the nine MCP Server Security Rules, and how to report a vulnerability are in [`SECURITY.md`](./SECURITY.md).

---

## Development

```bash
npm run build         # compile TypeScript to dist/ (tsc -p tsconfig.build.json)
npm test              # run the Vitest suite (vitest run)
npm run lint          # typescript-eslint strict lint
npm run format        # apply Prettier formatting
npm run format:check  # verify Prettier formatting without writing
npm start             # run the built server (node dist/index.js)
```

Adding a new module? See the [Module Development guide](./wiki/Module-Development.md) in the wiki for the `ModuleDefinition` contract, the file layout, finding-ID conventions, and registration steps.

---

## Documentation

| Document                                                       | Contents                                                              |
| -------------------------------------------------------------- | --------------------------------------------------------------------- |
| [Project wiki](./wiki/Home.md)                                 | A reference page for every tool, module pages, and how-to guides      |
| [`wiki/Module-Development.md`](./wiki/Module-Development.md)    | Guide for contributors adding a new module                            |
| [`wiki/Deployment.md`](./wiki/Deployment.md)                   | Deploying altais-mcp (stdio, HTTP, Docker, systemd)                   |
| [`wiki/Contributing.md`](./wiki/Contributing.md)               | Branch naming, commit conventions, and the PR process                 |
| [`SECURITY.md`](./SECURITY.md)                                 | Threat model, the nine security rules, vulnerability reporting        |
| [`CHANGELOG.md`](./CHANGELOG.md)                               | Release history (v0.1.0 – v1.0.0)                                     |
| `altais-mcp-architecture.md`                                   | Full module tree, tool tables, and phase plan                         |
