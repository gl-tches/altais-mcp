# Security Policy

This document describes the security model of **altais-mcp**, how the project follows the nine MCP Server Security Rules it holds itself to, how to report a vulnerability in altais-mcp itself, and how to operate the server safely.

altais-mcp is a security-analysis tool. Because it exists to inspect potentially malicious code, the project takes its own security posture seriously: a tool that ingests untrusted input must never be turned against the host it runs on.

---

## Threat model

altais-mcp **ingests untrusted code and configuration as text**. An AI coding agent — or, transitively, a human or repository the agent does not control — supplies source files, lockfiles, diffs, Dockerfiles, IaC manifests, OpenAPI specs, JWTs, certificates, and similar artifacts to be analyzed. That input must be treated as hostile.

The core security invariant: **altais-mcp analyzes input; it never executes, evaluates, imports, or trusts it.**

Primary threats the design defends against:

| Threat                                | Defense                                                                                    |
| ------------------------------------- | ------------------------------------------------------------------------------------------ |
| Code execution via analyzed input     | Pure static analysis — no `eval`, `Function`, `vm`, or process spawning anywhere.           |
| Sandbox / path-traversal escape       | `altais_scan_file` canonicalizes paths, resolves symlinks, and enforces the `scan_root` boundary. |
| Denial of service via oversized input | Every Zod schema caps string length, array size, and numeric range.                        |
| Data exfiltration at runtime          | No network calls from any tool handler; all reference databases are bundled.               |
| Credential leakage in output          | Secret/PII findings redact the literal value; errors are sanitized before reaching clients. |
| DNS rebinding against the HTTP server | `127.0.0.1`-only bind, `Origin` validation, DNS-rebinding protection, mandatory bearer token. |
| Tampered / spoofed finding state      | Deterministic finding IDs derived from location and evidence.                              |

Out of scope: altais-mcp does not defend the network path between an MCP client and the server beyond the transport's own controls, and it does not guarantee the *correctness* of every finding — its results are advisory input for an agent or human, not a compliance certification.

---

## The nine MCP Server Security Rules

These rules derive from the MCP specification, Anthropic's security guidance, the OWASP ASI Top 10 (2026), and real-world CVEs filed against MCP servers. Every contributor must follow them; this section records how altais-mcp implements each one.

### 1. Input validation

Every tool input is validated with a **Zod schema carrying explicit constraints** — `min`/`max` on string length, `max` on array size, `min`/`max` on numeric range, and `enum` for closed value sets. No raw string is passed through to a filesystem, shell, or evaluation operation. Inline-source inputs are capped (`scan.max_source_bytes`, default 2 MiB); file reads are capped (`scan.max_file_size_kb`, default 512 KiB).

`altais_scan_file` is the only tool that reads from disk. It **resolves the requested path with `path.resolve()`, canonicalizes it with `realpath()` (resolving symlinks), and verifies the result stays inside the configured `scan_root`** before reading. A path that escapes the root — directly or through a symlink — is rejected. This closes the class of sandbox-escape bugs seen in CVE-2025-53109 and CVE-2025-53110 against the Anthropic Filesystem MCP.

### 2. No code execution

altais-mcp is a static-analysis and advisory tool. It reads code as text and applies pattern matching or structural parsing. It **never** calls `eval()`, `new Function()`, `vm.runInContext()`, `child_process.exec()`/`spawn()`, or any equivalent. Rust `unsafe` auditing, memory-safety analysis, and every other language check are performed purely by regex and text inspection — never by running the target code. There is no dynamic `import()` of user-supplied modules.

### 3. No network calls at runtime

Every analysis runs locally against the input the agent supplies. The bundled databases — CWE, secret patterns, the OSV snapshot, OWASP control lists, the CVE snapshot, MITRE ATT&CK techniques, and compliance frameworks — ship inside the package under `data/`. No tool handler fetches from an external API. The only network activity is the MCP transport itself (stdio has none; the HTTP transport serves a local socket). If a future module ever needs CVE data, it must use a bundled local copy of the OSV database, and that exception must be documented explicitly.

### 4. No secrets in code

API keys, tokens, and credentials never appear in source, test fixtures, or bundled data files. Test fixtures that need a credential-shaped value use obviously synthetic placeholders. Potentially sensitive runtime values — currently only the HTTP bearer token — come from an environment variable (`ALTAIS_HTTP_TOKEN`), not from `altais.config.toml`. `.env` files are git-ignored.

### 5. Transport security

**stdio:** stdout is reserved exclusively for the MCP protocol stream. All logging goes to **stderr** via the `log` helper in `src/index.ts`; nothing else writes to stdout.

**Streamable HTTP:** the server **binds to `127.0.0.1` only**, never `0.0.0.0`. It **validates the `Origin` header** and enables the SDK's **DNS-rebinding protection** against an allowlist of local hosts and origins. It **requires a bearer token on every request** — the token is read from `ALTAIS_HTTP_TOKEN`, or, if that is unset, a cryptographically random ephemeral token is generated at startup and logged to stderr, so the endpoint is *never* served unauthenticated, even in development. The token is compared in **constant time** (`crypto.timingSafeEqual`). Each MCP client gets an isolated session and `FindingStore`. The deprecated SSE transport is not used.

### 6. Output safety

Tool responses never leak internal server state, filesystem paths beyond the scanned scope, environment variables, or raw stack traces. Errors are caught inside handlers and returned as a sanitized, actionable message (`isError: true`); the full error is logged server-side to stderr. Secret and PII findings **redact the literal value** (a short head/tail plus length) so the credential is not echoed back verbatim. Tool responses include a `summary` so large finding sets stay bounded and digestible.

### 7. Deterministic finding IDs

Every finding ID has the form `{module}:{rule}:{contentHash}`. The content hash is a truncated SHA-256 over the finding's module, rule, location (file, line, column), and evidence (see `findingId()` in `src/core/utils.ts`). Re-scanning identical input produces identical IDs, so duplicate scans never produce duplicate findings — which lets an agent track remediation state across sessions.

### 8. Tool annotations

Every tool declares the same accurate annotation set:

```typescript
annotations: {
  readOnlyHint: true,     // altais-mcp only analyzes — it never modifies code
  destructiveHint: false, // no tool performs a destructive action
  idempotentHint: true,   // same input always yields the same output
  openWorldHint: false,   // no tool reaches an external system
}
```

These are hints, not enforced guarantees — but they are accurate for every one of the 132 tools.

### 9. Instructions field

The `instructions` field of the MCP `InitializeResult` carries a concise description of every active module and its tools, so a client's tool search can match an agent's intent to the right tool. The string is rebuilt from the active-module set on every server construction (`buildInstructions()` in `src/index.ts`) and is kept current whenever a module is added or removed.

---

## Supply-chain scanner notes

Because altais-mcp is a security scanner, its own source necessarily *describes* dangerous APIs — the dynamic code-execution primitive, the HTTP request API, the process-spawning calls, and similar — as the patterns it looks for in the code it analyzes. Automated supply-chain scanners (Socket.dev and similar) statically match those names and can mis-report them as real capabilities of altais-mcp itself.

Two notes for anyone auditing altais-mcp with such a tool:

- **Detection-pattern tokens are data, not code.** As of v1.0.1, the literal API-name strings used by the vulnerability detectors live in the `data/scan-patterns.json` data file and are loaded at runtime by `src/core/scan-patterns.ts`. No detector embeds those API names as an inline source literal. altais-mcp only ever *matches* these tokens in the text it scans — it never calls them (see rule 2 above).

- **The `child_process` capability flag comes from the MCP SDK, not from altais-mcp.** altais-mcp's own code never imports `child_process` or spawns a process. The `child_process` flag that a supply-chain scanner attributes to the dependency tree originates in `@modelcontextprotocol/sdk`: its stdio transport implementation uses `child_process` to connect an MCP client and server over standard streams. altais-mcp depends on that transport for local / Claude Code use, so the dependency — and therefore the flag — cannot be removed without dropping stdio transport support entirely.

---


## Reporting a vulnerability in altais-mcp

If you discover a security vulnerability **in altais-mcp itself** — for example a way to make a tool execute code, escape the `scan_root` boundary, exfiltrate data, or crash the server with crafted input — please report it privately:

1. **Do not** open a public GitHub issue for a security vulnerability.
2. Use the repository's [private vulnerability reporting](https://github.com/gl-tches/altais-mcp/security/advisories/new) (GitHub Security Advisories) to open a draft advisory.
3. Include: a description of the issue, the affected version, reproduction steps or a proof of concept, and the impact you observed.

What to expect:

- An acknowledgment of your report within **5 business days**.
- An assessment of severity and an initial remediation plan.
- Coordinated disclosure: a fix and a published advisory once a patched release is available. Reporters are credited unless they ask otherwise.

Please give the maintainers a reasonable window to ship a fix before any public disclosure.

> Findings produced *by* altais-mcp's tools about *your* code are not vulnerabilities in altais-mcp — triage those in your own project.

---

## Safe use for operators

altais-mcp is hardened, but operators should still apply standard precautions:

- **Run with least privilege.** Run the server as an unprivileged user. It needs read access only to the files you intend to scan and never needs write access to any code under analysis.
- **Set the `scan_root` boundary.** Configure `scan.scan_root` to the narrowest absolute directory that contains the project you are analyzing. `altais_scan_file` will refuse any path — including via symlink — that resolves outside this root. When `scan_root` is empty it defaults to the server's working directory at startup, so launch the server from inside (or above) only the project you want reachable.
- **Treat inline-source inputs as the real boundary.** `altais_scan_code` and `altais_scan_diff` analyze text passed in the request and do not touch disk; the size cap (`scan.max_source_bytes`) bounds their work.
- **Protect the HTTP bearer token.** When using the HTTP transport, set `ALTAIS_HTTP_TOKEN` to a strong, stable secret via the environment (not the config file) and keep it out of version control. If you rely on the auto-generated ephemeral token, capture it from stderr — it changes on every restart.
- **Keep the HTTP transport local.** The server binds to `127.0.0.1` by design. Do not place it behind a reverse proxy that exposes it on a public interface without adding your own authentication, TLS, and access controls.
- **Keep bundled databases current.** The OSV and CVE snapshots are intentionally small, curated samples. For production dependency auditing, replace `data/osv-snapshot.json` (and related files) with a fresh export.
- **Audit dependencies.** Run `npm audit` after every dependency change; altais-mcp pins exact versions and keeps its runtime dependency surface minimal.
