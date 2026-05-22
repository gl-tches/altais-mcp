#!/usr/bin/env node
import { randomBytes, randomUUID, timingSafeEqual } from "node:crypto";
import { realpathSync } from "node:fs";
import http from "node:http";
import process from "node:process";
import { pathToFileURL } from "node:url";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";

import { type Config, enabledModules, loadConfig } from "./config.js";
import { ModuleRegistry } from "./core/registry.js";
import { FindingStore } from "./core/report.js";
import type { ModuleConfig, ModuleDefinition } from "./core/types.js";
import { createAuthModule } from "./modules/auth/index.js";
import { createContainerModule } from "./modules/container/index.js";
import { createCoreModule } from "./modules/core/index.js";
import { createCryptoModule } from "./modules/crypto/index.js";
import { createScanModule } from "./modules/scan/index.js";
import { createHeadersModule } from "./modules/headers/index.js";
import { createSecretsModule } from "./modules/secrets/index.js";
import { createSupplyChainModule } from "./modules/supply-chain/index.js";
import { createOwaspModule } from "./modules/owasp/index.js";
import { createThreatModelModule } from "./modules/threat-model/index.js";
import { createCodeModule } from "./modules/code/index.js";
import { createDataModule } from "./modules/data/index.js";
import { createIacModule } from "./modules/iac/index.js";
import { createApiModule } from "./modules/api/index.js";
import { createComplianceModule } from "./modules/compliance/index.js";
import { createInfraModule } from "./modules/infra/index.js";
import { createProtocolModule } from "./modules/protocol/index.js";
import { createVulnDbModule } from "./modules/vuln-db/index.js";
import { createIncidentModule } from "./modules/incident/index.js";
import { createTestingModule } from "./modules/testing/index.js";
import { createSdlcModule } from "./modules/sdlc/index.js";
import { createMlSecurityModule } from "./modules/ml-security/index.js";
import { createAgenticModule } from "./modules/agentic/index.js";
import { createRuntimeModule } from "./modules/runtime/index.js";
import { createDatabaseModule } from "./modules/database/index.js";

export const SERVER_VERSION = "1.1.1";
const HTTP_PATH = "/mcp";
const HTTP_HOST = "127.0.0.1";

/** Environment variable holding the bearer token for the HTTP transport. */
export const HTTP_TOKEN_ENV = "ALTAIS_HTTP_TOKEN";

/**
 * Resolve the bearer token required for every HTTP-transport request.
 * Prefers `ALTAIS_HTTP_TOKEN`; if it is unset, a random ephemeral token is
 * generated so the server never serves the MCP endpoint unauthenticated.
 */
export function resolveHttpToken(env: NodeJS.ProcessEnv = process.env): {
  readonly token: string;
  readonly generated: boolean;
} {
  const fromEnv = env[HTTP_TOKEN_ENV];
  if (fromEnv !== undefined && fromEnv.length > 0) {
    return { token: fromEnv, generated: false };
  }
  return { token: randomBytes(32).toString("hex"), generated: true };
}

/**
 * Constant-time check of an `Authorization: Bearer <token>` header against
 * the expected token. Returns false for a missing or malformed header.
 */
export function isAuthorized(authHeader: string | undefined, token: string): boolean {
  if (authHeader === undefined) return false;
  const match = /^Bearer (.+)$/.exec(authHeader);
  if (match === null) return false;
  const presented = Buffer.from(match[1] ?? "", "utf8");
  const expected = Buffer.from(token, "utf8");
  if (presented.length !== expected.length) return false;
  return timingSafeEqual(presented, expected);
}

/**
 * stderr-only logger. stdout is reserved for the MCP stdio transport.
 */
const log = {
  info: (msg: string): void => {
    process.stderr.write(`[altais-mcp] ${msg}\n`);
  },
  error: (msg: string): void => {
    process.stderr.write(`[altais-mcp] error: ${msg}\n`);
  },
};

function parseArgs(argv: readonly string[]): { configPath?: string } {
  const out: { configPath?: string } = {};
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i];
    if (arg === "--config" || arg === "-c") {
      const next = argv[i + 1];
      if (next !== undefined) {
        out.configPath = next;
        i++;
      }
    } else if (arg?.startsWith("--config=")) {
      out.configPath = arg.slice("--config=".length);
    }
  }
  return out;
}

/**
 * Pull the per-module config section out of the top-level config, keyed by
 * module name. Keys not present become an empty object.
 */
function moduleConfigsFor(config: Config): Record<string, ModuleConfig> {
  const all = config as unknown as Record<string, ModuleConfig | undefined>;
  const out: Record<string, ModuleConfig> = {};
  for (const name of Object.keys(config.modules)) {
    out[name] = all[name] ?? {};
  }
  return out;
}

/**
 * Per-module summaries for the `instructions` field of `InitializeResult`.
 * Each entry lists the module's tools so Claude Code Tool Search can match
 * an agent's intent to the appropriate tool. Keep entries terse — this
 * string is read by the client on every initialize.
 */
const MODULE_DESCRIPTIONS: Readonly<Record<string, string>> = {
  core: "altais_get_config, altais_explain_cwe (top-100 CWE DB), altais_score (full CVSS v3.1 + v4.0), altais_report (markdown/JSON, grouped by module by default), altais_risk_summary",
  scan: "altais_scan_code, altais_scan_file, altais_scan_diff — 15 vulnerability classes (injection, XSS, SSRF, path traversal, exceptional conditions, prototype pollution, SSTI, ReDoS, race conditions, insecure deserialization, business-logic flaws, request smuggling, cache poisoning, CRLF injection, host-header injection) for TypeScript / JavaScript / Python / Go / Rust",
  secrets:
    "altais_scan_secrets, altais_scan_entropy, altais_scan_git_secrets — 28 token patterns (AWS/GitHub/Stripe/PEM/JWT/DSNs/etc.) + Shannon-entropy heuristics, git log/diff aware",
  headers:
    "altais_audit_headers, altais_generate_csp, altais_check_cors — CSP/HSTS/framing/referrer/cookies/CORS",
  threat_model:
    "altais_stride (component-typed STRIDE), altais_dread (1-10 scoring), altais_attack_tree (template trees), altais_trust_boundaries (cross-zone flow audit)",
  owasp:
    "altais_check_owasp_web (Top 10:2025), altais_check_owasp_api (API:2023), altais_check_owasp_mobile (Mobile:2024), altais_check_owasp_serverless, altais_check_asvs (controls by level/section)",
  supply_chain:
    "altais_audit_deps (OSV), altais_generate_sbom (CycloneDX/SPDX), altais_check_licenses, altais_detect_typosquat, altais_verify_slsa, altais_verify_signatures (cosign/GPG), altais_check_dependency_confusion, altais_generate_vex, altais_check_build_integrity, altais_audit_registry",
  auth: "altais_audit_oauth (OAuth 2.1), altais_audit_jwt, altais_audit_session, altais_audit_csrf, altais_audit_password_hashing, altais_audit_rbac, altais_audit_passkey_impl, altais_audit_nhi (OWASP NHI Top 10), altais_check_secret_lifecycle, altais_check_nhi_isolation",
  crypto:
    "altais_audit_crypto (weak ciphers/hashes, ECB, static IV), altais_audit_tls (protocols/ciphers/cert verification), altais_audit_randomness (insecure PRNGs), altais_audit_key_mgmt (storage/rotation), altais_assess_pq_readiness (post-quantum), altais_audit_ct_logs, altais_audit_cert_pinning, altais_audit_acme, altais_assess_crypto_agility",
  container:
    "altais_audit_dockerfile (root user, unpinned base, ADD/curl-pipe-shell, secrets in ENV/ARG), altais_audit_compose (privileged, host namespaces, docker.sock, capabilities, hardcoded secrets), altais_check_base_image (version/digest pinning, end-of-life images, image bloat)",
  code: "altais_review_secure_coding (CERT standards), altais_audit_unsafe (Rust unsafe soundness), altais_check_error_handling (info leakage), altais_check_input_validation, altais_check_memory_safety (C/C++/Rust)",
  data: "altais_detect_pii (PII detection, masked evidence), altais_classify_data (sensitivity tiers), altais_audit_privacy (privacy-by-design / GDPR), altais_check_retention (retention & deletion)",
  iac: "altais_audit_terraform (HCL misconfig), altais_audit_k8s_manifest (Pod Security Standards), altais_audit_helm_chart, altais_check_policy_as_code (OPA/Rego, Kyverno)",
  api: "altais_audit_openapi_spec (OpenAPI 3.x security gaps), altais_audit_rate_limiting, altais_audit_api_gateway",
  compliance:
    "altais_map_findings, altais_gap_analysis, altais_generate_evidence — maps findings to 16 frameworks (OWASP ASVS/SAMM/DSOMM, NIST 800-53/SSDF/AI-RMF, ISO 27001, SOC 2, GDPR, PCI-DSS, NIS2, DORA, CRA, CISA SbD, EO 14028, FDA 524B)",
  infra:
    "altais_audit_network (segmentation/firewall rules), altais_audit_dns (DNSSEC, zone transfer, CAA), altais_check_zero_trust (NIST 800-207), altais_check_hardening (CIS benchmarks)",
  protocol:
    "altais_audit_tls_config (deep TLS/mTLS), altais_check_webhook (HMAC signatures), altais_audit_email_security (SPF/DKIM/DMARC), altais_audit_websocket, altais_audit_graphql, altais_audit_grpc, altais_audit_sse",
  vuln_db:
    "altais_lookup_cve (offline CVE DB), altais_lookup_cwe (CWE taxonomy + hierarchy), altais_calculate_cvss (full v3.1 + v4.0), altais_map_attack (MITRE ATT&CK)",
  incident:
    "altais_audit_logging, altais_generate_playbook, altais_generate_security_txt, altais_draft_advisory (GHSA), altais_check_canary, altais_recommend_siem, altais_generate_disclosure_program",
  testing:
    "altais_generate_fuzz_config, altais_generate_sast_config, altais_generate_pentest_scope, altais_generate_security_tests, altais_generate_chaos_config, altais_scope_red_team, altais_generate_iast_config",
  sdlc: "altais_generate_precommit, altais_audit_ci_cd (security gates), altais_generate_review_checklist, altais_check_release_integrity, altais_check_signed_commits, altais_audit_branch_protection, altais_assess_slsa_level (SLSA v1.2), altais_check_codeowners",
  ml_security:
    "altais_audit_ml_pipeline, altais_audit_inference_api, altais_audit_model_supply_chain, altais_check_owasp_ml, altais_check_llm_top10 (OWASP LLM Top 10), altais_audit_prompt_injection, altais_audit_agent_permissions (excessive agency), altais_audit_output_handling",
  agentic:
    "altais_audit_goal_hijack, altais_audit_tool_misuse, altais_audit_agent_identity, altais_audit_agentic_supply_chain, altais_audit_code_execution, altais_audit_memory_poisoning, altais_audit_inter_agent_comms, altais_audit_cascading_failures, altais_audit_trust_exploitation, altais_audit_rogue_agents — OWASP Agentic Top 10 (ASI01-ASI10)",
  runtime: "altais_generate_waf_rules, altais_recommend_rasp, altais_audit_monitoring",
  database:
    "altais_audit_connection, altais_audit_queries (parameterization across Prisma/Drizzle/TypeORM/Sequelize/Knex/pg/mysql2/SQLAlchemy/Django/psycopg/diesel/sqlx/GORM/pgx), altais_audit_postgres, altais_audit_mysql, altais_audit_mongodb, altais_audit_redis, altais_audit_sqlite, altais_audit_mssql, altais_audit_elasticsearch, altais_audit_dynamodb, altais_audit_pooling, altais_audit_migrations, altais_audit_backup, altais_audit_nosql_injection, altais_audit_db_tls, altais_audit_db_logging — connection / config / migration / backup / NoSQL-injection / TLS / logging audits per database engine",
};

export function buildInstructions(activeModules: readonly string[]): string {
  const lines: string[] = [
    "altais-mcp: read-only security analysis for AI coding agents.",
    "All tools share annotations readOnly=true, destructive=false, idempotent=true, openWorld=false. No tool executes user code or makes network calls.",
  ];
  if (activeModules.length === 0) {
    lines.push(
      "No modules are currently active. Tools will appear as modules are enabled in altais.config.toml.",
    );
    return lines.join("\n");
  }
  lines.push(`Active modules: ${activeModules.join(", ")}.`);
  const annotated = activeModules
    .map((name) => {
      const desc = MODULE_DESCRIPTIONS[name];
      return desc ? `- ${name}: ${desc}` : null;
    })
    .filter((line): line is string => line !== null);
  if (annotated.length > 0) {
    lines.push("", ...annotated);
  }
  lines.push(
    "",
    "Findings from every tool flow into a shared session FindingStore; altais_report returns a consolidated markdown or JSON report of the entire session.",
  );
  return lines.join("\n");
}

export function loadEnabledModules(deps: {
  config: Config;
  findingStore: FindingStore;
  activeModules: () => readonly string[];
}): readonly ModuleDefinition[] {
  // The `core` module is always loaded. Other modules are loaded here so
  // the registry can resolve them when their config flag is enabled.
  return [
    createCoreModule({
      config: deps.config,
      findingStore: deps.findingStore,
      activeModules: deps.activeModules,
    }),
    createScanModule({
      config: deps.config,
      findingStore: deps.findingStore,
    }),
    createSecretsModule({
      config: deps.config,
      findingStore: deps.findingStore,
    }),
    createHeadersModule({
      findingStore: deps.findingStore,
    }),
    createThreatModelModule({
      findingStore: deps.findingStore,
    }),
    createOwaspModule({
      findingStore: deps.findingStore,
    }),
    createSupplyChainModule({
      findingStore: deps.findingStore,
    }),
    createAuthModule({
      findingStore: deps.findingStore,
    }),
    createCryptoModule({
      findingStore: deps.findingStore,
    }),
    createContainerModule({
      findingStore: deps.findingStore,
    }),
    createCodeModule({
      findingStore: deps.findingStore,
    }),
    createDataModule({
      findingStore: deps.findingStore,
    }),
    createIacModule({
      findingStore: deps.findingStore,
    }),
    createApiModule({
      findingStore: deps.findingStore,
    }),
    createComplianceModule({
      findingStore: deps.findingStore,
    }),
    createInfraModule({
      findingStore: deps.findingStore,
    }),
    createProtocolModule({
      findingStore: deps.findingStore,
    }),
    createVulnDbModule({
      findingStore: deps.findingStore,
    }),
    createIncidentModule({
      findingStore: deps.findingStore,
    }),
    createTestingModule({
      findingStore: deps.findingStore,
    }),
    createSdlcModule({
      findingStore: deps.findingStore,
    }),
    createMlSecurityModule({
      findingStore: deps.findingStore,
    }),
    createAgenticModule({
      findingStore: deps.findingStore,
    }),
    createRuntimeModule({
      findingStore: deps.findingStore,
    }),
    createDatabaseModule({
      findingStore: deps.findingStore,
    }),
  ];
}

export interface BuiltServer {
  readonly server: McpServer;
  readonly registry: ModuleRegistry;
  readonly findingStore: FindingStore;
  readonly activeModules: readonly string[];
}

/**
 * Construct and fully wire an McpServer for the supplied config: load
 * modules, register tools, and set the `instructions` field. The caller
 * is responsible for connecting a transport. Used by both the stdio/HTTP
 * entrypoint and the integration tests.
 */
export async function buildServer(config: Config): Promise<BuiltServer> {
  const findingStore = new FindingStore();
  const activeModulesRef: { value: readonly string[] } = { value: [] };

  const registry = new ModuleRegistry();
  for (const mod of loadEnabledModules({
    config,
    findingStore,
    activeModules: () => activeModulesRef.value,
  })) {
    registry.load(mod);
  }

  const requested = ["core", ...enabledModules(config).filter((name) => registry.has(name))];
  activeModulesRef.value = requested;

  const server = new McpServer(
    { name: config.server.name, version: SERVER_VERSION },
    { instructions: buildInstructions(requested) },
  );

  await registry.registerAll(server, requested, moduleConfigsFor(config));

  return { server, registry, findingStore, activeModules: requested };
}

async function startStdio(server: McpServer): Promise<void> {
  const transport = new StdioServerTransport();
  await server.connect(transport);
  log.info("stdio transport ready");
}

function sendJson(res: http.ServerResponse, status: number, body: unknown): void {
  res.writeHead(status, { "content-type": "application/json" });
  res.end(JSON.stringify(body));
}

/**
 * Start the streamable HTTP transport. Binds to `127.0.0.1` only, validates
 * the `Origin` header and enables DNS-rebinding protection, and requires a
 * bearer token on every request — the server never exposes the MCP endpoint
 * unauthenticated, even in development.
 *
 * Each MCP client gets its own session: an `initialize` POST (no
 * `mcp-session-id` header) builds a fresh server + isolated FindingStore;
 * subsequent requests are routed to that session by id and torn down when
 * the transport closes. Returns the listening `http.Server`.
 */
export async function startHttp(config: Config, port: number): Promise<http.Server> {
  const origins = [`http://${HTTP_HOST}:${port}`, `http://localhost:${port}`];
  const hosts = [`${HTTP_HOST}:${port}`, `localhost:${port}`];

  const { token, generated } = resolveHttpToken();
  if (generated) {
    log.info(`generated ephemeral HTTP bearer token: ${token}`);
    log.info(`set ${HTTP_TOKEN_ENV} for a stable token across restarts`);
  } else {
    log.info(`HTTP bearer token loaded from ${HTTP_TOKEN_ENV}`);
  }

  const sessions = new Map<string, StreamableHTTPServerTransport>();

  const openSession = async (
    req: http.IncomingMessage,
    res: http.ServerResponse,
  ): Promise<void> => {
    const transport = new StreamableHTTPServerTransport({
      sessionIdGenerator: () => randomUUID(),
      enableDnsRebindingProtection: true,
      allowedHosts: hosts,
      allowedOrigins: origins,
      onsessioninitialized: (id: string) => {
        sessions.set(id, transport);
      },
    });
    transport.onclose = (): void => {
      if (transport.sessionId !== undefined) sessions.delete(transport.sessionId);
    };
    const { server } = await buildServer(config);
    await server.connect(transport);
    await transport.handleRequest(req, res);
  };

  const httpServer = http.createServer((req, res) => {
    const url = req.url ?? "";
    if (!url.startsWith(HTTP_PATH)) {
      sendJson(res, 404, { error: "Not found" });
      return;
    }
    if (!isAuthorized(req.headers.authorization, token)) {
      res.writeHead(401, {
        "content-type": "application/json",
        "www-authenticate": 'Bearer realm="altais-mcp"',
      });
      res.end(JSON.stringify({ error: "Unauthorized: a valid bearer token is required" }));
      return;
    }

    const sidHeader = req.headers["mcp-session-id"];
    const sessionId = typeof sidHeader === "string" ? sidHeader : undefined;
    const handle = (): Promise<void> => {
      if (sessionId !== undefined) {
        const existing = sessions.get(sessionId);
        if (existing === undefined) {
          sendJson(res, 404, { error: "Unknown or expired MCP session" });
          return Promise.resolve();
        }
        return existing.handleRequest(req, res);
      }
      if (req.method !== "POST") {
        sendJson(res, 400, { error: "Missing mcp-session-id header" });
        return Promise.resolve();
      }
      return openSession(req, res);
    };

    handle().catch((err: unknown) => {
      log.error(`http request failed: ${(err as Error).message}`);
      if (!res.headersSent) {
        sendJson(res, 500, { error: "Internal server error" });
      }
    });
  });

  await new Promise<void>((resolve) => {
    httpServer.listen(port, HTTP_HOST, () => {
      resolve();
    });
  });
  log.info(`http transport listening on http://${HTTP_HOST}:${port}${HTTP_PATH}`);
  return httpServer;
}

export async function main(argv: readonly string[]): Promise<void> {
  const args = parseArgs(argv);
  const config = await loadConfig(args.configPath ?? "altais.config.toml");

  if (config.server.transport === "stdio") {
    const { server } = await buildServer(config);
    await startStdio(server);
  } else {
    await startHttp(config, config.server.port);
  }
}

const isEntrypoint = (): boolean => {
  // npm installs the `altais-mcp` bin as a symlink; npx launches that
  // symlink, so process.argv[1] must be resolved to its real path before
  // it can be compared to this module's URL.
  const a = process.argv[1];
  return a ? import.meta.url === pathToFileURL(realpathSync(a)).href : false;
};

if (isEntrypoint()) {
  main(process.argv.slice(2)).catch((err: unknown) => {
    log.error((err as Error).stack ?? String(err));
    process.exit(1);
  });
}
