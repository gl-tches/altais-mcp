// Phase 6 — full tool-coverage test (task 6.4).
//
// Builds a server with every module enabled and invokes EVERY registered
// tool once with a minimal, schema-valid sample input. Asserts each tool
// returns a non-error result whose first content item is text. It is fine
// for a tool to return zero findings — this test proves reachability and
// well-formedness, not detection accuracy.

import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";

import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { afterAll, beforeAll, describe, expect, it } from "vitest";

import { configSchema } from "./config.js";
import { buildServer } from "./index.js";

interface CallResult {
  readonly content?: readonly { readonly type: string; readonly text?: string }[];
  readonly isError?: boolean;
}

let tempDir = "";
let server: McpServer | null = null;
let client: Client | null = null;

// Per-module tool counts — summed to derive the expected total without a
// brittle hardcoded number. Kept in module order from `loadEnabledModules`.
const MODULE_TOOL_COUNTS: Readonly<Record<string, number>> = {
  core: 5,
  scan: 3,
  secrets: 3,
  headers: 3,
  threat_model: 4,
  owasp: 5,
  supply_chain: 10,
  auth: 10,
  crypto: 9,
  container: 3,
  code: 5,
  data: 4,
  iac: 4,
  api: 3,
  compliance: 3,
  infra: 4,
  protocol: 7,
  vuln_db: 4,
  incident: 7,
  testing: 7,
  sdlc: 8,
  ml_security: 8,
  agentic: 10,
  runtime: 3,
};

const EXPECTED_TOOL_COUNT = Object.values(MODULE_TOOL_COUNTS).reduce((a, b) => a + b, 0);

// A minimal npm lockfile used by the supply-chain lockfile tools.
const PACKAGE_LOCK = JSON.stringify({
  name: "sample",
  version: "1.0.0",
  lockfileVersion: 3,
  packages: {
    "node_modules/left-pad": {
      version: "1.3.0",
      resolved: "https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz",
    },
  },
});

const OPENAPI_SPEC = JSON.stringify({
  openapi: "3.0.0",
  info: { title: "Sample", version: "1.0.0" },
  paths: {
    "/items": {
      get: { responses: { "200": { description: "ok" } } },
    },
  },
});

const SLSA_ATTESTATION = JSON.stringify({
  _type: "https://in-toto.io/Statement/v1",
  subject: [{ name: "artifact", digest: { sha256: "abc" } }],
  predicateType: "https://slsa.dev/provenance/v1",
  predicate: {},
});

// One schema-valid sample input per registered tool. It is fine for a tool
// to return zero findings; the inputs only need to satisfy the Zod schema.
const SAMPLE_ARGS: Readonly<Record<string, Record<string, unknown>>> = {
  // ── core ────────────────────────────────────────────────────────────────
  altais_get_config: {},
  altais_explain_cwe: { cwe: "CWE-79" },
  altais_score: { vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" },
  altais_report: { format: "json" },
  altais_risk_summary: {},

  // ── scan ────────────────────────────────────────────────────────────────
  altais_scan_code: {
    source: "db.query('SELECT * FROM x WHERE id = ' + req.params.id);",
    language: "javascript",
  },
  altais_scan_file: { path: "sample.js" },
  altais_scan_diff: { diff: "+++ b/a.js\n@@ -0,0 +1,1 @@\n+eval(userInput);\n" },

  // ── secrets ─────────────────────────────────────────────────────────────
  altais_scan_secrets: { source: "const k = 'AKIAIOSFODNN7EXAMPLE';" },
  altais_scan_entropy: { source: "let k = 'Z9pK3mB7cR2vQjL8nF6tH4wY1dXuM5iE0oP';" },
  altais_scan_git_secrets: {
    source: "commit abc1234def5678\n+++ b/c.js\n@@ -1,1 +1,2 @@\n const A = 1;\n",
  },

  // ── headers ─────────────────────────────────────────────────────────────
  altais_audit_headers: { headers: {}, context: "html-app" },
  altais_generate_csp: { mode: "strict" },
  altais_check_cors: { config: { allowed_origins: ["https://example.com"] } },

  // ── threat-model ────────────────────────────────────────────────────────
  altais_stride: {
    architecture: { components: [{ name: "api", type: "api" }] },
  },
  altais_dread: {
    threat: "SQL injection on /search",
    damage: 9,
    reproducibility: 9,
    exploitability: 8,
    affected_users: 10,
    discoverability: 7,
  },
  altais_attack_tree: { goal: "Exfiltrate customer data" },
  altais_trust_boundaries: {
    architecture: {
      components: [
        { name: "internet", type: "user", trust_zone: "untrusted" },
        { name: "api", type: "api", trust_zone: "internal" },
      ],
    },
  },

  // ── owasp ───────────────────────────────────────────────────────────────
  altais_check_owasp_web: { use_session_findings: false },
  altais_check_owasp_api: { use_session_findings: false },
  altais_check_owasp_mobile: { use_session_findings: false },
  altais_check_owasp_serverless: { use_session_findings: false },
  altais_check_asvs: { level: 1, use_session_findings: false },

  // ── supply-chain ────────────────────────────────────────────────────────
  altais_audit_deps: { content: PACKAGE_LOCK, kind: "npm" },
  altais_generate_sbom: { content: PACKAGE_LOCK, kind: "npm" },
  altais_check_licenses: { content: PACKAGE_LOCK, kind: "npm" },
  altais_detect_typosquat: { content: PACKAGE_LOCK, kind: "npm" },
  altais_verify_slsa: { attestation: SLSA_ATTESTATION },
  altais_verify_signatures: {
    signature: "-----BEGIN PGP SIGNATURE-----\nabc\n-----END PGP SIGNATURE-----",
  },
  altais_check_dependency_confusion: {
    content: PACKAGE_LOCK,
    kind: "npm",
    internal_names: ["left-pad"],
  },
  altais_generate_vex: {
    statements: [
      {
        vulnerability: "CVE-2021-44228",
        products: [{ identifier: "pkg:npm/sample@1.0.0" }],
        status: "not_affected",
        justification: "vulnerable_code_not_present",
      },
    ],
  },
  altais_check_build_integrity: {
    content: "name: ci\non: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n",
  },
  altais_audit_registry: { content: "registry=https://registry.npmjs.org/\n", kind: "npmrc" },

  // ── auth ────────────────────────────────────────────────────────────────
  altais_audit_oauth: { config: { flow: "authorization_code" } },
  altais_audit_jwt: { config: {} },
  altais_audit_session: { config: { cookie: { secure: true, httpOnly: true } } },
  altais_audit_csrf: { config: { auth_via: "bearer" } },
  altais_audit_password_hashing: {
    source: "const hashed = await bcrypt.hash(password, 12);",
  },
  altais_audit_rbac: { policy: { roles: [{ name: "viewer", permissions: ["read:items"] }] } },
  altais_audit_passkey_impl: { config: { rp_id: "example.com" } },
  altais_audit_nhi: {
    identities: [{ name: "deploy", kind: "service_account", owner: "infra" }],
  },
  altais_check_secret_lifecycle: { secrets: [{ name: "k", kind: "api_key" }] },
  altais_check_nhi_isolation: {
    identities: [{ name: "ci-bot", environment: "dev" }],
  },

  // ── crypto ──────────────────────────────────────────────────────────────
  altais_audit_crypto: { source: "const h = crypto.createHash('md5');" },
  altais_audit_tls: { config: { min_version: "TLSv1.2" } },
  altais_audit_randomness: { source: "const t = Math.random();" },
  altais_audit_key_mgmt: { keys: [{ name: "signing-key", type: "signing" }] },
  altais_assess_pq_readiness: { config: { algorithms: ["RSA-2048"] } },
  altais_audit_ct_logs: { config: { monitoring_enabled: true } },
  altais_audit_cert_pinning: { config: { pinning_enabled: false } },
  altais_audit_acme: { config: { provider: "letsencrypt", challenge_type: "dns-01" } },
  altais_assess_crypto_agility: { config: { inventory_exists: true } },

  // ── container ───────────────────────────────────────────────────────────
  altais_audit_dockerfile: { content: "FROM node:20-alpine\nUSER node\n" },
  altais_audit_compose: {
    content: 'version: "3.8"\nservices:\n  web:\n    image: nginx:1.27\n',
  },
  altais_check_base_image: { image: "node:20-alpine" },

  // ── code ────────────────────────────────────────────────────────────────
  altais_review_secure_coding: { source: "int main() { return 0; }", language: "c" },
  altais_audit_unsafe: { source: "fn main() { let x = 1; }" },
  altais_check_error_handling: {
    source: "try { run(); } catch (e) { console.log(e); }",
    language: "javascript",
  },
  altais_check_input_validation: {
    source: "const id = req.body.id;",
    language: "javascript",
  },
  altais_check_memory_safety: { source: "int main() { return 0; }", language: "c" },

  // ── data ────────────────────────────────────────────────────────────────
  altais_detect_pii: { source: "const email = 'user@example.com';" },
  altais_classify_data: { fields: [{ name: "user_id" }] },
  altais_audit_privacy: { config: { data_minimization: true } },
  altais_check_retention: {
    policies: [{ data_category: "logs", retention_period_days: 30 }],
  },

  // ── iac ─────────────────────────────────────────────────────────────────
  altais_audit_terraform: {
    content: 'resource "aws_s3_bucket" "b" {\n  bucket = "b"\n}\n',
  },
  altais_audit_k8s_manifest: {
    content: "apiVersion: v1\nkind: Pod\nmetadata:\n  name: p\nspec:\n  containers: []\n",
  },
  altais_audit_helm_chart: { content: "image:\n  repository: nginx\n  tag: 1.27\n" },
  altais_check_policy_as_code: {
    content: 'package x\n\ndeny[msg] { msg := "no" }\n',
    policy_type: "rego",
  },

  // ── api ─────────────────────────────────────────────────────────────────
  altais_audit_openapi_spec: { spec: OPENAPI_SPEC },
  altais_audit_rate_limiting: { config: { enabled: true } },
  altais_audit_api_gateway: { config: { authentication_enabled: true } },

  // ── compliance ──────────────────────────────────────────────────────────
  altais_map_findings: { framework: "nist-800-53" },
  altais_gap_analysis: { framework: "nist-800-53" },
  altais_generate_evidence: { framework: "nist-800-53" },

  // ── infra ───────────────────────────────────────────────────────────────
  altais_audit_network: { config: { egress_filtering: true } },
  altais_audit_dns: { config: { dnssec_enabled: true } },
  altais_check_zero_trust: { config: { verify_explicitly: true } },
  altais_check_hardening: { platform: "linux", settings: { ssh_root_login: false } },

  // ── protocol ────────────────────────────────────────────────────────────
  altais_audit_tls_config: { config: { min_version: "TLSv1.2" } },
  altais_check_webhook: { config: { signature_verified: true } },
  altais_audit_email_security: { config: { dkim_enabled: true } },
  altais_audit_websocket: { config: { tls: true } },
  altais_audit_graphql: { config: { introspection_enabled: false } },
  altais_audit_grpc: { config: { tls_enabled: true } },
  altais_audit_sse: { config: { tls: true } },

  // ── vuln_db ─────────────────────────────────────────────────────────────
  altais_lookup_cve: { cve_id: "CVE-2021-44228" },
  altais_lookup_cwe: { cwe_id: "CWE-89" },
  altais_calculate_cvss: { vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" },
  altais_map_attack: { cwe: "CWE-89" },

  // ── incident ────────────────────────────────────────────────────────────
  altais_audit_logging: { config: { has_audit_log: true } },
  altais_generate_playbook: { scenario: "ransomware" },
  altais_generate_security_txt: { config: { contact: "security@example.com" } },
  altais_draft_advisory: {
    config: { title: "Sample advisory", severity: "high" },
  },
  altais_check_canary: { config: { canary_tokens_deployed: true } },
  altais_recommend_siem: { config: { platform: "splunk" } },
  altais_generate_disclosure_program: {
    config: { organization: "Example Corp", contact: "security@example.com" },
  },

  // ── testing ─────────────────────────────────────────────────────────────
  altais_generate_fuzz_config: { language: "rust" },
  altais_generate_sast_config: { tool: "semgrep", languages: ["python"] },
  altais_generate_pentest_scope: {
    config: {
      application_type: "web",
      assets: ["https://example.com"],
      environment: "staging",
      objectives: ["prove access to customer PII"],
    },
  },
  altais_generate_security_tests: { vulnerability_class: "injection", language: "python" },
  altais_generate_chaos_config: {
    config: { platform: "kubernetes", experiments: ["pod-kill"] },
  },
  altais_scope_red_team: {
    config: {
      objectives: ["test detection"],
      threat_actor_profile: "organized-crime",
      duration_weeks: 4,
      assumed_breach: false,
    },
  },
  altais_generate_iast_config: { tool: "open-source", language: "java" },

  // ── sdlc ────────────────────────────────────────────────────────────────
  altais_generate_precommit: {
    config: { languages: ["python"], checks: ["secrets"] },
  },
  altais_audit_ci_cd: { config: { has_sast: true } },
  altais_generate_review_checklist: {
    config: { change_type: "feature", languages: ["python"], sensitivity: "medium" },
  },
  altais_check_release_integrity: { config: { artifacts_signed: true } },
  altais_check_signed_commits: { config: { signing_enforced: true } },
  altais_audit_branch_protection: { config: { required_reviews: 2 } },
  altais_assess_slsa_level: { config: { scripted_build: true } },
  altais_check_codeowners: { content: "* @org/team\n" },

  // ── ml-security ─────────────────────────────────────────────────────────
  altais_audit_ml_pipeline: { config: { data_validation: true } },
  altais_audit_inference_api: { config: { rate_limited: true } },
  altais_audit_model_supply_chain: { config: { signed: true } },
  altais_check_owasp_ml: { config: { input_validation: true } },
  altais_check_llm_top10: { config: { prompt_injection_defenses: true } },
  altais_audit_prompt_injection: { config: { instruction_data_separation: true } },
  altais_audit_agent_permissions: { config: { autonomous: false } },
  altais_audit_output_handling: { config: {} },

  // ── agentic ─────────────────────────────────────────────────────────────
  altais_audit_goal_hijack: { config: { goal_validation: true } },
  altais_audit_tool_misuse: { config: { tool_allowlist: true } },
  altais_audit_agent_identity: { config: { per_agent_identity: true } },
  altais_audit_agentic_supply_chain: { config: { manifests_signed: true } },
  altais_audit_code_execution: { config: { sandboxed: true } },
  altais_audit_memory_poisoning: { config: {} },
  altais_audit_inter_agent_comms: { config: { message_authentication: true } },
  altais_audit_cascading_failures: { config: {} },
  altais_audit_trust_exploitation: { config: {} },
  altais_audit_rogue_agents: { config: {} },

  // ── runtime ─────────────────────────────────────────────────────────────
  altais_generate_waf_rules: {
    config: { platform: "modsecurity", protect_against: ["sql-injection"] },
  },
  altais_recommend_rasp: {
    config: {
      language: "java",
      framework: "spring-boot",
      deployment: "container",
      risk_tolerance: "medium",
    },
  },
  altais_audit_monitoring: {
    config: {
      logs_authentication: true,
      logs_authorization_failures: true,
      logs_input_validation_failures: true,
      logs_admin_actions: true,
      alerting_enabled: true,
      alert_routing: true,
      siem_integrated: true,
      metrics_collected: true,
      anomaly_detection: true,
      dashboards: true,
      on_call: true,
      mean_time_to_detect_minutes: 15,
    },
  },
};

beforeAll(async () => {
  tempDir = await mkdtemp(path.join(tmpdir(), "altais-tools-"));
  // altais_scan_file needs a real file under scan_root.
  await writeFile(
    path.join(tempDir, "sample.js"),
    "db.query('SELECT * FROM users WHERE id = ' + req.params.id);\n",
    "utf8",
  );

  const config = configSchema.parse({
    modules: {
      crypto: true,
      container: true,
      code: true,
      data: true,
      iac: true,
      api: true,
      compliance: true,
      infra: true,
      protocol: true,
      vuln_db: true,
      incident: true,
      testing: true,
      sdlc: true,
      ml_security: true,
      agentic: true,
      runtime: true,
    },
    scan: { scan_root: tempDir },
  });

  const built = await buildServer(config);
  server = built.server;

  const [serverTx, clientTx] = InMemoryTransport.createLinkedPair();
  await server.connect(serverTx);

  client = new Client({ name: "altais-all-tools", version: "0.0.0" });
  await client.connect(clientTx);
});

afterAll(async () => {
  if (client) await client.close();
  if (server) await server.close();
  if (tempDir) await rm(tempDir, { recursive: true, force: true });
});

function expectClient(): Client {
  if (!client) throw new Error("client not initialized");
  return client;
}

describe("Phase 6 — every registered tool is invocable (6.4)", () => {
  it("registers the full tool set across every module", async () => {
    const { tools } = await expectClient().listTools();
    expect(tools.length).toBe(EXPECTED_TOOL_COUNT);
    expect(tools.length).toBeGreaterThanOrEqual(120);
  });

  it("has a sample input for every registered tool", async () => {
    const { tools } = await expectClient().listTools();
    const registered = tools.map((t) => t.name).sort();
    const sampled = Object.keys(SAMPLE_ARGS).sort();
    expect(sampled).toEqual(registered);
  });

  it("invokes every registered tool and gets a non-error text result", async () => {
    const { tools } = await expectClient().listTools();
    const failures: string[] = [];

    for (const tool of tools) {
      const args = SAMPLE_ARGS[tool.name];
      if (args === undefined) {
        failures.push(`${tool.name}: no sample args defined`);
        continue;
      }
      const result = (await expectClient().callTool({
        name: tool.name,
        arguments: args,
      })) as CallResult;

      if (result.isError === true) {
        const first = result.content?.[0];
        failures.push(`${tool.name}: returned isError (${first?.text ?? "no text"})`);
        continue;
      }
      if (result.content?.[0]?.type !== "text") {
        failures.push(`${tool.name}: first content item is not text`);
      }
    }

    expect(failures).toEqual([]);
  });
});
