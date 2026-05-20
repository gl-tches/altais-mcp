// Integration test — exercises every active tool through the MCP wire
// protocol via InMemoryTransport. Originally written for Phase 1 (1.23);
// expanded as new modules land so the suite always asserts the full
// tool set is reachable and well-formed.

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

const ACTIVE_TOOL_NAMES = [
  "altais_get_config",
  "altais_explain_cwe",
  "altais_score",
  "altais_report",
  "altais_risk_summary",
  "altais_scan_code",
  "altais_scan_file",
  "altais_scan_diff",
  "altais_scan_secrets",
  "altais_scan_entropy",
  "altais_scan_git_secrets",
  "altais_audit_headers",
  "altais_generate_csp",
  "altais_check_cors",
  "altais_stride",
  "altais_dread",
  "altais_attack_tree",
  "altais_trust_boundaries",
  "altais_check_owasp_web",
  "altais_check_owasp_api",
  "altais_check_owasp_mobile",
  "altais_check_owasp_serverless",
  "altais_check_asvs",
  "altais_audit_deps",
  "altais_generate_sbom",
  "altais_check_licenses",
  "altais_detect_typosquat",
  "altais_verify_slsa",
  "altais_verify_signatures",
  "altais_check_dependency_confusion",
  "altais_generate_vex",
  "altais_check_build_integrity",
  "altais_audit_registry",
  "altais_audit_oauth",
  "altais_audit_jwt",
  "altais_audit_session",
  "altais_audit_csrf",
  "altais_audit_password_hashing",
  "altais_audit_rbac",
  "altais_audit_passkey_impl",
  "altais_audit_nhi",
  "altais_check_secret_lifecycle",
  "altais_check_nhi_isolation",
] as const;

beforeAll(async () => {
  tempDir = await mkdtemp(path.join(tmpdir(), "altais-int-"));
  // Vulnerable JS file used by altais_scan_file. Resolved inside scan_root.
  await writeFile(
    path.join(tempDir, "vuln.js"),
    "db.query('SELECT * FROM users WHERE id = ' + req.params.id);\n",
    "utf8",
  );

  const config = configSchema.parse({
    scan: { scan_root: tempDir },
  });

  const built = await buildServer(config);
  server = built.server;

  const [serverTx, clientTx] = InMemoryTransport.createLinkedPair();
  await server.connect(serverTx);

  client = new Client({ name: "altais-integration", version: "0.1.0" });
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

async function call(name: string, args: Record<string, unknown>): Promise<CallResult> {
  return (await expectClient().callTool({ name, arguments: args })) as CallResult;
}

function expectText(result: CallResult): string {
  expect(result.isError).not.toBe(true);
  expect(result.content?.length ?? 0).toBeGreaterThan(0);
  const first = result.content?.[0];
  expect(first?.type).toBe("text");
  return first?.text ?? "";
}

describe("Integration — initialize + tool listing", () => {
  it("advertises every active tool", async () => {
    const { tools } = await expectClient().listTools();
    const names = tools.map((t) => t.name).sort();
    const expected = [...ACTIVE_TOOL_NAMES].sort();
    expect(names).toEqual(expected);
  });

  it("declares the documented annotations on every tool", async () => {
    const { tools } = await expectClient().listTools();
    for (const tool of tools) {
      expect(tool.annotations?.readOnlyHint).toBe(true);
      expect(tool.annotations?.destructiveHint).toBe(false);
      expect(tool.annotations?.idempotentHint).toBe(true);
      expect(tool.annotations?.openWorldHint).toBe(false);
    }
  });
});

describe("Phase 1 — core tools", () => {
  it("altais_get_config returns the active module set", async () => {
    const text = expectText(await call("altais_get_config", {}));
    const parsed = JSON.parse(text) as { active_modules: string[] };
    expect(parsed.active_modules).toContain("core");
    expect(parsed.active_modules).toContain("scan");
    expect(parsed.active_modules).toContain("secrets");
    expect(parsed.active_modules).toContain("headers");
  });

  it("altais_explain_cwe returns a CWE entry", async () => {
    const text = expectText(await call("altais_explain_cwe", { cwe: "CWE-79" }));
    const parsed = JSON.parse(text) as { id: string; name: string };
    expect(parsed.id).toBe("CWE-79");
    expect(parsed.name).toMatch(/Cross-site Scripting/);
  });

  it("altais_score computes CVSS v3.1 base score", async () => {
    const text = expectText(
      await call("altais_score", {
        vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
      }),
    );
    const parsed = JSON.parse(text) as { base_score: number; severity: string };
    expect(parsed.base_score).toBeCloseTo(9.8, 1);
    expect(parsed.severity).toBe("critical");
  });

  it("altais_report renders markdown", async () => {
    const text = expectText(await call("altais_report", { format: "markdown" }));
    expect(text).toMatch(/altais-mcp Security Report/);
  });

  it("altais_risk_summary returns a score envelope", async () => {
    const text = expectText(await call("altais_risk_summary", {}));
    const parsed = JSON.parse(text) as { risk_score: number; total: number };
    expect(parsed.risk_score).toBeGreaterThanOrEqual(0);
    expect(parsed.total).toBeGreaterThanOrEqual(0);
  });
});

describe("Phase 1 — scan tools", () => {
  it("altais_scan_code flags SQL injection", async () => {
    const text = expectText(
      await call("altais_scan_code", {
        source: "db.query('SELECT * FROM x WHERE id = ' + req.params.id);",
        language: "javascript",
      }),
    );
    const parsed = JSON.parse(text) as { findings: { rule: string }[] };
    expect(parsed.findings.some((f) => f.rule.startsWith("sql-injection"))).toBe(true);
  });

  it("altais_scan_file reads the temp fixture and reports findings", async () => {
    const text = expectText(await call("altais_scan_file", { path: "vuln.js" }));
    const parsed = JSON.parse(text) as { file: string; findings: { rule: string }[] };
    expect(parsed.file).toBe("vuln.js");
    expect(parsed.findings.length).toBeGreaterThan(0);
  });

  it("altais_scan_diff flags additions only", async () => {
    const text = expectText(
      await call("altais_scan_diff", {
        diff: "+++ b/app.js\n@@ -0,0 +1,1 @@\n+eval(userInput);\n",
      }),
    );
    const parsed = JSON.parse(text) as { findings: { rule: string }[] };
    expect(parsed.findings.some((f) => f.rule === "xss-eval")).toBe(true);
  });
});

describe("Phase 1 — secrets tools", () => {
  it("altais_scan_secrets flags an AWS key", async () => {
    const text = expectText(
      await call("altais_scan_secrets", {
        source: "const k = 'AKIAIOSFODNN7EXAMPLE';",
      }),
    );
    const parsed = JSON.parse(text) as { findings: { rule: string }[] };
    expect(parsed.findings.some((f) => f.rule === "aws-access-key-id")).toBe(true);
  });

  it("altais_scan_entropy flags a high-entropy random string", async () => {
    const text = expectText(
      await call("altais_scan_entropy", {
        source: "let k = 'Z9pK3mB7cR2vQjL8nF6tH4wY1dXuM5iE0oP';",
      }),
    );
    const parsed = JSON.parse(text) as { findings: { rule: string }[] };
    expect(parsed.findings.some((f) => f.rule.startsWith("entropy-"))).toBe(true);
  });

  it("altais_scan_git_secrets attributes a finding to a commit", async () => {
    const text = expectText(
      await call("altais_scan_git_secrets", {
        source: `commit abc1234def5678\n+++ b/config.js\n@@ -1,1 +1,2 @@\n const A = 1;\n+const T = "ghp_${"a".repeat(36)}";\n`,
      }),
    );
    const parsed = JSON.parse(text) as { findings: { rule: string; tags: string[] }[] };
    const pat = parsed.findings.find((f) => f.rule === "github-pat-classic");
    expect(pat).toBeDefined();
    expect(pat?.tags).toContain("commit:abc1234def5678");
  });
});

describe("Phase 1 — headers tools", () => {
  it("altais_audit_headers flags missing CSP / HSTS", async () => {
    const text = expectText(
      await call("altais_audit_headers", { headers: {}, context: "html-app" }),
    );
    const parsed = JSON.parse(text) as { findings: { rule: string }[] };
    const rules = parsed.findings.map((f) => f.rule);
    expect(rules).toContain("csp-missing");
    expect(rules).toContain("hsts-missing");
  });

  it("altais_generate_csp emits a strict CSP", async () => {
    const text = expectText(await call("altais_generate_csp", { mode: "strict" }));
    const parsed = JSON.parse(text) as { header: string };
    expect(parsed.header).toMatch(/default-src 'none'/);
    expect(parsed.header).toMatch(/frame-ancestors 'none'/);
    expect(parsed.header).not.toMatch(/unsafe-inline/);
  });

  it("altais_check_cors flags wildcard with credentials", async () => {
    const text = expectText(
      await call("altais_check_cors", {
        config: { allowed_origins: ["*"], allow_credentials: true },
      }),
    );
    const parsed = JSON.parse(text) as { findings: { rule: string }[] };
    expect(parsed.findings.some((f) => f.rule === "cors-wildcard-with-credentials")).toBe(true);
  });
});

describe("Phase 2 — threat-model tools", () => {
  it("altais_stride breaks down threats per component", async () => {
    const text = expectText(
      await call("altais_stride", {
        architecture: {
          components: [
            { name: "api", type: "api", authenticates_clients: true },
            { name: "db", type: "database" },
          ],
        },
      }),
    );
    const parsed = JSON.parse(text) as {
      components: { component: string; threats: Record<string, unknown[]> }[];
      summary: { total_threats: number };
    };
    expect(parsed.components).toHaveLength(2);
    expect(parsed.summary.total_threats).toBeGreaterThan(0);
  });

  it("altais_dread returns a rating", async () => {
    const text = expectText(
      await call("altais_dread", {
        threat: "SQL injection on /search",
        damage: 9,
        reproducibility: 9,
        exploitability: 8,
        affected_users: 10,
        discoverability: 7,
      }),
    );
    const parsed = JSON.parse(text) as { rating: string; total: number };
    expect(parsed.total).toBe(43);
    expect(parsed.rating).toBe("critical");
  });

  it("altais_attack_tree picks a matching template", async () => {
    const text = expectText(await call("altais_attack_tree", { goal: "Exfiltrate customer data" }));
    const parsed = JSON.parse(text) as { matched_template: string };
    expect(parsed.matched_template).toBe("data-exfiltration");
  });

  it("altais_trust_boundaries flags a cleartext ingress flow", async () => {
    const text = expectText(
      await call("altais_trust_boundaries", {
        architecture: {
          components: [
            { name: "internet", type: "user", trust_zone: "untrusted" },
            { name: "api", type: "api", trust_zone: "internal" },
          ],
          data_flows: [
            { from: "internet", to: "api", data: "json body", protocol: "http", auth: "bearer" },
          ],
        },
      }),
    );
    const parsed = JSON.parse(text) as { findings: { rule: string }[] };
    expect(parsed.findings.some((f) => f.rule === "boundary-cleartext")).toBe(true);
  });
});

describe("Phase 2 — OWASP tools", () => {
  it("altais_check_owasp_web maps SQL injection finding to A06:2025", async () => {
    const text = expectText(await call("altais_check_owasp_web", { use_session_findings: true }));
    const parsed = JSON.parse(text) as {
      categories: { id: string; status: string; matched_findings: unknown[] }[];
    };
    const a06 = parsed.categories.find((c) => c.id === "A06:2025");
    expect(a06?.status).toBe("covered");
    expect(a06?.matched_findings.length ?? 0).toBeGreaterThan(0);
  });

  it("altais_check_owasp_web returns needs_review when no findings match", async () => {
    const text = expectText(await call("altais_check_owasp_web", { use_session_findings: false }));
    const parsed = JSON.parse(text) as {
      categories: { id: string; status: string }[];
      summary: { covered: number; needs_review: number };
    };
    expect(parsed.summary.covered).toBe(0);
    expect(parsed.summary.needs_review).toBe(10);
  });

  it("altais_check_owasp_api returns API1..API10:2023 categories", async () => {
    const text = expectText(await call("altais_check_owasp_api", { use_session_findings: false }));
    const parsed = JSON.parse(text) as { categories: { id: string }[] };
    expect(parsed.categories.map((c) => c.id)).toContain("API1:2023");
    expect(parsed.categories.map((c) => c.id)).toContain("API10:2023");
  });

  it("altais_check_owasp_mobile returns the Mobile Top 10 (2024)", async () => {
    const text = expectText(
      await call("altais_check_owasp_mobile", { use_session_findings: false }),
    );
    const parsed = JSON.parse(text) as { categories: { id: string }[] };
    expect(parsed.categories).toHaveLength(10);
    expect(parsed.categories[0]?.id).toBe("M1:2024");
  });

  it("altais_check_owasp_serverless covers SAS-1..SAS-10", async () => {
    const text = expectText(
      await call("altais_check_owasp_serverless", { use_session_findings: false }),
    );
    const parsed = JSON.parse(text) as { categories: { id: string }[] };
    expect(parsed.categories.map((c) => c.id)).toContain("SAS-1");
    expect(parsed.categories.map((c) => c.id)).toContain("SAS-10");
  });

  it("altais_check_asvs filters by level", async () => {
    const text = expectText(
      await call("altais_check_asvs", { level: 1, use_session_findings: false }),
    );
    const parsed = JSON.parse(text) as {
      level: number;
      controls: { id: string; level: number }[];
    };
    expect(parsed.level).toBe(1);
    expect(parsed.controls.every((c) => c.level === 1)).toBe(true);
  });

  it("altais_check_asvs filters by section", async () => {
    const text = expectText(
      await call("altais_check_asvs", {
        level: 3,
        section: "V2",
        use_session_findings: false,
      }),
    );
    const parsed = JSON.parse(text) as { controls: { section: string }[] };
    expect(parsed.controls.every((c) => c.section === "V2")).toBe(true);
  });
});

describe("Phase 2 — auth tools", () => {
  it("altais_audit_oauth flags wildcard redirect URI", async () => {
    const text = expectText(
      await call("altais_audit_oauth", {
        config: { redirect_uris: ["https://*.example.com/cb"] },
      }),
    );
    const parsed = JSON.parse(text) as { findings: { rule: string }[] };
    expect(parsed.findings.some((f) => f.rule === "oauth-wildcard-redirect")).toBe(true);
  });

  it("altais_audit_jwt flags alg:none", async () => {
    const header = Buffer.from(JSON.stringify({ alg: "none" })).toString("base64url");
    const payload = Buffer.from(JSON.stringify({ exp: 9999999999, aud: "x" })).toString(
      "base64url",
    );
    const text = expectText(await call("altais_audit_jwt", { token: `${header}.${payload}.sig` }));
    const parsed = JSON.parse(text) as { findings: { rule: string }[] };
    expect(parsed.findings.some((f) => f.rule === "jwt-alg-none")).toBe(true);
  });

  it("altais_audit_session flags missing SameSite", async () => {
    const text = expectText(
      await call("altais_audit_session", {
        config: { cookie: { secure: true, httpOnly: true } },
      }),
    );
    const parsed = JSON.parse(text) as { findings: { rule: string }[] };
    expect(parsed.findings.some((f) => f.rule === "session-samesite-missing")).toBe(true);
  });

  it("altais_audit_csrf flags cookie auth without mitigation", async () => {
    const text = expectText(
      await call("altais_audit_csrf", {
        config: {
          auth_via: "cookie",
          csrf_token: "none",
          samesite: "Lax",
          checks_origin_header: false,
        },
      }),
    );
    const parsed = JSON.parse(text) as { findings: { rule: string }[] };
    expect(parsed.findings.some((f) => f.rule === "csrf-no-mitigation")).toBe(true);
  });

  it("altais_audit_password_hashing flags MD5 in password context", async () => {
    const text = expectText(
      await call("altais_audit_password_hashing", {
        source: 'const hashed = crypto.createHash("md5").update(password).digest("hex");',
      }),
    );
    const parsed = JSON.parse(text) as { findings: { rule: string }[] };
    expect(parsed.findings.some((f) => f.rule === "password-weak-hash-context")).toBe(true);
  });

  it("altais_audit_rbac flags superuser permission", async () => {
    const text = expectText(
      await call("altais_audit_rbac", {
        policy: { roles: [{ name: "root", permissions: ["*:*"] }] },
      }),
    );
    const parsed = JSON.parse(text) as { findings: { rule: string }[] };
    expect(parsed.findings.some((f) => f.rule === "rbac-superuser")).toBe(true);
  });

  it("altais_audit_passkey_impl flags rp_id / origin mismatch", async () => {
    const text = expectText(
      await call("altais_audit_passkey_impl", {
        config: { rp_id: "example.com", origins: ["https://other.com"] },
      }),
    );
    const parsed = JSON.parse(text) as { findings: { rule: string }[] };
    expect(parsed.findings.some((f) => f.rule === "passkey-origin-rp-mismatch")).toBe(true);
  });

  it("altais_audit_nhi flags credential in repo", async () => {
    const text = expectText(
      await call("altais_audit_nhi", {
        identities: [
          { name: "deploy", kind: "service_account", owner: "infra", stored_in_repo: true },
        ],
      }),
    );
    const parsed = JSON.parse(text) as { findings: { rule: string }[] };
    expect(parsed.findings.some((f) => f.rule === "nhi-credential-in-repo")).toBe(true);
  });

  it("altais_check_secret_lifecycle flags missing expiry", async () => {
    const text = expectText(
      await call("altais_check_secret_lifecycle", {
        secrets: [{ name: "k", kind: "api_key" }],
      }),
    );
    const parsed = JSON.parse(text) as { findings: { rule: string }[] };
    expect(parsed.findings.some((f) => f.rule === "secret-no-expiry")).toBe(true);
  });

  it("altais_check_nhi_isolation flags pre-prod reaching prod", async () => {
    const text = expectText(
      await call("altais_check_nhi_isolation", {
        identities: [{ name: "ci-bot", environment: "dev", cross_environment_access: ["prod"] }],
      }),
    );
    const parsed = JSON.parse(text) as { findings: { rule: string }[] };
    expect(parsed.findings.some((f) => f.rule === "nhi-preprod-reaches-prod")).toBe(true);
  });
});

describe("Phase 1+ — session integration", () => {
  it("altais_report reflects findings produced by earlier tool calls", async () => {
    const text = expectText(await call("altais_report", { format: "json" }));
    const parsed = JSON.parse(text) as { findings: { rule: string }[] };
    // Earlier tests pushed SQL injection, AWS-key, CSP-missing, etc.
    const rules = new Set(parsed.findings.map((f) => f.rule));
    expect(rules.has("aws-access-key-id")).toBe(true);
    expect(rules.has("csp-missing")).toBe(true);
  });

  it("altais_risk_summary shows a non-zero score after scans", async () => {
    const text = expectText(await call("altais_risk_summary", {}));
    const parsed = JSON.parse(text) as { risk_score: number; total: number };
    expect(parsed.total).toBeGreaterThan(0);
    expect(parsed.risk_score).toBeGreaterThan(0);
  });

  it("altais_report markdown output groups findings by module", async () => {
    const text = expectText(await call("altais_report", { format: "markdown" }));
    expect(text).toMatch(/`scan` module/);
    expect(text).toMatch(/`secrets` module/);
    expect(text).toMatch(/\| Module \| Total \| Critical \| High \| Medium \| Low \| Info \|/);
  });

  it("altais_report JSON output includes a by_module breakdown", async () => {
    const text = expectText(await call("altais_report", { format: "json" }));
    const parsed = JSON.parse(text) as {
      by_module: { module: string; total: number }[];
    };
    expect(parsed.by_module.length).toBeGreaterThan(1);
    const modules = parsed.by_module.map((m) => m.module);
    expect(modules).toContain("scan");
    expect(modules).toContain("secrets");
  });
});

// 2.38: full multi-module workflow on a single client connection — confirms
// that scan / auth / owasp findings flow through one session and produce a
// coherent consolidated report.
describe("Phase 2 — multi-module workflow", () => {
  it("scan + auth + owasp findings appear together in altais_report", async () => {
    // Scan a vulnerable JS snippet.
    await call("altais_scan_code", {
      source: 'db.query("SELECT * FROM users WHERE id = " + req.params.id);',
      language: "javascript",
    });

    // Audit a JWT with `alg: none`.
    const header = Buffer.from(JSON.stringify({ alg: "none" })).toString("base64url");
    const payload = Buffer.from(JSON.stringify({ exp: 9999999999, aud: "x" })).toString(
      "base64url",
    );
    await call("altais_audit_jwt", { token: `${header}.${payload}.sig` });

    // OAuth config without PKCE.
    await call("altais_audit_oauth", {
      config: { flow: "authorization_code", pkce: { used: false } },
    });

    // OWASP coverage report should see at least Injection (A06:2025) and
    // Authentication Failures (A07:2025) covered.
    const owaspText = expectText(
      await call("altais_check_owasp_web", { use_session_findings: true }),
    );
    const owasp = JSON.parse(owaspText) as {
      categories: { id: string; status: string; matched_findings: unknown[] }[];
    };
    const a06 = owasp.categories.find((c) => c.id === "A06:2025");
    const a07 = owasp.categories.find((c) => c.id === "A07:2025");
    expect(a06?.status).toBe("covered");
    expect(a07?.status).toBe("covered");
    expect(a06?.matched_findings.length).toBeGreaterThan(0);
    expect(a07?.matched_findings.length).toBeGreaterThan(0);

    // The consolidated report should include findings from both scan and
    // auth modules.
    const reportText = expectText(await call("altais_report", { format: "json" }));
    const report = JSON.parse(reportText) as {
      findings: { module: string; rule: string }[];
      by_module: { module: string; total: number }[];
    };
    const modulesWithFindings = new Set(report.findings.map((f) => f.module));
    expect(modulesWithFindings.has("scan")).toBe(true);
    expect(modulesWithFindings.has("auth")).toBe(true);

    const byModuleNames = report.by_module.map((m) => m.module);
    expect(byModuleNames).toContain("scan");
    expect(byModuleNames).toContain("auth");
  });

  it("altais_risk_summary reflects the multi-module total", async () => {
    const text = expectText(await call("altais_risk_summary", {}));
    const parsed = JSON.parse(text) as {
      total: number;
      by_module: Record<string, number>;
    };
    expect(parsed.total).toBeGreaterThan(0);
    expect(Object.keys(parsed.by_module).length).toBeGreaterThan(1);
  });
});
