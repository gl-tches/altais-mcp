// Phase 4 integration test (task 4.9).
//
// Exercises the cross-module enterprise workflow over the MCP wire
// protocol: scan a vulnerable snippet, map the resulting findings to
// NIST SP 800-53 controls, and generate a compliance gap report.

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

let server: McpServer | null = null;
let client: Client | null = null;

beforeAll(async () => {
  // scan ships enabled by default; opt into the Phase 4 enterprise modules.
  const config = configSchema.parse({
    modules: { compliance: true, infra: true, protocol: true, vuln_db: true },
  });
  const built = await buildServer(config);
  server = built.server;
  const [serverTx, clientTx] = InMemoryTransport.createLinkedPair();
  await server.connect(serverTx);
  client = new Client({ name: "altais-phase4-integration", version: "0.0.0" });
  await client.connect(clientTx);
});

afterAll(async () => {
  if (client) await client.close();
  if (server) await server.close();
});

function expectClient(): Client {
  if (!client) throw new Error("client not initialized");
  return client;
}

async function call(name: string, args: Record<string, unknown>): Promise<CallResult> {
  return (await expectClient().callTool({ name, arguments: args })) as CallResult;
}

function expectJson(result: CallResult): unknown {
  expect(result.isError).not.toBe(true);
  const text = result.content?.[0]?.text ?? "";
  return JSON.parse(text);
}

describe("Phase 4 — enterprise modules", () => {
  it("registers all 18 Phase 4 tools", async () => {
    const { tools } = await expectClient().listTools();
    const names = new Set(tools.map((t) => t.name));
    for (const name of [
      "altais_map_findings",
      "altais_gap_analysis",
      "altais_generate_evidence",
      "altais_audit_network",
      "altais_audit_dns",
      "altais_check_zero_trust",
      "altais_check_hardening",
      "altais_audit_tls_config",
      "altais_check_webhook",
      "altais_audit_email_security",
      "altais_audit_websocket",
      "altais_audit_graphql",
      "altais_audit_grpc",
      "altais_audit_sse",
      "altais_lookup_cve",
      "altais_lookup_cwe",
      "altais_calculate_cvss",
      "altais_map_attack",
    ]) {
      expect(names.has(name)).toBe(true);
    }
  });
});

describe("Phase 4 — scan → map to NIST 800-53 → gap report (4.9)", () => {
  it("scans a vulnerable snippet and produces findings", async () => {
    const json = expectJson(
      await call("altais_scan_code", {
        source: "db.query('SELECT * FROM users WHERE id = ' + req.params.id);",
        language: "javascript",
      }),
    ) as { findings: { rule: string }[] };
    expect(json.findings.some((f) => f.rule.startsWith("sql-injection"))).toBe(true);
  });

  it("maps the session findings to NIST 800-53 controls", async () => {
    const json = expectJson(await call("altais_map_findings", { framework: "nist-800-53" })) as {
      framework_id: string;
      mappings: { control: { id: string }; status: string; matched_findings: unknown[] }[];
    };
    expect(json.framework_id).toBe("nist-800-53");
    expect(json.mappings.length).toBeGreaterThan(0);
    // The SQL injection finding (CWE-89) maps to Information Input Validation.
    const inputValidation = json.mappings.find((m) => m.control.id === "SI-10");
    expect(inputValidation?.status).toBe("addressed");
    expect(inputValidation?.matched_findings.length ?? 0).toBeGreaterThan(0);
  });

  it("generates a NIST 800-53 gap report with coverage statistics", async () => {
    const json = expectJson(await call("altais_gap_analysis", { framework: "nist-800-53" })) as {
      coverage: { total_controls: number; addressed: number; gap: number; coverage_pct: number };
      addressed_controls: { id: string }[];
      gap_controls: { id: string }[];
    };
    expect(json.coverage.total_controls).toBeGreaterThan(0);
    expect(json.coverage.addressed).toBeGreaterThanOrEqual(1);
    expect(json.coverage.addressed + json.coverage.gap).toBe(json.coverage.total_controls);
    expect(json.addressed_controls.some((c) => c.id === "SI-10")).toBe(true);
    expect(json.gap_controls.length).toBeGreaterThan(0);
  });

  it("generates compliance evidence artifacts", async () => {
    const json = expectJson(
      await call("altais_generate_evidence", { framework: "nist-800-53" }),
    ) as Record<string, unknown>;
    expect(JSON.stringify(json)).toMatch(/SI-10/);
  });
});

describe("Phase 4 — vuln_db lookups", () => {
  it("looks up a known CVE from the offline database", async () => {
    const json = expectJson(await call("altais_lookup_cve", { cve_id: "CVE-2021-44228" })) as {
      id: string;
      severity: string;
    };
    expect(json.id).toBe("CVE-2021-44228");
    expect(json.severity).toBe("critical");
  });

  it("calculates a CVSS v3.1 base score", async () => {
    const json = expectJson(
      await call("altais_calculate_cvss", {
        vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
      }),
    ) as { version: string; base_score: number; severity: string };
    expect(json.version).toBe("3.1");
    expect(json.base_score).toBeCloseTo(9.8, 1);
    expect(json.severity).toBe("critical");
  });

  it("maps a CWE to MITRE ATT&CK techniques", async () => {
    const json = expectJson(await call("altais_map_attack", { cwe: "CWE-89" })) as Record<
      string,
      unknown
    >;
    expect(JSON.stringify(json)).toMatch(/T\d{4}/);
  });
});
