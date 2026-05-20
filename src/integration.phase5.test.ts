// Phase 5 integration test (task 5.9).
//
// Exercises the agentic module auditing a deliberately-insecure
// MCP-server / AI-agent project over the MCP wire protocol, and confirms
// the findings flow into the consolidated session report.

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
  const config = configSchema.parse({
    modules: {
      incident: true,
      testing: true,
      sdlc: true,
      ml_security: true,
      agentic: true,
      runtime: true,
    },
  });
  const built = await buildServer(config);
  server = built.server;
  const [serverTx, clientTx] = InMemoryTransport.createLinkedPair();
  await server.connect(serverTx);
  client = new Client({ name: "altais-phase5-integration", version: "0.0.0" });
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
  return JSON.parse(result.content?.[0]?.text ?? "");
}

describe("Phase 5 — advanced modules", () => {
  it("registers all 43 Phase 5 tools", async () => {
    const { tools } = await expectClient().listTools();
    const names = new Set(tools.map((t) => t.name));
    for (const name of [
      "altais_audit_logging",
      "altais_generate_playbook",
      "altais_generate_security_txt",
      "altais_draft_advisory",
      "altais_check_canary",
      "altais_recommend_siem",
      "altais_generate_disclosure_program",
      "altais_generate_fuzz_config",
      "altais_generate_sast_config",
      "altais_generate_pentest_scope",
      "altais_generate_security_tests",
      "altais_generate_chaos_config",
      "altais_scope_red_team",
      "altais_generate_iast_config",
      "altais_generate_precommit",
      "altais_audit_ci_cd",
      "altais_generate_review_checklist",
      "altais_check_release_integrity",
      "altais_check_signed_commits",
      "altais_audit_branch_protection",
      "altais_assess_slsa_level",
      "altais_check_codeowners",
      "altais_audit_ml_pipeline",
      "altais_audit_inference_api",
      "altais_audit_model_supply_chain",
      "altais_check_owasp_ml",
      "altais_check_llm_top10",
      "altais_audit_prompt_injection",
      "altais_audit_agent_permissions",
      "altais_audit_output_handling",
      "altais_audit_goal_hijack",
      "altais_audit_tool_misuse",
      "altais_audit_agent_identity",
      "altais_audit_agentic_supply_chain",
      "altais_audit_code_execution",
      "altais_audit_memory_poisoning",
      "altais_audit_inter_agent_comms",
      "altais_audit_cascading_failures",
      "altais_audit_trust_exploitation",
      "altais_audit_rogue_agents",
      "altais_generate_waf_rules",
      "altais_recommend_rasp",
      "altais_audit_monitoring",
    ]) {
      expect(names.has(name)).toBe(true);
    }
  });
});

describe("Phase 5 — agentic audit of an insecure MCP-server project (5.9)", () => {
  it("flags an unsandboxed code-execution path (ASI05)", async () => {
    const json = expectJson(
      await call("altais_audit_code_execution", {
        config: {
          executes_generated_code: true,
          sandboxed: false,
          allowlist_enforced: false,
          resource_limits: false,
        },
      }),
    ) as { summary: { total: number }; findings: { rule: string; tags: string[] }[] };
    expect(json.summary.total).toBeGreaterThan(0);
    expect(json.findings.some((f) => f.rule === "code-exec-no-sandbox")).toBe(true);
    expect(json.findings.every((f) => f.tags.includes("agentic"))).toBe(true);
  });

  it("flags over-permissioned, unverified tool integrations (ASI02)", async () => {
    const json = expectJson(
      await call("altais_audit_tool_misuse", {
        config: {
          tools: [{ name: "shell", scope: "*" }],
          tool_allowlist: false,
          tool_descriptors_verified: false,
          over_permissioned_apis: true,
          tool_output_validation: false,
        },
      }),
    ) as { summary: { total: number } };
    expect(json.summary.total).toBeGreaterThan(0);
  });

  it("flags unsigned MCP server manifests in the agentic supply chain (ASI04)", async () => {
    const json = expectJson(
      await call("altais_audit_agentic_supply_chain", {
        config: {
          mcp_servers: [{ name: "untrusted-mcp", source: "unknown" }],
          manifests_signed: false,
          plugins_verified: false,
          registry_pinned: false,
          provenance_attestation: false,
        },
      }),
    ) as { summary: { total: number } };
    expect(json.summary.total).toBeGreaterThan(0);
  });

  it("flags unauthenticated inter-agent communication (ASI07)", async () => {
    const json = expectJson(
      await call("altais_audit_inter_agent_comms", {
        config: {
          message_authentication: false,
          message_integrity: false,
          origin_validation: false,
          encrypted_channel: false,
        },
      }),
    ) as { summary: { total: number } };
    expect(json.summary.total).toBeGreaterThan(0);
  });

  it("consolidates agentic findings into the session report", async () => {
    const text = expectClient();
    const result = (await text.callTool({
      name: "altais_report",
      arguments: { format: "json" },
    })) as CallResult;
    const json = expectJson(result) as { findings: { module: string }[] };
    expect(json.findings.some((f) => f.module === "agentic")).toBe(true);
  });
});

describe("Phase 5 — generators produce artifacts", () => {
  it("generates an incident-response playbook", async () => {
    const json = expectJson(await call("altais_generate_playbook", { scenario: "ransomware" })) as {
      phases: unknown[];
    };
    expect(Array.isArray(json.phases)).toBe(true);
    expect(json.phases.length).toBeGreaterThan(0);
  });

  it("generates WAF rules for a chosen platform", async () => {
    const json = expectJson(
      await call("altais_generate_waf_rules", {
        config: { platform: "modsecurity", protect_against: ["sql-injection", "xss"] },
      }),
    ) as { rules: unknown };
    expect(JSON.stringify(json.rules)).toMatch(/Sec|rule/i);
  });
});
