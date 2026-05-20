import { describe, expect, it } from "vitest";
import type { CallToolResult } from "@modelcontextprotocol/sdk/types.js";

import { FindingStore } from "../../core/report.js";
import { createTestingModule } from "./index.js";

function textOf(result: CallToolResult): string {
  const first = result.content[0];
  return first?.type === "text" ? first.text : "";
}

const moduleDef = createTestingModule({ findingStore: new FindingStore() });

describe("createTestingModule — assembly", () => {
  it("registers exactly 7 generator tools", () => {
    expect(moduleDef.tools).toHaveLength(7);
    expect(moduleDef.name).toBe("testing");
    expect(moduleDef.version).toBe("0.5.0");
  });

  it("names every tool with the altais_ prefix", () => {
    for (const t of moduleDef.tools) {
      expect(t.name.startsWith("altais_")).toBe(true);
    }
  });

  it("declares read-only, non-destructive annotations on every tool", () => {
    for (const t of moduleDef.tools) {
      expect(t.annotations.readOnlyHint).toBe(true);
      expect(t.annotations.destructiveHint).toBe(false);
      expect(t.annotations.idempotentHint).toBe(true);
      expect(t.annotations.openWorldHint).toBe(false);
    }
  });

  it("gives every tool an input schema, title, and description", () => {
    for (const t of moduleDef.tools) {
      expect(t.inputSchema).toBeDefined();
      expect((t.title ?? "").length).toBeGreaterThan(0);
      expect(t.description.length).toBeGreaterThan(20);
    }
  });
});

function callTool(name: string, args: Record<string, unknown>): CallToolResult {
  const tool = moduleDef.tools.find((t) => t.name === name);
  if (tool === undefined) throw new Error(`tool not found: ${name}`);
  const r = tool.handler(args);
  if (r instanceof Promise) throw new Error("handler returned a promise");
  return r;
}

describe("createTestingModule — handlers", () => {
  it("altais_generate_fuzz_config returns JSON for a valid request", () => {
    const r = callTool("altais_generate_fuzz_config", { language: "rust" });
    expect(r.isError).toBeFalsy();
    expect(JSON.parse(textOf(r))).toMatchObject({ language: "rust" });
  });

  it("altais_generate_sast_config returns an error for invalid input", () => {
    const r = callTool("altais_generate_sast_config", { tool: "semgrep", languages: [] });
    expect(r.isError).toBe(true);
    expect(textOf(r)).toContain("Invalid input");
  });

  it("altais_generate_pentest_scope returns JSON for a valid request", () => {
    const r = callTool("altais_generate_pentest_scope", {
      config: {
        application_type: "web",
        assets: ["app.example.com"],
        environment: "staging",
        objectives: ["assess attack surface"],
      },
    });
    expect(r.isError).toBeFalsy();
    expect(JSON.parse(textOf(r))).toMatchObject({ application_type: "web" });
  });

  it("altais_generate_security_tests returns JSON for a valid request", () => {
    const r = callTool("altais_generate_security_tests", {
      vulnerability_class: "xss",
      language: "javascript",
    });
    expect(r.isError).toBeFalsy();
    expect(JSON.parse(textOf(r))).toMatchObject({ vulnerability_class: "xss" });
  });

  it("altais_generate_chaos_config returns JSON for a valid request", () => {
    const r = callTool("altais_generate_chaos_config", {
      config: { platform: "kubernetes", experiments: ["pod-kill"] },
    });
    expect(r.isError).toBeFalsy();
    expect(JSON.parse(textOf(r))).toMatchObject({ platform: "kubernetes" });
  });

  it("altais_scope_red_team returns JSON for a valid request", () => {
    const r = callTool("altais_scope_red_team", {
      config: {
        objectives: ["reach the crown jewels"],
        threat_actor_profile: "nation-state",
        duration_weeks: 6,
        assumed_breach: true,
      },
    });
    expect(r.isError).toBeFalsy();
    expect(JSON.parse(textOf(r))).toMatchObject({ threat_actor_profile: "nation-state" });
  });

  it("altais_generate_iast_config returns JSON for a valid request", () => {
    const r = callTool("altais_generate_iast_config", { tool: "contrast", language: "java" });
    expect(r.isError).toBeFalsy();
    expect(JSON.parse(textOf(r))).toMatchObject({ tool: "contrast", supported: true });
  });

  it("rejects a request with a missing required field", () => {
    const r = callTool("altais_generate_iast_config", { tool: "contrast" });
    expect(r.isError).toBe(true);
  });
});
