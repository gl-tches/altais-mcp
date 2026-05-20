import { describe, expect, it } from "vitest";
import { FindingStore } from "../../core/report.js";
import type { CallToolResult } from "@modelcontextprotocol/sdk/types.js";
import type { ToolDefinition } from "../../core/types.js";
import { createRuntimeModule } from "./index.js";

function toolByName(name: string): ToolDefinition {
  const mod = createRuntimeModule({ findingStore: new FindingStore() });
  const tool = mod.tools.find((t) => t.name === name);
  if (tool === undefined) throw new Error(`tool ${name} not found`);
  return tool;
}

function resultText(r: CallToolResult): string {
  const first = r.content[0];
  if (first?.type !== "text") return "";
  return first.text;
}

describe("createRuntimeModule", () => {
  it("registers three tools with read-only annotations", () => {
    const mod = createRuntimeModule({ findingStore: new FindingStore() });
    expect(mod.name).toBe("runtime");
    expect(mod.version).toBe("0.5.0");
    expect(mod.tools).toHaveLength(3);
    for (const t of mod.tools) {
      expect(t.annotations.readOnlyHint).toBe(true);
      expect(t.annotations.destructiveHint).toBe(false);
      expect(t.inputSchema).toBeDefined();
    }
  });
});

describe("altais_generate_waf_rules tool", () => {
  it("returns a WAF artifact for valid input", async () => {
    const tool = toolByName("altais_generate_waf_rules");
    const r = await tool.handler({
      config: { platform: "modsecurity", protect_against: ["sql-injection"] },
    });
    expect(r.isError).toBeFalsy();
    const parsed = JSON.parse(resultText(r)) as Record<string, unknown>;
    expect(parsed.platform).toBe("modsecurity");
  });

  it("rejects an invalid platform", async () => {
    const tool = toolByName("altais_generate_waf_rules");
    const r = await tool.handler({
      config: { platform: "bogus", protect_against: ["xss"] },
    });
    expect(r.isError).toBe(true);
  });

  it("rejects an empty protect_against list", async () => {
    const tool = toolByName("altais_generate_waf_rules");
    const r = await tool.handler({
      config: { platform: "cloudflare", protect_against: [] },
    });
    expect(r.isError).toBe(true);
  });
});

describe("altais_recommend_rasp tool", () => {
  it("returns a RASP recommendation for valid input", async () => {
    const tool = toolByName("altais_recommend_rasp");
    const r = await tool.handler({
      config: {
        language: "java",
        framework: "spring-boot",
        deployment: "container",
        risk_tolerance: "medium",
      },
    });
    expect(r.isError).toBeFalsy();
    const parsed = JSON.parse(resultText(r)) as Record<string, unknown>;
    expect(parsed.language).toBe("java");
  });

  it("rejects an invalid language", async () => {
    const tool = toolByName("altais_recommend_rasp");
    const r = await tool.handler({
      config: {
        language: "cobol",
        framework: "x",
        deployment: "vm",
        risk_tolerance: "low",
      },
    });
    expect(r.isError).toBe(true);
  });
});

describe("altais_audit_monitoring tool", () => {
  it("pushes findings into the store for a poor posture", async () => {
    const store = new FindingStore();
    const mod = createRuntimeModule({ findingStore: store });
    const tool = mod.tools.find((t) => t.name === "altais_audit_monitoring");
    expect(tool).toBeDefined();
    const r = await tool?.handler({
      config: {
        logs_authentication: false,
        logs_authorization_failures: false,
        logs_input_validation_failures: false,
        logs_admin_actions: false,
        alerting_enabled: false,
        alert_routing: false,
        siem_integrated: false,
        metrics_collected: false,
        anomaly_detection: false,
        dashboards: false,
        on_call: false,
        mean_time_to_detect_minutes: 300,
      },
    });
    expect(r?.isError).toBeFalsy();
    expect(store.all().length).toBeGreaterThan(0);
  });

  it("rejects a non-integer MTTD", async () => {
    const tool = toolByName("altais_audit_monitoring");
    const r = await tool.handler({
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
        mean_time_to_detect_minutes: 12.5,
      },
    });
    expect(r.isError).toBe(true);
  });
});
