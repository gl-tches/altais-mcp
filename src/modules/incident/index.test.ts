import { describe, expect, it } from "vitest";
import type { CallToolResult } from "@modelcontextprotocol/sdk/types.js";
import { FindingStore } from "../../core/report.js";
import { createIncidentModule } from "./index.js";

/** Invoke a tool handler, asserting it resolves synchronously to a result. */
function call(
  handler: (args: Record<string, unknown>) => Promise<CallToolResult> | CallToolResult,
  args: Record<string, unknown>,
): CallToolResult {
  const result = handler(args);
  if (result instanceof Promise) throw new Error("handler returned a Promise");
  return result;
}

function parse(result: CallToolResult): unknown {
  const first = result.content[0];
  if (first?.type !== "text") throw new Error("no text content");
  return JSON.parse(first.text);
}

describe("createIncidentModule", () => {
  it("registers seven tools", () => {
    const mod = createIncidentModule({ findingStore: new FindingStore() });
    expect(mod.name).toBe("incident");
    expect(mod.version).toBe("0.5.0");
    expect(mod.tools).toHaveLength(7);
  });

  it("declares read-only, non-destructive annotations on every tool", () => {
    const mod = createIncidentModule({ findingStore: new FindingStore() });
    for (const tool of mod.tools) {
      expect(tool.annotations.readOnlyHint).toBe(true);
      expect(tool.annotations.destructiveHint).toBe(false);
      expect(tool.annotations.idempotentHint).toBe(true);
      expect(tool.annotations.openWorldHint).toBe(false);
      expect(tool.inputSchema).toBeDefined();
    }
  });

  it("auditor tools push findings into the shared store", () => {
    const store = new FindingStore();
    const mod = createIncidentModule({ findingStore: store });
    const logging = mod.tools.find((t) => t.name === "altais_audit_logging");
    expect(logging).toBeDefined();
    if (logging !== undefined) call(logging.handler, { config: { has_audit_log: false } });
    expect(store.size()).toBeGreaterThan(0);
  });

  it("generator tools return an artifact without pushing findings", () => {
    const store = new FindingStore();
    const mod = createIncidentModule({ findingStore: store });
    const playbook = mod.tools.find((t) => t.name === "altais_generate_playbook");
    expect(playbook).toBeDefined();
    if (playbook !== undefined) {
      const body = parse(call(playbook.handler, { scenario: "ransomware" })) as {
        phases: unknown[];
      };
      expect(body.phases.length).toBe(6);
    }
    expect(store.size()).toBe(0);
  });

  it("returns an error result for invalid auditor input", () => {
    const mod = createIncidentModule({ findingStore: new FindingStore() });
    const logging = mod.tools.find((t) => t.name === "altais_audit_logging");
    expect(logging).toBeDefined();
    if (logging !== undefined) {
      expect(call(logging.handler, {}).isError).toBe(true);
    }
  });

  it("returns an error result for invalid generator input", () => {
    const mod = createIncidentModule({ findingStore: new FindingStore() });
    const advisory = mod.tools.find((t) => t.name === "altais_draft_advisory");
    expect(advisory).toBeDefined();
    if (advisory !== undefined) {
      expect(call(advisory.handler, { config: { title: "x" } }).isError).toBe(true);
    }
  });
});
