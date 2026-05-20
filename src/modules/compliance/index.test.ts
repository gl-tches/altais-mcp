import { beforeEach, describe, expect, it } from "vitest";
import type { CallToolResult } from "@modelcontextprotocol/sdk/types.js";
import { FindingStore } from "../../core/report.js";
import type { Finding, ToolDefinition } from "../../core/types.js";
import { createComplianceModule } from "./index.js";

function textOf(result: CallToolResult): string {
  const first = result.content[0];
  if (first?.type !== "text") {
    throw new Error("expected a text result");
  }
  return first.text;
}

function jsonOf(result: CallToolResult): unknown {
  return JSON.parse(textOf(result));
}

function sampleFinding(rule: string, cwe: readonly string[], title = rule): Finding {
  return {
    id: `scan:${rule}:abc`,
    module: "scan",
    rule,
    severity: "high",
    cwe,
    title,
    description: "d",
    remediation: "r",
    references: [],
    tags: [],
    status: "open",
  };
}

async function setup(): Promise<{
  store: FindingStore;
  tools: Map<string, ToolDefinition>;
}> {
  const store = new FindingStore();
  const mod = createComplianceModule({ findingStore: store });
  await mod.init({});
  const tools = new Map(mod.tools.map((t) => [t.name, t]));
  return { store, tools };
}

describe("createComplianceModule — definition", () => {
  it("declares name compliance and version 0.4.0", () => {
    const mod = createComplianceModule({ findingStore: new FindingStore() });
    expect(mod.name).toBe("compliance");
    expect(mod.version).toBe("0.4.0");
  });

  it("exposes exactly 3 tools", () => {
    const mod = createComplianceModule({ findingStore: new FindingStore() });
    expect(mod.tools).toHaveLength(3);
    expect(mod.tools.map((t) => t.name).sort()).toEqual([
      "altais_gap_analysis",
      "altais_generate_evidence",
      "altais_map_findings",
    ]);
  });

  it("every tool carries the read-only annotations", () => {
    const mod = createComplianceModule({ findingStore: new FindingStore() });
    for (const t of mod.tools) {
      expect(t.annotations).toEqual({
        readOnlyHint: true,
        destructiveHint: false,
        idempotentHint: true,
        openWorldHint: false,
      });
    }
  });

  it("throws if a handler runs before init()", () => {
    const mod = createComplianceModule({ findingStore: new FindingStore() });
    const tool = mod.tools.find((t) => t.name === "altais_map_findings");
    expect(tool).toBeDefined();
    expect(() => tool?.handler({ framework: "nist-800-53", findings: [{ rule: "x" }] })).toThrow(
      /before init/,
    );
  });
});

describe("altais_map_findings", () => {
  let store: FindingStore;
  let tools: Map<string, ToolDefinition>;

  beforeEach(async () => {
    ({ store, tools } = await setup());
  });

  function run(args: Record<string, unknown>): CallToolResult {
    const tool = tools.get("altais_map_findings");
    if (tool === undefined) throw new Error("tool missing");
    return tool.handler(args) as CallToolResult;
  }

  it("maps a CWE-89 finding to the SI-10 control of NIST 800-53", () => {
    const r = run({
      framework: "nist-800-53",
      findings: [{ rule: "sql-injection", cwe: ["CWE-89"], severity: "high" }],
    });
    const data = jsonOf(r) as {
      mappings: { control: { id: string }; status: string }[];
    };
    const si10 = data.mappings.find((m) => m.control.id === "SI-10");
    expect(si10?.status).toBe("addressed");
  });

  it("maps via a keyword when no CWE is supplied", () => {
    const r = run({
      framework: "pci-dss",
      findings: [{ rule: "weak-tls-config", title: "TLS misconfigured" }],
    });
    const data = jsonOf(r) as { summary: { addressed: number } };
    expect(data.summary.addressed).toBeGreaterThan(0);
  });

  it("uses the session FindingStore when findings are omitted", () => {
    store.add(sampleFinding("sql-injection", ["CWE-89"]));
    const r = run({ framework: "nist-800-53" });
    const data = jsonOf(r) as { summary: { mapped_findings: number } };
    expect(data.summary.mapped_findings).toBe(1);
  });

  it("emits an info Finding per addressed control into the store", () => {
    run({
      framework: "owasp-asvs",
      findings: [{ rule: "sql-injection", cwe: ["CWE-89"] }],
    });
    const emitted = store.all().filter((f) => f.module === "compliance");
    expect(emitted.length).toBeGreaterThan(0);
    expect(emitted.every((f) => f.module === "compliance")).toBe(true);
    expect(emitted.some((f) => f.rule.startsWith("mapping:owasp-asvs:"))).toBe(true);
  });

  it("returns a coverage summary with all the expected fields", () => {
    const r = run({ framework: "soc2", findings: [{ rule: "x", cwe: ["CWE-89"] }] });
    const data = jsonOf(r) as { summary: Record<string, unknown> };
    for (const k of [
      "total_controls",
      "addressed",
      "gap",
      "coverage_pct",
      "total_findings",
      "mapped_findings",
    ]) {
      expect(data.summary[k], k).toBeTypeOf("number");
    }
  });

  it("rejects an unknown framework with a validation error", () => {
    const r = run({ framework: "made-up", findings: [] });
    expect(r.isError).toBe(true);
    expect(textOf(r)).toMatch(/Invalid input/);
  });

  it("rejects a finding with a too-long rule string", () => {
    const r = run({
      framework: "gdpr",
      findings: [{ rule: "x".repeat(200) }],
    });
    expect(r.isError).toBe(true);
  });

  it("is deterministic — same input produces identical output", () => {
    const args = {
      framework: "nist-800-53",
      findings: [{ rule: "sql-injection", cwe: ["CWE-89"] }],
    };
    expect(textOf(run(args))).toBe(textOf(run(args)));
  });

  it("emitted findings have deterministic ids", () => {
    run({ framework: "iso-27001", findings: [{ rule: "x", cwe: ["CWE-89"] }] });
    const ids1 = store
      .all()
      .map((f) => f.id)
      .sort();
    run({ framework: "iso-27001", findings: [{ rule: "x", cwe: ["CWE-89"] }] });
    const ids2 = store
      .all()
      .map((f) => f.id)
      .sort();
    expect(ids1).toEqual(ids2);
  });
});

describe("altais_gap_analysis", () => {
  let store: FindingStore;
  let tools: Map<string, ToolDefinition>;

  beforeEach(async () => {
    ({ store, tools } = await setup());
  });

  function run(args: Record<string, unknown>): CallToolResult {
    const tool = tools.get("altais_gap_analysis");
    if (tool === undefined) throw new Error("tool missing");
    return tool.handler(args) as CallToolResult;
  }

  it("reports every control as a gap when there are no findings", () => {
    const r = run({ framework: "cisa-sbd", findings: [] });
    const data = jsonOf(r) as {
      coverage: { addressed: number; gap: number; total_controls: number };
    };
    expect(data.coverage.addressed).toBe(0);
    expect(data.coverage.gap).toBe(data.coverage.total_controls);
  });

  it("classifies a covered control as addressed", () => {
    const r = run({
      framework: "nist-800-53",
      findings: [{ rule: "sql-injection", cwe: ["CWE-89"] }],
    });
    const data = jsonOf(r) as { addressed_controls: { id: string }[] };
    expect(data.addressed_controls.some((c) => c.id === "SI-10")).toBe(true);
  });

  it("lists uncovered controls in gap_controls", () => {
    const r = run({ framework: "nist-800-53", findings: [] });
    const data = jsonOf(r) as { gap_controls: { id: string }[] };
    expect(data.gap_controls.length).toBeGreaterThan(0);
    expect(data.gap_controls.some((c) => c.id === "AC-3")).toBe(true);
  });

  it("emits a Finding per gap control into the store", () => {
    run({ framework: "soc2", findings: [] });
    const emitted = store.all().filter((f) => f.rule.startsWith("gap:soc2:"));
    expect(emitted.length).toBeGreaterThan(0);
  });

  it("rates access-control / crypto gaps as high severity", () => {
    run({ framework: "nist-800-53", findings: [] });
    const ac3 = store.all().find((f) => f.rule === "gap:nist-800-53:AC-3");
    expect(ac3?.severity).toBe("high");
  });

  it("rates other gaps as medium severity", () => {
    run({ framework: "nist-800-53", findings: [] });
    const au2 = store.all().find((f) => f.rule === "gap:nist-800-53:AU-2");
    expect(au2?.severity).toBe("medium");
  });

  it("computes a coverage percentage", () => {
    const r = run({
      framework: "owasp-asvs",
      findings: [{ rule: "sql-injection", cwe: ["CWE-89"] }],
    });
    const data = jsonOf(r) as { coverage: { coverage_pct: number } };
    expect(data.coverage.coverage_pct).toBeGreaterThan(0);
    expect(data.coverage.coverage_pct).toBeLessThan(100);
  });

  it("emitted gap findings have module compliance", () => {
    run({ framework: "gdpr", findings: [] });
    const emitted = store.all().filter((f) => f.rule.startsWith("gap:gdpr:"));
    expect(emitted.every((f) => f.module === "compliance")).toBe(true);
  });

  it("emitted gap findings carry real reference URLs", () => {
    run({ framework: "pci-dss", findings: [] });
    const emitted = store.all().filter((f) => f.rule.startsWith("gap:pci-dss:"));
    const first = emitted[0];
    expect(first).toBeDefined();
    expect(first?.references.some((u) => u.includes("pcisecuritystandards.org"))).toBe(true);
  });

  it("rejects an unknown framework", () => {
    const r = run({ framework: "bogus", findings: [] });
    expect(r.isError).toBe(true);
  });

  it("is deterministic", () => {
    const args = { framework: "nis2", findings: [{ rule: "x", cwe: ["CWE-89"] }] };
    expect(textOf(run(args))).toBe(textOf(run(args)));
  });
});

describe("altais_generate_evidence", () => {
  let tools: Map<string, ToolDefinition>;

  beforeEach(async () => {
    ({ tools } = await setup());
  });

  function run(args: Record<string, unknown>): CallToolResult {
    const tool = tools.get("altais_generate_evidence");
    if (tool === undefined) throw new Error("tool missing");
    return tool.handler(args) as CallToolResult;
  }

  it("generates an evidence record for every control by default", () => {
    const r = run({ framework: "soc2", findings: [] });
    const data = jsonOf(r) as { evidence: unknown[]; summary: { controls_in_pack: number } };
    expect(data.evidence.length).toBe(data.summary.controls_in_pack);
    expect(data.evidence.length).toBeGreaterThan(0);
  });

  it("marks a control as addressed when a finding maps to it", () => {
    const r = run({
      framework: "nist-800-53",
      findings: [{ rule: "sql-injection", cwe: ["CWE-89"] }],
    });
    const data = jsonOf(r) as { evidence: { control_id: string; status: string }[] };
    const si10 = data.evidence.find((e) => e.control_id === "SI-10");
    expect(si10?.status).toBe("addressed");
  });

  it("marks an unassessed control as a gap", () => {
    const r = run({ framework: "nist-800-53", findings: [] });
    const data = jsonOf(r) as { evidence: { status: string }[] };
    expect(data.evidence.every((e) => e.status === "gap")).toBe(true);
  });

  it("filters the pack to the requested control_ids", () => {
    const r = run({
      framework: "nist-800-53",
      control_ids: ["AC-3", "SC-13"],
      findings: [],
    });
    const data = jsonOf(r) as { evidence: { control_id: string }[] };
    expect(data.evidence.map((e) => e.control_id).sort()).toEqual(["AC-3", "SC-13"]);
  });

  it("includes a generated evidence statement on each record", () => {
    const r = run({ framework: "gdpr", control_ids: ["Art.32"], findings: [] });
    const data = jsonOf(r) as { evidence: { evidence_statement: string }[] };
    const first = data.evidence[0];
    expect(first).toBeDefined();
    expect(first?.evidence_statement.length).toBeGreaterThan(0);
  });

  it("lists evidence findings for an addressed control", () => {
    const r = run({
      framework: "owasp-asvs",
      findings: [{ rule: "sql-injection", cwe: ["CWE-89"], title: "SQLi" }],
    });
    const data = jsonOf(r) as {
      evidence: { status: string; evidence_findings: unknown[] }[];
    };
    const addressed = data.evidence.find((e) => e.status === "addressed");
    expect(addressed).toBeDefined();
    expect(addressed?.evidence_findings.length).toBeGreaterThan(0);
  });

  it("includes the framework reference URL", () => {
    const r = run({ framework: "owasp-asvs", findings: [] });
    const data = jsonOf(r) as { reference: string };
    expect(data.reference).toMatch(/^https:\/\/owasp\.org/);
  });

  it("errors when no control_ids match the framework", () => {
    const r = run({ framework: "nist-800-53", control_ids: ["ZZ-99"], findings: [] });
    expect(r.isError).toBe(true);
    expect(textOf(r)).toMatch(/No matching controls/);
  });

  it("rejects an unknown framework", () => {
    const r = run({ framework: "nope", findings: [] });
    expect(r.isError).toBe(true);
  });

  it("is deterministic", () => {
    const args = {
      framework: "nist-ssdf",
      findings: [{ rule: "sql-injection", cwe: ["CWE-89"] }],
    };
    expect(textOf(run(args))).toBe(textOf(run(args)));
  });

  it("reports an addressed/gap summary that sums to the pack size", () => {
    const r = run({
      framework: "nist-800-53",
      findings: [{ rule: "sql-injection", cwe: ["CWE-89"] }],
    });
    const data = jsonOf(r) as {
      summary: { controls_in_pack: number; addressed: number; gap: number };
    };
    expect(data.summary.addressed + data.summary.gap).toBe(data.summary.controls_in_pack);
  });
});
