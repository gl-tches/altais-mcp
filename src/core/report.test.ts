import { describe, expect, it } from "vitest";
import { FindingStore, hashJson, renderJsonReport, renderMarkdownReport } from "./report.js";
import type { Finding } from "./types.js";

function f(overrides: Partial<Finding> = {}): Finding {
  return {
    id: "scan:rule:abcd",
    module: "scan",
    rule: "rule",
    severity: "high",
    title: "Test finding",
    description: "A finding for testing.",
    remediation: "Do the thing.",
    references: ["https://example.com/cwe"],
    tags: [],
    status: "open",
    ...overrides,
  };
}

describe("FindingStore", () => {
  it("deduplicates by id", () => {
    const store = new FindingStore();
    store.add(f({ id: "x" }));
    store.add(f({ id: "x" }));
    expect(store.size()).toBe(1);
  });

  it("summarizes by severity and module", () => {
    const store = new FindingStore();
    store.addMany([
      f({ id: "1", severity: "critical" }),
      f({ id: "2", severity: "high", module: "secrets" }),
      f({ id: "3", severity: "medium" }),
    ]);
    const summary = store.summarize();
    expect(summary.total).toBe(3);
    expect(summary.by_severity.critical).toBe(1);
    expect(summary.by_severity.high).toBe(1);
    expect(summary.by_module.scan).toBe(2);
    expect(summary.by_module.secrets).toBe(1);
    expect(summary.risk_score).toBeGreaterThan(0);
  });

  it("returns sorted findings in result()", () => {
    const store = new FindingStore();
    store.addMany([
      f({ id: "a", severity: "info" }),
      f({ id: "b", severity: "critical" }),
      f({ id: "c", severity: "low" }),
    ]);
    const result = store.result(["core", "scan"], "deadbeef");
    expect(result.findings.map((x) => x.severity)).toEqual(["critical", "low", "info"]);
    expect(result.metadata.modules_active).toEqual(["core", "scan"]);
    expect(result.metadata.config_hash).toBe("deadbeef");
  });

  it("clear() empties the store", () => {
    const store = new FindingStore();
    store.add(f());
    store.clear();
    expect(store.size()).toBe(0);
  });
});

describe("renderMarkdownReport", () => {
  it("includes summary and findings", () => {
    const store = new FindingStore();
    store.addMany([
      f({ id: "1", severity: "critical", title: "RCE risk" }),
      f({ id: "2", severity: "info", title: "Info note" }),
    ]);
    const md = renderMarkdownReport(store.result(["core"], "abc"), false);
    expect(md).toMatch(/# altais-mcp Security Report/);
    expect(md).toMatch(/Risk score/);
    expect(md).toMatch(/RCE risk/);
    expect(md).not.toMatch(/Info note/);
  });

  it("includes info findings when requested", () => {
    const store = new FindingStore();
    store.add(f({ id: "1", severity: "info", title: "Info note" }));
    const md = renderMarkdownReport(store.result(["core"], "abc"), true);
    expect(md).toMatch(/Info note/);
  });

  it("renders 'no findings' when empty", () => {
    const store = new FindingStore();
    const md = renderMarkdownReport(store.result(["core"], "abc"), false);
    expect(md).toMatch(/No findings to report/);
  });
});

describe("renderMarkdownReport — module-level breakdowns", () => {
  it("groups findings under per-module sections by default", () => {
    const store = new FindingStore();
    store.addMany([
      f({ id: "1", module: "scan", severity: "high", title: "SQL injection" }),
      f({ id: "2", module: "auth", severity: "critical", title: "Bad JWT" }),
      f({ id: "3", module: "scan", severity: "medium", title: "Path traversal" }),
    ]);
    const md = renderMarkdownReport(store.result(["core", "scan", "auth"], "abc"), false);
    expect(md).toMatch(/`scan` module \(2 findings\)/);
    expect(md).toMatch(/`auth` module \(1 finding\)/);
  });

  it("emits a Module summary table with per-severity columns", () => {
    const store = new FindingStore();
    store.addMany([
      f({ id: "1", module: "scan", severity: "high" }),
      f({ id: "2", module: "scan", severity: "critical" }),
      f({ id: "3", module: "auth", severity: "medium" }),
    ]);
    const md = renderMarkdownReport(store.result(["core"], "x"), false);
    expect(md).toMatch(/\| Module \| Total \| Critical \| High \| Medium \| Low \| Info \|/);
    expect(md).toMatch(/\| scan \| 2 \| 1 \| 1 \| 0 \| 0 \| 0 \|/);
    expect(md).toMatch(/\| auth \| 1 \| 0 \| 0 \| 1 \| 0 \| 0 \|/);
  });

  it("falls back to flat severity ordering when group_by=`severity`", () => {
    const store = new FindingStore();
    store.addMany([
      f({ id: "1", module: "scan", severity: "high" }),
      f({ id: "2", module: "auth", severity: "critical" }),
    ]);
    const md = renderMarkdownReport(store.result(["core"], "abc"), false, "severity");
    expect(md).not.toMatch(/`scan` module/);
    expect(md).toMatch(/CRITICAL/);
    expect(md).toMatch(/HIGH/);
  });
});

describe("renderJsonReport", () => {
  it("emits parseable JSON", () => {
    const store = new FindingStore();
    store.add(f({ id: "1", severity: "high" }));
    const json = renderJsonReport(store.result(["core"], "abc"), false);
    const parsed = JSON.parse(json) as { findings: unknown[] };
    expect(parsed.findings).toHaveLength(1);
  });

  it("includes a `by_module` breakdown", () => {
    const store = new FindingStore();
    store.addMany([
      f({ id: "1", module: "scan", severity: "high" }),
      f({ id: "2", module: "scan", severity: "critical" }),
      f({ id: "3", module: "auth", severity: "medium" }),
    ]);
    const json = renderJsonReport(store.result(["core"], "abc"), false);
    const parsed = JSON.parse(json) as {
      by_module: {
        module: string;
        total: number;
        findings: unknown[];
        by_severity: Record<string, number>;
      }[];
    };
    expect(parsed.by_module.length).toBe(2);
    const scan = parsed.by_module.find((m) => m.module === "scan");
    expect(scan?.total).toBe(2);
    expect(scan?.by_severity.critical).toBe(1);
    expect(scan?.by_severity.high).toBe(1);
    const auth = parsed.by_module.find((m) => m.module === "auth");
    expect(auth?.total).toBe(1);
  });

  it("filters info findings from by_module unless include_info is true", () => {
    const store = new FindingStore();
    store.addMany([
      f({ id: "1", module: "scan", severity: "high" }),
      f({ id: "2", module: "scan", severity: "info" }),
    ]);
    const json = renderJsonReport(store.result(["core"], "abc"), false);
    const parsed = JSON.parse(json) as {
      by_module: { findings: unknown[]; total: number }[];
    };
    expect(parsed.by_module[0]?.total).toBe(1);
  });
});

describe("hashJson", () => {
  it("is stable for the same value", () => {
    expect(hashJson({ a: 1, b: 2 })).toBe(hashJson({ a: 1, b: 2 }));
  });

  it("differs for different values", () => {
    expect(hashJson({ a: 1 })).not.toBe(hashJson({ a: 2 }));
  });
});
