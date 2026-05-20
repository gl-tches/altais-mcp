import { describe, expect, it } from "vitest";
import { contentHash, findingId, sortFindingsBySeverity } from "./utils.js";
import type { Finding } from "./types.js";

describe("contentHash", () => {
  it("is deterministic for the same inputs", () => {
    expect(contentHash(["a", 1, "b"])).toBe(contentHash(["a", 1, "b"]));
  });

  it("changes when any input changes", () => {
    expect(contentHash(["a", 1])).not.toBe(contentHash(["a", 2]));
  });

  it("distinguishes undefined from empty string", () => {
    expect(contentHash([undefined, "x"])).not.toBe(contentHash(["", "x"]));
  });
});

describe("findingId", () => {
  it("produces the required format", () => {
    const id = findingId("scan", "sql-injection", { file: "a.ts", line_start: 10 }, "evidence");
    expect(id).toMatch(/^scan:sql-injection:[0-9a-f]{12}$/);
  });

  it("is identical for equivalent locations and evidence", () => {
    const a = findingId("scan", "rule", { file: "x.ts", line_start: 1 }, "evidence");
    const b = findingId("scan", "rule", { file: "x.ts", line_start: 1 }, "evidence");
    expect(a).toBe(b);
  });

  it("differs when location differs", () => {
    const a = findingId("scan", "rule", { file: "x.ts", line_start: 1 }, "evidence");
    const b = findingId("scan", "rule", { file: "x.ts", line_start: 2 }, "evidence");
    expect(a).not.toBe(b);
  });
});

function f(severity: Finding["severity"], id: string): Finding {
  return {
    id,
    module: "m",
    rule: "r",
    severity,
    title: "t",
    description: "d",
    remediation: "fix",
    references: [],
    tags: [],
    status: "open",
  };
}

describe("sortFindingsBySeverity", () => {
  it("orders critical first, info last", () => {
    const input = [f("info", "1"), f("critical", "2"), f("medium", "3"), f("high", "4")];
    const sorted = sortFindingsBySeverity(input);
    expect(sorted.map((x) => x.severity)).toEqual(["critical", "high", "medium", "info"]);
  });

  it("breaks ties by id", () => {
    const sorted = sortFindingsBySeverity([f("high", "b"), f("high", "a")]);
    expect(sorted.map((x) => x.id)).toEqual(["a", "b"]);
  });
});
