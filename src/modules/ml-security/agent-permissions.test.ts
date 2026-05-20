import { describe, expect, it } from "vitest";
import { auditAgentPermissions } from "./agent-permissions.js";

const rules = (input: Parameters<typeof auditAgentPermissions>[0]): string[] =>
  auditAgentPermissions(input).map((f) => f.rule);

describe("auditAgentPermissions — tool surface", () => {
  it("flags an excessive tool count", () => {
    expect(rules({ config: { tool_count: 40 } })).toContain("agent-excessive-tool-count");
  });

  it("does not flag a small tool count", () => {
    expect(rules({ config: { tool_count: 4 } })).not.toContain("agent-excessive-tool-count");
  });

  it("flags a wildcard scope on a tool", () => {
    expect(rules({ config: { tools: [{ name: "files", scope: "files:*" }] } })).toContain(
      "agent-broad-tool-scope",
    );
  });

  it("flags a wildcard agent-level permission scope", () => {
    expect(rules({ config: { permission_scopes: ["admin"] } })).toContain(
      "agent-broad-permission-scope",
    );
  });

  it("does not flag a narrow scope", () => {
    const r = rules({ config: { tools: [{ name: "files", scope: "files:read" }] } });
    expect(r).not.toContain("agent-broad-tool-scope");
  });
});

describe("auditAgentPermissions — human-in-the-loop", () => {
  it("flags destructive tools with no human approval", () => {
    expect(rules({ config: { has_destructive_tools: true } })).toContain(
      "agent-destructive-tools-no-approval",
    );
  });

  it("does not flag destructive tools when approval is required", () => {
    expect(
      rules({ config: { has_destructive_tools: true, human_approval_required: true } }),
    ).not.toContain("agent-destructive-tools-no-approval");
  });

  it("flags spending money and modifying data without approval", () => {
    const r = rules({ config: { can_spend_money: true, can_modify_data: true } });
    expect(r).toContain("agent-can-spend-money-no-approval");
    expect(r).toContain("agent-can-modify-data-no-approval");
  });

  it("flags code execution and full autonomy with high-impact capabilities", () => {
    const r = rules({ config: { can_execute_code: true, autonomous: true } });
    expect(r).toContain("agent-can-execute-code");
    expect(r).toContain("agent-fully-autonomous-high-risk");
  });

  it("returns no findings for a minimal, gated agent", () => {
    expect(
      auditAgentPermissions({
        config: {
          tools: [{ name: "search", scope: "search:read" }],
          tool_count: 1,
          has_destructive_tools: false,
          human_approval_required: true,
          permission_scopes: ["search:read"],
          autonomous: false,
          can_spend_money: false,
          can_modify_data: false,
          can_execute_code: false,
        },
      }),
    ).toHaveLength(0);
  });
});

describe("auditAgentPermissions — shape and determinism", () => {
  it("produces deterministic finding IDs", () => {
    const a = auditAgentPermissions({ config: { has_destructive_tools: true } });
    const b = auditAgentPermissions({ config: { has_destructive_tools: true } });
    expect(a.map((f) => f.id)).toEqual(b.map((f) => f.id));
  });

  it("tags every finding with the ml_security module, ml-security tag, and a CWE", () => {
    const findings = auditAgentPermissions({
      config: { tool_count: 40, has_destructive_tools: true },
    });
    expect(findings.length).toBeGreaterThan(0);
    for (const f of findings) {
      expect(f.module).toBe("ml_security");
      expect(f.tags).toContain("ml-security");
      expect(f.cwe?.length ?? 0).toBeGreaterThan(0);
    }
  });
});
