import { describe, expect, it } from "vitest";
import { auditCodeExecution } from "./code-execution.js";

describe("auditCodeExecution — config", () => {
  it("flags executing generated code with no sandbox as critical", () => {
    const f = auditCodeExecution({
      config: { executes_generated_code: true, sandboxed: false },
    });
    const hit = f.find((x) => x.rule === "code-exec-no-sandbox");
    expect(hit?.severity).toBe("critical");
  });

  it("flags sandbox_type 'none' as unsandboxed", () => {
    const f = auditCodeExecution({
      config: { executes_generated_code: true, sandbox_type: "none" },
    });
    expect(f.some((x) => x.rule === "code-exec-no-sandbox")).toBe(true);
  });

  it("flags a sandbox with network and filesystem access", () => {
    const f = auditCodeExecution({
      config: {
        executes_generated_code: true,
        sandboxed: true,
        sandbox_type: "gvisor",
        network_access_in_sandbox: true,
        filesystem_access_in_sandbox: true,
      },
    });
    expect(f.map((x) => x.rule)).toEqual(
      expect.arrayContaining([
        "code-exec-sandbox-network-access",
        "code-exec-sandbox-filesystem-access",
      ]),
    );
    expect(f.some((x) => x.rule === "code-exec-no-sandbox")).toBe(false);
  });

  it("flags missing allowlist and resource limits", () => {
    const f = auditCodeExecution({
      config: {
        executes_generated_code: true,
        sandboxed: true,
        allowlist_enforced: false,
        resource_limits: false,
      },
    });
    expect(f.map((x) => x.rule)).toEqual(
      expect.arrayContaining(["code-exec-no-allowlist", "code-exec-no-resource-limits"]),
    );
  });
});

describe("auditCodeExecution — source", () => {
  it("flags eval() near a model output variable", () => {
    const f = auditCodeExecution({
      source: "const llmResult = call();\neval(llmResult);",
    });
    const hit = f.find((x) => x.rule === "code-exec-model-output-to-sink");
    expect(hit?.severity).toBe("critical");
  });

  it("flags child_process driven by a generated command", () => {
    const f = auditCodeExecution({
      source: "child_process.execSync(generatedCommand)",
    });
    expect(f.some((x) => x.rule === "code-exec-model-output-to-sink")).toBe(true);
  });

  it("does not flag eval() unrelated to model output", () => {
    const f = auditCodeExecution({ source: "const total = eval('1 + 2');" });
    expect(f.some((x) => x.rule === "code-exec-model-output-to-sink")).toBe(false);
  });
});

describe("auditCodeExecution — negative", () => {
  it("returns nothing for a hardened config", () => {
    const f = auditCodeExecution({
      config: {
        executes_generated_code: true,
        sandboxed: true,
        sandbox_type: "microvm",
        allowlist_enforced: true,
        network_access_in_sandbox: false,
        filesystem_access_in_sandbox: false,
        resource_limits: true,
      },
    });
    expect(f).toHaveLength(0);
  });

  it("returns nothing when no config or source is supplied", () => {
    expect(auditCodeExecution({})).toHaveLength(0);
  });
});

describe("auditCodeExecution — shape & determinism", () => {
  it("produces deterministic IDs across runs", () => {
    const a = auditCodeExecution({ config: { executes_generated_code: true, sandboxed: false } });
    const b = auditCodeExecution({ config: { executes_generated_code: true, sandboxed: false } });
    expect(a.map((x) => x.id)).toEqual(b.map((x) => x.id));
  });

  it("tags every finding with the module, a CWE, and ASI05", () => {
    const f = auditCodeExecution({
      config: { executes_generated_code: true, sandboxed: false },
    });
    expect(f.length).toBeGreaterThan(0);
    for (const x of f) {
      expect(x.module).toBe("agentic");
      expect((x.cwe ?? []).length).toBeGreaterThan(0);
      expect(x.tags).toContain("agentic");
      expect(x.tags).toContain("ASI05");
    }
  });
});
