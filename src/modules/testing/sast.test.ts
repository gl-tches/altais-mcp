import { describe, expect, it } from "vitest";
import { generateSastConfig, SastConfigError } from "./sast.js";

describe("generateSastConfig — per tool", () => {
  it("generates a Semgrep ruleset with security rule packs", () => {
    const r = generateSastConfig({ tool: "semgrep", languages: ["python"] });
    expect(r.config_file.filename).toBe(".semgrep.yml");
    expect(r.rule_packs).toContain("p/security-audit");
    expect(r.ci_snippet.content).toContain("semgrep ci");
  });

  it("generates a CodeQL config and workflow with a language matrix", () => {
    const r = generateSastConfig({ tool: "codeql", languages: ["java", "javascript"] });
    expect(r.config_file.content).toContain("security-extended");
    expect(r.ci_snippet.content).toContain("- java");
    expect(r.ci_snippet.content).toContain("- javascript");
  });

  it("generates a .bandit config", () => {
    const r = generateSastConfig({ tool: "bandit", languages: ["python"] });
    expect(r.config_file.filename).toBe(".bandit");
    expect(r.config_file.content).toContain("[bandit]");
  });

  it("generates a gosec config", () => {
    const r = generateSastConfig({ tool: "gosec", languages: ["go"] });
    expect(r.config_file.filename).toBe(".gosec.json");
    expect(r.ci_snippet.content).toContain("securego/gosec");
  });

  it("generates an ESLint security flat config", () => {
    const r = generateSastConfig({ tool: "eslint-security", languages: ["javascript"] });
    expect(r.config_file.content).toContain("eslint-plugin-security");
    expect(r.config_file.content).toContain("detect-child-process");
  });

  it("generates a Brakeman config", () => {
    const r = generateSastConfig({ tool: "brakeman", languages: ["ruby"] });
    expect(r.config_file.content).toContain("run_all_checks");
    expect(r.rule_packs.join(" ")).toContain("SQL injection");
  });
});

describe("generateSastConfig — shape", () => {
  it("always includes notes and references", () => {
    const r = generateSastConfig({ tool: "semgrep", languages: ["go"] });
    expect(r.notes.length).toBeGreaterThan(0);
    expect(r.references.length).toBeGreaterThan(0);
  });

  it("rejects an empty languages list", () => {
    expect(() => generateSastConfig({ tool: "semgrep", languages: [] })).toThrow(SastConfigError);
  });

  it("is deterministic for the same input", () => {
    const a = generateSastConfig({ tool: "codeql", languages: ["python"] });
    const b = generateSastConfig({ tool: "codeql", languages: ["python"] });
    expect(JSON.stringify(a)).toBe(JSON.stringify(b));
  });
});
