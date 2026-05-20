import { describe, expect, it } from "vitest";
import { AttackCatalog, mapToAttack } from "./attack.js";

describe("AttackCatalog.load", () => {
  it("loads the bundled ATT&CK technique catalogue", async () => {
    const catalog = await AttackCatalog.load();
    expect(catalog.size()).toBeGreaterThanOrEqual(40);
    expect(catalog.size()).toBeLessThanOrEqual(70);
  });

  it("every technique has an ATT&CK id, tactic and keywords", async () => {
    const catalog = await AttackCatalog.load();
    for (const t of catalog.all()) {
      expect(t.id).toMatch(/^T\d{4}(?:\.\d{3})?$/);
      expect(t.tactic.length).toBeGreaterThan(0);
      expect(t.keywords.length).toBeGreaterThan(0);
    }
  });
});

describe("mapToAttack — CWE mapping", () => {
  it("maps SQL injection (CWE-89) to Exploit Public-Facing Application", async () => {
    const catalog = await AttackCatalog.load();
    const r = mapToAttack(catalog, { cwe: "CWE-89" });
    expect(r.matches.some((m) => m.id === "T1190")).toBe(true);
  });

  it("maps OS command injection (CWE-78) to Command and Scripting Interpreter", async () => {
    const catalog = await AttackCatalog.load();
    const r = mapToAttack(catalog, { cwe: "CWE-78" });
    expect(r.matches.some((m) => m.id === "T1059")).toBe(true);
  });

  it("maps hardcoded credentials (CWE-798) to Unsecured Credentials", async () => {
    const catalog = await AttackCatalog.load();
    const r = mapToAttack(catalog, { cwe: "CWE-798" });
    expect(r.matches.some((m) => m.id === "T1552")).toBe(true);
  });

  it("accepts a bare numeric CWE id", async () => {
    const catalog = await AttackCatalog.load();
    const r = mapToAttack(catalog, { cwe: "22" });
    expect(r.query.cwe).toBe("CWE-22");
    expect(r.matches.length).toBeGreaterThan(0);
  });

  it("ranks the top match with the highest normalized score", async () => {
    const catalog = await AttackCatalog.load();
    const r = mapToAttack(catalog, { cwe: "CWE-89" });
    expect(r.matches[0]?.score).toBe(1);
    for (let i = 1; i < r.matches.length; i++) {
      expect(r.matches[i]?.score ?? 0).toBeLessThanOrEqual(r.matches[i - 1]?.score ?? 1);
    }
  });
});

describe("mapToAttack — description mapping", () => {
  it("matches a free-text description against technique keywords", async () => {
    const catalog = await AttackCatalog.load();
    const r = mapToAttack(catalog, {
      description: "An attacker uploads a malicious web shell to gain persistence on the server.",
    });
    expect(r.matches.some((m) => m.id === "T1505.003")).toBe(true);
  });

  it("matches a denial-of-service description", async () => {
    const catalog = await AttackCatalog.load();
    const r = mapToAttack(catalog, {
      description: "Uncontrolled resource consumption leads to denial of service.",
    });
    expect(r.matches.some((m) => m.id === "T1499")).toBe(true);
  });

  it("combines CWE and description signals and reports reasons", async () => {
    const catalog = await AttackCatalog.load();
    const r = mapToAttack(catalog, {
      cwe: "CWE-22",
      description: "Path traversal allows arbitrary file read outside the web root.",
    });
    const top = r.matches.find((m) => m.id === "T1083.001" || m.id === "T1190");
    expect(top).toBeDefined();
    expect(r.matches[0]?.reasons.length).toBeGreaterThan(0);
  });

  it("respects the limit parameter", async () => {
    const catalog = await AttackCatalog.load();
    const r = mapToAttack(catalog, { cwe: "CWE-78", description: "command shell", limit: 3 });
    expect(r.matches.length).toBeLessThanOrEqual(3);
  });

  it("returns an empty match list when nothing matches", async () => {
    const catalog = await AttackCatalog.load();
    const r = mapToAttack(catalog, { cwe: "CWE-1426" });
    expect(r.total_matched).toBe(0);
  });

  it("is deterministic across repeated mapping", async () => {
    const catalog = await AttackCatalog.load();
    const a = mapToAttack(catalog, { cwe: "CWE-89", description: "sql injection" });
    const b = mapToAttack(catalog, { cwe: "CWE-89", description: "sql injection" });
    expect(JSON.stringify(a)).toBe(JSON.stringify(b));
  });
});
