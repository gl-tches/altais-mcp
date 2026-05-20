import { describe, expect, it } from "vitest";
import { FRAMEWORK_IDS, FRAMEWORK_REFERENCES, FrameworkRegistry } from "./frameworks.js";

describe("FrameworkRegistry — bundled data file", () => {
  it("parses the data file and loads all 16 frameworks", async () => {
    const registry = await FrameworkRegistry.load();
    expect(registry.size()).toBe(16);
  });

  it("loads every framework id declared in FRAMEWORK_IDS", async () => {
    const registry = await FrameworkRegistry.load();
    for (const id of FRAMEWORK_IDS) {
      expect(registry.has(id)).toBe(true);
    }
  });

  it("declares exactly 16 framework ids", () => {
    expect(FRAMEWORK_IDS).toHaveLength(16);
    expect(new Set(FRAMEWORK_IDS).size).toBe(16);
  });

  it("gives the 5 priority frameworks 10+ controls each", async () => {
    const registry = await FrameworkRegistry.load();
    for (const id of ["owasp-asvs", "nist-800-53", "nist-ssdf", "cisa-sbd", "nis2"]) {
      const fw = registry.get(id);
      expect(fw, id).toBeDefined();
      expect(fw?.controls.length, id).toBeGreaterThanOrEqual(10);
    }
  });

  it("gives every non-priority framework 5+ controls", async () => {
    const registry = await FrameworkRegistry.load();
    const priority = new Set(["owasp-asvs", "nist-800-53", "nist-ssdf", "cisa-sbd", "nis2"]);
    for (const id of FRAMEWORK_IDS) {
      if (priority.has(id)) continue;
      const fw = registry.get(id);
      expect(fw?.controls.length, id).toBeGreaterThanOrEqual(5);
    }
  });

  it("gives every control a non-empty id and title", async () => {
    const registry = await FrameworkRegistry.load();
    for (const id of FRAMEWORK_IDS) {
      const fw = registry.get(id);
      for (const c of fw?.controls ?? []) {
        expect(c.id.length, `${id}/${c.id}`).toBeGreaterThan(0);
        expect(c.title.length, `${id}/${c.id}`).toBeGreaterThan(0);
      }
    }
  });

  it("uses well-formed CWE identifiers throughout the data file", async () => {
    const registry = await FrameworkRegistry.load();
    for (const id of FRAMEWORK_IDS) {
      const fw = registry.get(id);
      for (const c of fw?.controls ?? []) {
        for (const cwe of c.cwes) {
          expect(cwe, `${id}/${c.id}`).toMatch(/^CWE-\d+$/);
        }
      }
    }
  });

  it("uses lowercase keywords throughout the data file", async () => {
    const registry = await FrameworkRegistry.load();
    for (const id of FRAMEWORK_IDS) {
      const fw = registry.get(id);
      for (const c of fw?.controls ?? []) {
        for (const kw of c.keywords) {
          expect(kw, `${id}/${c.id}`).toBe(kw.toLowerCase());
          expect(kw.length).toBeGreaterThan(0);
        }
      }
    }
  });

  it("looks up a known control by framework and control id", async () => {
    const registry = await FrameworkRegistry.load();
    const ac3 = registry.control("nist-800-53", "AC-3");
    expect(ac3?.title).toBe("Access Enforcement");
  });

  it("returns undefined for an unknown framework or control", async () => {
    const registry = await FrameworkRegistry.load();
    expect(registry.get("nope")).toBeUndefined();
    expect(registry.control("nist-800-53", "NOPE-1")).toBeUndefined();
    expect(registry.control("nope", "AC-3")).toBeUndefined();
  });

  it("exposes a reference URL for every framework", () => {
    for (const id of FRAMEWORK_IDS) {
      expect(FRAMEWORK_REFERENCES[id]).toMatch(/^https:\/\//);
    }
  });

  it("ids() returns all framework ids sorted", async () => {
    const registry = await FrameworkRegistry.load();
    const ids = registry.ids();
    expect(ids).toHaveLength(16);
    expect([...ids]).toEqual([...ids].sort());
  });
});
