import { describe, expect, it } from "vitest";
import { CweDatabase, normalizeCweId } from "./cwe.js";

describe("normalizeCweId", () => {
  it("accepts numeric input", () => {
    expect(normalizeCweId("79")).toBe("CWE-79");
  });

  it("accepts CWE-prefixed input", () => {
    expect(normalizeCweId("CWE-79")).toBe("CWE-79");
    expect(normalizeCweId("cwe-79")).toBe("CWE-79");
    expect(normalizeCweId("cwe 79")).toBe("CWE-79");
    expect(normalizeCweId("CWE79")).toBe("CWE-79");
  });

  it("rejects garbage", () => {
    expect(normalizeCweId("")).toBeNull();
    expect(normalizeCweId("CWE")).toBeNull();
    expect(normalizeCweId("not a cwe")).toBeNull();
  });

  it("trims whitespace", () => {
    expect(normalizeCweId("  79  ")).toBe("CWE-79");
  });
});

describe("CweDatabase", () => {
  it("loads the bundled database", async () => {
    const db = await CweDatabase.load();
    expect(db.size()).toBeGreaterThanOrEqual(100);
  });

  it("looks up known entries", async () => {
    const db = await CweDatabase.load();
    const entry = db.lookup("79");
    expect(entry?.id).toBe("CWE-79");
    expect(entry?.name).toMatch(/Cross-site Scripting/);
    expect(entry?.remediation.length).toBeGreaterThan(20);
  });

  it("returns undefined for unknown CWE", async () => {
    const db = await CweDatabase.load();
    expect(db.lookup("CWE-99999")).toBeUndefined();
  });

  it("returns undefined for invalid input", async () => {
    const db = await CweDatabase.load();
    expect(db.lookup("not a cwe")).toBeUndefined();
  });
});
