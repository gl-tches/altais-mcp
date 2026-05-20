import { describe, expect, it } from "vitest";
import { CweDatabase, lookupCwe } from "./cwe.js";

describe("lookupCwe", () => {
  it("returns the full entry for a known CWE", async () => {
    const db = await CweDatabase.load();
    const r = lookupCwe(db, "CWE-79");
    expect(r.found).toBe(true);
    if (r.found) {
      expect(r.entry.id).toBe("CWE-79");
      expect(r.entry.name).toMatch(/Cross-site Scripting|Scripting/i);
      expect(r.entry.description.length).toBeGreaterThan(20);
      expect(r.entry.references.length).toBeGreaterThan(0);
    }
  });

  it("accepts a bare numeric id", async () => {
    const db = await CweDatabase.load();
    const r = lookupCwe(db, "89");
    expect(r.found).toBe(true);
    if (r.found) expect(r.entry.id).toBe("CWE-89");
  });

  it("accepts a lowercase id with no separator", async () => {
    const db = await CweDatabase.load();
    const r = lookupCwe(db, "cwe22");
    expect(r.found).toBe(true);
    if (r.found) expect(r.entry.id).toBe("CWE-22");
  });

  it("surfaces related CWEs for a CWE in the curated relation map", async () => {
    const db = await CweDatabase.load();
    const r = lookupCwe(db, "CWE-79");
    expect(r.found).toBe(true);
    if (r.found) {
      expect(r.related.length).toBeGreaterThan(0);
      // CWE-79 ChildOf CWE-20 (Improper Input Validation), which is in the DB.
      expect(r.related.some((rel) => rel.id === "CWE-20")).toBe(true);
      expect(r.related.every((rel) => /^(ChildOf|ParentOf|PeerOf)$/.test(rel.relation))).toBe(true);
    }
  });

  it("includes parent relations for a child weakness", async () => {
    const db = await CweDatabase.load();
    const r = lookupCwe(db, "CWE-78");
    expect(r.found).toBe(true);
    if (r.found) {
      // CWE-78 ChildOf CWE-77, both in the bundled DB.
      expect(r.related.some((rel) => rel.id === "CWE-77" && rel.relation === "ChildOf")).toBe(true);
    }
  });

  it("does not list a CWE as related to itself", async () => {
    const db = await CweDatabase.load();
    const r = lookupCwe(db, "CWE-89");
    expect(r.found).toBe(true);
    if (r.found) {
      expect(r.related.some((rel) => rel.id === "CWE-89")).toBe(false);
    }
  });

  it("only includes related CWEs that exist in the bundled database", async () => {
    const db = await CweDatabase.load();
    const r = lookupCwe(db, "CWE-22");
    expect(r.found).toBe(true);
    if (r.found) {
      for (const rel of r.related) {
        expect(db.lookup(rel.id)).toBeDefined();
      }
    }
  });

  it("returns an actionable error for an unknown CWE id", async () => {
    const db = await CweDatabase.load();
    const r = lookupCwe(db, "CWE-99999");
    expect(r.found).toBe(false);
    if (!r.found) {
      expect(r.message).toMatch(/cwe\.mitre\.org/);
      expect(r.message).toMatch(/not in the bundled/i);
    }
  });

  it("returns an actionable error for a malformed CWE id", async () => {
    const db = await CweDatabase.load();
    const r = lookupCwe(db, "xyz");
    expect(r.found).toBe(false);
    if (!r.found) expect(r.message).toMatch(/not a valid CWE/i);
  });

  it("is deterministic across repeated lookups", async () => {
    const db = await CweDatabase.load();
    const a = lookupCwe(db, "CWE-79");
    const b = lookupCwe(db, "CWE-79");
    expect(JSON.stringify(a)).toBe(JSON.stringify(b));
  });
});
