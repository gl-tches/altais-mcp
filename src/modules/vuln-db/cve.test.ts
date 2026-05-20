import { describe, expect, it } from "vitest";
import { CveDatabase, lookupCve, normalizeCveId } from "./cve.js";

describe("CveDatabase.load", () => {
  it("loads the bundled CVE snapshot with a curated set of CVEs", async () => {
    const db = await CveDatabase.load();
    expect(db.size()).toBeGreaterThanOrEqual(35);
    expect(db.size()).toBeLessThanOrEqual(60);
  });

  it("includes well-known high-impact CVEs", async () => {
    const db = await CveDatabase.load();
    for (const id of ["CVE-2021-44228", "CVE-2014-0160", "CVE-2024-3094"]) {
      expect(db.lookup(id)).toBeDefined();
    }
  });
});

describe("normalizeCveId", () => {
  it("normalizes a valid lowercase id to upper-case", () => {
    expect(normalizeCveId("cve-2021-44228")).toBe("CVE-2021-44228");
  });

  it("trims surrounding whitespace", () => {
    expect(normalizeCveId("  CVE-2014-0160  ")).toBe("CVE-2014-0160");
  });

  it("rejects a malformed identifier", () => {
    expect(normalizeCveId("CVE-21-1")).toBeNull();
    expect(normalizeCveId("not-a-cve")).toBeNull();
    expect(normalizeCveId("")).toBeNull();
  });
});

describe("lookupCve", () => {
  it("returns the full entry for a known CVE", async () => {
    const db = await CveDatabase.load();
    const r = lookupCve(db, "CVE-2021-44228");
    expect(r.found).toBe(true);
    if (r.found) {
      expect(r.cve.id).toBe("CVE-2021-44228");
      expect(r.cve.severity).toBe("critical");
      expect(r.cve.cwe.length).toBeGreaterThan(0);
      expect(r.cve.cwe).toContain("CWE-502");
      expect(r.cve.references.length).toBeGreaterThan(0);
      expect(r.cve.remediation.length).toBeGreaterThan(10);
    }
  });

  it("is case-insensitive on the CVE id", async () => {
    const db = await CveDatabase.load();
    const r = lookupCve(db, "cve-2014-0160");
    expect(r.found).toBe(true);
    if (r.found) expect(r.cve.id).toBe("CVE-2014-0160");
  });

  it("returns an actionable error for an unknown but well-formed CVE", async () => {
    const db = await CveDatabase.load();
    const r = lookupCve(db, "CVE-1999-0001");
    expect(r.found).toBe(false);
    if (!r.found) {
      expect(r.message).toMatch(/curated offline/i);
      expect(r.message).toMatch(/nvd\.nist\.gov/);
    }
  });

  it("returns an actionable error for a malformed CVE id", async () => {
    const db = await CveDatabase.load();
    const r = lookupCve(db, "CVE-bad");
    expect(r.found).toBe(false);
    if (!r.found) expect(r.message).toMatch(/not a valid CVE/i);
  });

  it("every CVE entry carries an NVD reference URL", async () => {
    const db = await CveDatabase.load();
    for (const id of db.ids()) {
      const r = lookupCve(db, id);
      expect(r.found).toBe(true);
      if (r.found) {
        expect(r.cve.references.some((u) => u.startsWith("https://nvd.nist.gov/"))).toBe(true);
      }
    }
  });

  it("is deterministic across repeated lookups", async () => {
    const db = await CveDatabase.load();
    const a = lookupCve(db, "CVE-2022-22965");
    const b = lookupCve(db, "CVE-2022-22965");
    expect(JSON.stringify(a)).toBe(JSON.stringify(b));
  });

  it("CVSS scores fall within the valid 0..10 range", async () => {
    const db = await CveDatabase.load();
    for (const id of db.ids()) {
      const r = lookupCve(db, id);
      if (r.found && r.cve.cvss_score !== undefined) {
        expect(r.cve.cvss_score).toBeGreaterThanOrEqual(0);
        expect(r.cve.cvss_score).toBeLessThanOrEqual(10);
      }
    }
  });
});
