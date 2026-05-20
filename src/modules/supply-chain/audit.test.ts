import { describe, expect, it } from "vitest";
import { auditPackages, OsvDatabase } from "./audit.js";
import type { LockfileParseResult } from "./types.js";

describe("OsvDatabase + auditPackages", () => {
  it("loads the bundled snapshot", async () => {
    const db = await OsvDatabase.load();
    expect(db.size()).toBeGreaterThanOrEqual(30);
  });

  it("flags lodash@4.17.10 (prototype pollution)", async () => {
    const db = await OsvDatabase.load();
    const parsed: LockfileParseResult = {
      ecosystem: "npm",
      package_manager: "npm",
      packages: [{ name: "lodash", version: "4.17.10", ecosystem: "npm" }],
    };
    const r = auditPackages(parsed, db, "package-lock.json");
    expect(r.findings.length).toBeGreaterThan(0);
    expect(r.findings.some((f) => f.rule.startsWith("GHSA"))).toBe(true);
  });

  it("does not flag lodash@4.17.21 (post-fix)", async () => {
    const db = await OsvDatabase.load();
    const parsed: LockfileParseResult = {
      ecosystem: "npm",
      package_manager: "npm",
      packages: [{ name: "lodash", version: "4.17.21", ecosystem: "npm" }],
    };
    const r = auditPackages(parsed, db, "x");
    expect(r.findings).toEqual([]);
  });

  it("flags pyyaml < 5.4", async () => {
    const db = await OsvDatabase.load();
    const r = auditPackages(
      {
        ecosystem: "pypi",
        package_manager: "poetry",
        packages: [{ name: "pyyaml", version: "5.3.1", ecosystem: "pypi" }],
      },
      db,
      undefined,
    );
    expect(r.findings.some((f) => f.severity === "critical")).toBe(true);
  });

  it("summary counts findings by severity", async () => {
    const db = await OsvDatabase.load();
    const r = auditPackages(
      {
        ecosystem: "npm",
        package_manager: "npm",
        packages: [
          { name: "lodash", version: "4.17.10", ecosystem: "npm" }, // critical
          { name: "qs", version: "6.5.0", ecosystem: "npm" }, // high
        ],
      },
      db,
      undefined,
    );
    expect(r.summary.critical + r.summary.high).toBeGreaterThan(0);
  });
});
