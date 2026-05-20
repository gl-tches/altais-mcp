import { describe, expect, it } from "vitest";
import { generateSbom } from "./sbom.js";
import type { LockfileParseResult } from "./types.js";

const PARSED: LockfileParseResult = {
  ecosystem: "npm",
  package_manager: "npm",
  packages: [
    {
      name: "lodash",
      version: "4.17.21",
      ecosystem: "npm",
      integrity: "sha512-abc",
      license: "MIT",
      purl: "pkg:npm/lodash@4.17.21",
    },
    {
      name: "@scope/pkg",
      version: "1.0.0",
      ecosystem: "npm",
      purl: "pkg:npm/%40scope%2Fpkg@1.0.0",
    },
  ],
};

describe("generateSbom — CycloneDX", () => {
  it("emits CycloneDX 1.5 with components", () => {
    const { document } = generateSbom(PARSED, { format: "cyclonedx", project_name: "demo" });
    const doc = document as { bomFormat: string; specVersion: string; components: unknown[] };
    expect(doc.bomFormat).toBe("CycloneDX");
    expect(doc.specVersion).toBe("1.5");
    expect(doc.components).toHaveLength(2);
  });

  it("includes purl + hashes", () => {
    const { document } = generateSbom(PARSED, { format: "cyclonedx" });
    const doc = document as { components: { purl: string; hashes?: unknown[] }[] };
    expect(doc.components[0]?.purl).toMatch(/^pkg:npm\/lodash/);
    expect(doc.components[0]?.hashes).toBeDefined();
  });
});

describe("generateSbom — SPDX", () => {
  it("emits SPDX 2.3 with packages + relationships", () => {
    const { document } = generateSbom(PARSED, { format: "spdx", project_name: "demo" });
    const doc = document as {
      spdxVersion: string;
      packages: unknown[];
      relationships: unknown[];
    };
    expect(doc.spdxVersion).toBe("SPDX-2.3");
    expect(doc.packages).toHaveLength(2);
    expect(doc.relationships.length).toBeGreaterThan(0);
  });

  it("links every package via DESCRIBES", () => {
    const { document } = generateSbom(PARSED, { format: "spdx" });
    const doc = document as { relationships: { relationshipType: string }[] };
    expect(doc.relationships.every((r) => r.relationshipType === "DESCRIBES")).toBe(true);
  });
});
