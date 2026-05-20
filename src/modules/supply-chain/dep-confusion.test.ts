import { describe, expect, it } from "vitest";
import { checkDependencyConfusion } from "./dep-confusion.js";
import type { DependencyPackage } from "./types.js";

function p(name: string, source: string | undefined): DependencyPackage {
  return { name, version: "1.0.0", ecosystem: "npm", ...(source !== undefined ? { source } : {}) };
}

describe("checkDependencyConfusion", () => {
  it("flags a scoped internal name resolved from npmjs.org", () => {
    const r = checkDependencyConfusion(
      [p("@acme/widgets", "https://registry.npmjs.org/@acme/widgets/-/widgets-1.0.0.tgz")],
      { internal_scopes: ["@acme"] },
      undefined,
    );
    expect(r.findings[0]?.rule).toBe("dependency-confusion");
  });

  it("clears packages resolved from an internal registry", () => {
    const r = checkDependencyConfusion(
      [p("@acme/widgets", "https://registry.internal.example/@acme/widgets-1.0.0.tgz")],
      { internal_scopes: ["@acme"], internal_registries: ["registry.internal.example"] },
      undefined,
    );
    expect(r.findings).toEqual([]);
  });

  it("matches internal_prefixes", () => {
    const r = checkDependencyConfusion(
      [p("acme-utils", "https://registry.npmjs.org/acme-utils/-/acme-utils-1.0.0.tgz")],
      { internal_prefixes: ["acme-"] },
      undefined,
    );
    expect(r.findings).toHaveLength(1);
  });

  it("matches internal_names exactly", () => {
    const r = checkDependencyConfusion(
      [p("my-internal", "https://registry.npmjs.org/my-internal-1.0.0.tgz")],
      { internal_names: ["my-internal"] },
      undefined,
    );
    expect(r.findings).toHaveLength(1);
  });

  it("does not flag packages outside internal patterns", () => {
    const r = checkDependencyConfusion(
      [p("lodash", "https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz")],
      { internal_scopes: ["@acme"] },
      undefined,
    );
    expect(r.findings).toEqual([]);
  });
});
