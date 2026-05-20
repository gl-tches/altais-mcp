import { describe, expect, it } from "vitest";
import { analyzeStride } from "./stride.js";

describe("analyzeStride", () => {
  it("emits a STRIDE breakdown per component", () => {
    const result = analyzeStride({
      components: [
        { name: "api", type: "api" },
        { name: "db", type: "database" },
      ],
    });
    expect(result.components).toHaveLength(2);
    for (const c of result.components) {
      expect(c.threats.spoofing.length).toBeGreaterThan(0);
      expect(c.threats.tampering.length).toBeGreaterThan(0);
    }
  });

  it("adds a PII-specific threat when handles_pii is true", () => {
    const result = analyzeStride({
      components: [{ name: "api", type: "api", handles_pii: true }],
    });
    const id = result.components[0]?.threats.information_disclosure;
    expect(id?.some((t) => /PII/i.test(t.description))).toBe(true);
  });

  it("adds an auth-specific threat when authenticates_clients is true", () => {
    const result = analyzeStride({
      components: [{ name: "auth", type: "auth", authenticates_clients: true }],
    });
    const sp = result.components[0]?.threats.spoofing;
    expect(sp?.some((t) => /credential|MFA|token/i.test(t.description))).toBe(true);
  });

  it("emits cross-flow threats for unencrypted flows", () => {
    const result = analyzeStride({
      components: [
        { name: "user", type: "user" },
        { name: "api", type: "api" },
      ],
      data_flows: [
        { from: "user", to: "api", data: "auth token", protocol: "http", auth: "bearer" },
      ],
    });
    expect(
      result.cross_component_threats.some(
        (t) => t.category === "information_disclosure" && /encrypted/i.test(t.description),
      ),
    ).toBe(true);
  });

  it("emits cross-flow threats for unauthenticated flows", () => {
    const result = analyzeStride({
      components: [
        { name: "svc-a", type: "service" },
        { name: "svc-b", type: "service" },
      ],
      data_flows: [{ from: "svc-a", to: "svc-b", data: "RPC", protocol: "https" }],
    });
    expect(result.cross_component_threats.some((t) => t.category === "spoofing")).toBe(true);
  });

  it("summary counts total threats by category", () => {
    const result = analyzeStride({
      components: [{ name: "db", type: "database" }],
    });
    const total = Object.values(result.summary.by_category).reduce((a, b) => a + b, 0);
    expect(result.summary.total_threats).toBe(total);
  });

  it("falls back to generic threats for `other` type", () => {
    const result = analyzeStride({
      components: [{ name: "x", type: "other" }],
    });
    expect(result.components[0]?.threats.repudiation.length).toBeGreaterThan(0);
  });
});
