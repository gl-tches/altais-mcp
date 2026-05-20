import { describe, expect, it } from "vitest";
import { analyzeTrustBoundaries } from "./trust-boundaries.js";

describe("analyzeTrustBoundaries", () => {
  it("ignores flows within the same trust zone", () => {
    const r = analyzeTrustBoundaries({
      components: [
        { name: "svc-a", type: "service", trust_zone: "internal" },
        { name: "svc-b", type: "service", trust_zone: "internal" },
      ],
      data_flows: [{ from: "svc-a", to: "svc-b", data: "RPC", protocol: "https", auth: "mtls" }],
    });
    expect(r.crossings).toEqual([]);
  });

  it("flags cleartext crossing of trust boundary", () => {
    const r = analyzeTrustBoundaries({
      components: [
        { name: "internet", type: "user", trust_zone: "untrusted" },
        { name: "api", type: "api", trust_zone: "internal" },
      ],
      data_flows: [
        { from: "internet", to: "api", data: "request body", protocol: "http", auth: "bearer" },
      ],
    });
    expect(r.findings.some((f) => f.rule === "boundary-cleartext")).toBe(true);
  });

  it("flags unauthenticated crossing", () => {
    const r = analyzeTrustBoundaries({
      components: [
        { name: "partner", type: "external", trust_zone: "untrusted" },
        { name: "api", type: "api", trust_zone: "internal" },
      ],
      data_flows: [{ from: "partner", to: "api", data: "webhook", protocol: "https" }],
    });
    expect(r.findings.some((f) => f.rule === "boundary-unauthenticated")).toBe(true);
  });

  it("flags ingress points needing input validation", () => {
    const r = analyzeTrustBoundaries({
      components: [
        { name: "internet", type: "user", trust_zone: "untrusted" },
        { name: "api", type: "api", trust_zone: "internal" },
      ],
      data_flows: [
        { from: "internet", to: "api", data: "json body", protocol: "https", auth: "bearer" },
      ],
    });
    expect(r.findings.some((f) => f.rule === "boundary-ingress-validation")).toBe(true);
  });

  it("classifies direction (ingress/egress/lateral)", () => {
    const r = analyzeTrustBoundaries({
      components: [
        { name: "internet", type: "user", trust_zone: "untrusted" },
        { name: "api", type: "api", trust_zone: "internal" },
        { name: "vendor", type: "external", trust_zone: "untrusted" },
      ],
      data_flows: [
        { from: "internet", to: "api", data: "x", protocol: "https", auth: "bearer" },
        { from: "api", to: "vendor", data: "y", protocol: "https", auth: "bearer" },
      ],
    });
    expect(r.crossings.find((c) => c.flow.from === "internet")?.direction).toBe("ingress");
    expect(r.crossings.find((c) => c.flow.from === "api")?.direction).toBe("egress");
  });

  it("infers a zone from the component name when not declared", () => {
    const r = analyzeTrustBoundaries({
      components: [
        { name: "internet", type: "user" },
        { name: "api", type: "api", trust_zone: "internal" },
      ],
      data_flows: [{ from: "internet", to: "api", data: "req", protocol: "https", auth: "bearer" }],
    });
    expect(r.crossings.some((c) => c.from_zone === "untrusted")).toBe(true);
  });

  it("summary counts crossings by direction", () => {
    const r = analyzeTrustBoundaries({
      components: [
        { name: "internet", type: "user", trust_zone: "untrusted" },
        { name: "api", type: "api", trust_zone: "internal" },
      ],
      data_flows: [{ from: "internet", to: "api", data: "x", protocol: "https", auth: "bearer" }],
    });
    expect(r.summary.total_crossings).toBe(1);
    expect(r.summary.ingress).toBe(1);
  });
});
