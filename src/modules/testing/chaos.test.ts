import { describe, expect, it } from "vitest";
import { ChaosConfigError, generateChaosConfig } from "./chaos.js";

describe("generateChaosConfig — per platform", () => {
  it("generates Chaos Mesh specs for a Kubernetes platform", () => {
    const r = generateChaosConfig({ platform: "kubernetes", experiments: ["pod-kill"] });
    expect(r.tooling).toContain("Chaos Mesh");
    const spec = r.experiments[0]?.spec.content ?? "";
    expect(spec).toContain("chaos-mesh.org");
    expect(spec).toContain("PodChaos");
  });

  it("generates AWS FIS specs for an AWS platform", () => {
    const r = generateChaosConfig({ platform: "aws", experiments: ["network-latency"] });
    expect(r.tooling).toContain("FIS");
    expect(r.experiments[0]?.spec.content ?? "").toContain("stopConditions");
  });

  it("generates shell scripts for a linux-host platform", () => {
    const r = generateChaosConfig({ platform: "linux-host", experiments: ["network-latency"] });
    const spec = r.experiments[0]?.spec ?? { filename: "", content: "" };
    expect(spec.filename).toContain(".sh");
    expect(spec.content).toContain("tc qdisc");
  });
});

describe("generateChaosConfig — experiment metadata", () => {
  it("includes a steady-state hypothesis, blast radius, and rollback per experiment", () => {
    const r = generateChaosConfig({
      platform: "kubernetes",
      experiments: ["dependency-failure"],
    });
    const exp = r.experiments[0];
    expect(exp?.steady_state_hypothesis.length ?? 0).toBeGreaterThan(10);
    expect(exp?.blast_radius.length ?? 0).toBeGreaterThan(5);
    expect(exp?.rollback.length ?? 0).toBeGreaterThan(5);
  });

  it("generates one experiment per requested kind", () => {
    const r = generateChaosConfig({
      platform: "aws",
      experiments: ["pod-kill", "iam-revocation", "credential-expiry"],
    });
    expect(r.experiments).toHaveLength(3);
  });

  it("deduplicates repeated experiment kinds", () => {
    const r = generateChaosConfig({
      platform: "kubernetes",
      experiments: ["pod-kill", "pod-kill"],
    });
    expect(r.experiments).toHaveLength(1);
  });

  it("always lists the principles of chaos", () => {
    const r = generateChaosConfig({ platform: "application", experiments: ["network-latency"] });
    expect(r.principles.length).toBeGreaterThan(0);
    expect(r.references.join(" ")).toContain("principlesofchaos.org");
  });
});

describe("generateChaosConfig — validation and determinism", () => {
  it("rejects an empty experiments list", () => {
    expect(() => generateChaosConfig({ platform: "kubernetes", experiments: [] })).toThrow(
      ChaosConfigError,
    );
  });

  it("is deterministic for the same input", () => {
    const input = { platform: "kubernetes" as const, experiments: ["pod-kill" as const] };
    expect(JSON.stringify(generateChaosConfig(input))).toBe(
      JSON.stringify(generateChaosConfig(input)),
    );
  });
});
