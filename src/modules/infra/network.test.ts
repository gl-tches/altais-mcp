import { describe, expect, it } from "vitest";
import { auditNetwork, type NetworkAuditConfig } from "./network.js";

const run = (config: NetworkAuditConfig): ReturnType<typeof auditNetwork> =>
  auditNetwork({ config });

const has = (config: NetworkAuditConfig, rule: string): boolean =>
  run(config).some((f) => f.rule === rule);

describe("auditNetwork — ingress exposure", () => {
  it("flags an any-source ingress allow to an admin port (SSH)", () => {
    expect(
      has(
        {
          firewall_rules: [
            { direction: "ingress", source: "0.0.0.0/0", port: 22, action: "allow" },
          ],
        },
        "network-admin-port-exposed",
      ),
    ).toBe(true);
  });

  it("flags an any-source ingress allow to a database port (PostgreSQL)", () => {
    expect(
      has(
        {
          firewall_rules: [{ direction: "ingress", source: "::/0", port: "5432", action: "allow" }],
        },
        "network-admin-port-exposed",
      ),
    ).toBe(true);
  });

  it("flags an allow-any-any ingress rule with no port restriction", () => {
    expect(
      has(
        { firewall_rules: [{ direction: "ingress", source: "any", action: "allow" }] },
        "network-any-any-ingress",
      ),
    ).toBe(true);
  });

  it("flags an any-source ingress allow to a non-admin port", () => {
    expect(
      has(
        {
          firewall_rules: [
            { direction: "ingress", source: "0.0.0.0/0", port: 8443, action: "allow" },
          ],
        },
        "network-any-source-ingress",
      ),
    ).toBe(true);
  });

  it("does not flag an admin port restricted to a private CIDR", () => {
    expect(
      has(
        {
          firewall_rules: [
            { direction: "ingress", source: "10.0.0.0/8", port: 22, action: "allow" },
          ],
        },
        "network-admin-port-exposed",
      ),
    ).toBe(false);
  });
});

describe("auditNetwork — egress and segmentation", () => {
  it("flags an unrestricted egress allow rule", () => {
    expect(
      has(
        {
          firewall_rules: [
            { direction: "egress", source: "any", destination: "any", action: "allow" },
          ],
        },
        "network-unrestricted-egress-rule",
      ),
    ).toBe(true);
  });

  it("flags a flat network with a single zone", () => {
    expect(has({ zones: ["all"] }, "network-flat-topology")).toBe(true);
  });

  it("does not flag a segmented network with multiple zones", () => {
    expect(has({ zones: ["public", "app", "data"] }, "network-flat-topology")).toBe(false);
  });

  it("flags disabled egress filtering", () => {
    expect(has({ egress_filtering: false }, "network-no-egress-filtering")).toBe(true);
  });

  it("flags a rule set with no deny rules", () => {
    expect(
      has(
        {
          firewall_rules: [
            { direction: "ingress", source: "10.0.0.0/8", port: 443, action: "allow" },
          ],
        },
        "network-no-default-deny",
      ),
    ).toBe(true);
  });

  it("does not flag a rule set that contains an explicit deny", () => {
    expect(
      has(
        {
          firewall_rules: [
            { direction: "ingress", source: "10.0.0.0/8", port: 443, action: "allow" },
            { direction: "ingress", source: "0.0.0.0/0", action: "deny" },
          ],
        },
        "network-no-default-deny",
      ),
    ).toBe(false);
  });

  it("returns no findings for a well-configured network", () => {
    expect(
      run({
        firewall_rules: [
          { direction: "ingress", source: "10.0.0.0/8", port: 443, action: "allow" },
          { direction: "ingress", source: "0.0.0.0/0", action: "deny" },
        ],
        zones: ["public", "app", "data"],
        egress_filtering: true,
      }),
    ).toHaveLength(0);
  });
});

describe("auditNetwork — shape and determinism", () => {
  it("produces deterministic finding IDs across runs", () => {
    const cfg: NetworkAuditConfig = {
      firewall_rules: [{ direction: "ingress", source: "0.0.0.0/0", port: 22, action: "allow" }],
    };
    expect(run(cfg).map((f) => f.id)).toEqual(run(cfg).map((f) => f.id));
  });

  it("tags every finding with the infra module and a CWE", () => {
    const findings = run({
      firewall_rules: [{ direction: "ingress", source: "0.0.0.0/0", port: 6379, action: "allow" }],
    });
    expect(findings.length).toBeGreaterThan(0);
    for (const f of findings) {
      expect(f.module).toBe("infra");
      expect(f.tags).toContain("infra");
      expect(f.cwe?.length ?? 0).toBeGreaterThan(0);
    }
  });
});
