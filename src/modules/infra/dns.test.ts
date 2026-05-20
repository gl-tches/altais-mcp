import { describe, expect, it } from "vitest";
import { auditDns, type DnsAuditConfig } from "./dns.js";

const run = (config: DnsAuditConfig): ReturnType<typeof auditDns> => auditDns({ config });

const has = (config: DnsAuditConfig, rule: string): boolean =>
  run(config).some((f) => f.rule === rule);

describe("auditDns — DNSSEC and zone transfer", () => {
  it("flags DNSSEC disabled", () => {
    expect(has({ dnssec_enabled: false }, "dns-dnssec-disabled")).toBe(true);
  });

  it("does not flag DNSSEC when enabled", () => {
    expect(has({ dnssec_enabled: true }, "dns-dnssec-disabled")).toBe(false);
  });

  it("flags an open zone transfer", () => {
    expect(has({ zone_transfer_allowed: true }, "dns-open-zone-transfer")).toBe(true);
  });

  it("flags a zone transfer allowed to any host", () => {
    expect(has({ allowed_to: ["any"] }, "dns-open-zone-transfer")).toBe(true);
  });

  it("does not flag a zone transfer restricted to named secondaries", () => {
    expect(has({ allowed_to: ["192.0.2.10", "192.0.2.11"] }, "dns-open-zone-transfer")).toBe(false);
  });
});

describe("auditDns — CAA and wildcards", () => {
  it("flags a zone with no CAA records", () => {
    expect(has({ caa_records: [] }, "dns-missing-caa")).toBe(true);
  });

  it("does not flag a zone that has CAA records", () => {
    expect(has({ caa_records: ['0 issue "letsencrypt.org"'] }, "dns-missing-caa")).toBe(false);
  });

  it("flags a wildcard record declared as a boolean", () => {
    expect(has({ wildcard_records: true }, "dns-wildcard-record")).toBe(true);
  });

  it("flags wildcard records declared as a list", () => {
    expect(has({ wildcard_records: ["*.dev.example.com"] }, "dns-wildcard-record")).toBe(true);
  });

  it("does not flag when wildcard records are absent", () => {
    expect(has({ wildcard_records: false }, "dns-wildcard-record")).toBe(false);
  });
});

describe("auditDns — dangling records", () => {
  it("flags a CNAME pointing to an unclaimed external resource", () => {
    expect(
      has(
        {
          records: [
            {
              name: "shop.example.com",
              type: "CNAME",
              value: "shop.myshopify.com",
              points_to_external: true,
            },
          ],
        },
        "dns-dangling-record",
      ),
    ).toBe(true);
  });

  it("does not flag an internal A record", () => {
    expect(
      has(
        {
          records: [
            { name: "app.example.com", type: "A", value: "192.0.2.5", points_to_external: false },
          ],
        },
        "dns-dangling-record",
      ),
    ).toBe(false);
  });

  it("does not flag a CNAME not marked as external", () => {
    expect(
      has(
        { records: [{ name: "x.example.com", type: "CNAME", value: "y.example.com" }] },
        "dns-dangling-record",
      ),
    ).toBe(false);
  });
});

describe("auditDns — shape and determinism", () => {
  it("returns no findings for a hardened DNS configuration", () => {
    expect(
      run({
        dnssec_enabled: true,
        zone_transfer_allowed: false,
        caa_records: ['0 issue "letsencrypt.org"'],
        wildcard_records: false,
      }),
    ).toHaveLength(0);
  });

  it("produces deterministic finding IDs across runs", () => {
    const cfg: DnsAuditConfig = { dnssec_enabled: false, zone_transfer_allowed: true };
    expect(run(cfg).map((f) => f.id)).toEqual(run(cfg).map((f) => f.id));
  });

  it("tags every finding with the infra module and a CWE", () => {
    const findings = run({ dnssec_enabled: false, caa_records: [] });
    expect(findings.length).toBeGreaterThan(0);
    for (const f of findings) {
      expect(f.module).toBe("infra");
      expect(f.tags).toContain("infra");
      expect(f.cwe?.length ?? 0).toBeGreaterThan(0);
    }
  });
});
