import { describe, expect, it } from "vitest";
import { auditEmailSecurity, type EmailSecurityAuditConfig } from "./email.js";

const run = (config: EmailSecurityAuditConfig): ReturnType<typeof auditEmailSecurity> =>
  auditEmailSecurity({ config });

const has = (config: EmailSecurityAuditConfig, rule: string): boolean =>
  run(config).some((f) => f.rule === rule);

describe("auditEmailSecurity — SPF", () => {
  it("flags a missing SPF record", () => {
    expect(has({ dmarc_policy: "reject" }, "email-missing-spf")).toBe(true);
  });

  it("flags an SPF record ending in +all", () => {
    expect(
      has({ spf_record: "v=spf1 include:_spf.example.com +all" }, "email-spf-permissive-all"),
    ).toBe(true);
  });

  it("flags an SPF record ending in ?all", () => {
    expect(has({ spf_record: "v=spf1 mx ?all" }, "email-spf-neutral-all")).toBe(true);
  });

  it("flags an SPF record with no all mechanism", () => {
    expect(
      has({ spf_record: "v=spf1 include:_spf.example.com" }, "email-spf-no-all-mechanism"),
    ).toBe(true);
  });

  it("accepts an SPF record ending in -all", () => {
    const findings = run({ spf_record: "v=spf1 mx -all" });
    expect(findings.some((f) => f.rule.startsWith("email-spf"))).toBe(false);
  });
});

describe("auditEmailSecurity — DKIM and DMARC", () => {
  it("flags DKIM disabled", () => {
    expect(has({ dkim_enabled: false }, "email-missing-dkim")).toBe(true);
  });

  it("does not flag DKIM when selectors are present", () => {
    expect(has({ dkim_enabled: true, dkim_selectors: ["sel1"] }, "email-missing-dkim")).toBe(false);
  });

  it("flags a missing DMARC record", () => {
    expect(has({ spf_record: "v=spf1 -all", dkim_enabled: true }, "email-missing-dmarc")).toBe(
      true,
    );
  });

  it("flags a DMARC p=none policy", () => {
    expect(
      has({ dmarc_record: "v=DMARC1; p=none; rua=mailto:r@x.com" }, "email-dmarc-policy-none"),
    ).toBe(true);
  });

  it("flags a DMARC record with no rua", () => {
    expect(has({ dmarc_record: "v=DMARC1; p=reject" }, "email-dmarc-no-aggregate-reporting")).toBe(
      true,
    );
  });

  it("does not flag a strong DMARC record with rua", () => {
    const findings = run({ dmarc_record: "v=DMARC1; p=reject; rua=mailto:r@x.com" });
    expect(findings.some((f) => f.rule.startsWith("email-dmarc"))).toBe(false);
  });
});

describe("auditEmailSecurity — transport hardening", () => {
  it("flags MTA-STS disabled", () => {
    expect(has({ mta_sts: false }, "email-missing-mta-sts")).toBe(true);
  });

  it("flags DNSSEC disabled", () => {
    expect(has({ dnssec: false }, "email-missing-dnssec")).toBe(true);
  });

  it("returns no findings for a fully hardened domain", () => {
    const findings = run({
      spf_record: "v=spf1 include:_spf.example.com -all",
      dkim_enabled: true,
      dkim_selectors: ["sel1"],
      dmarc_record: "v=DMARC1; p=reject; rua=mailto:dmarc@example.com",
      mta_sts: true,
      dnssec: true,
    });
    expect(findings).toHaveLength(0);
  });
});

describe("auditEmailSecurity — finding shape", () => {
  it("produces deterministic finding IDs across runs", () => {
    const config: EmailSecurityAuditConfig = {
      spf_record: "v=spf1 +all",
      dmarc_record: "v=DMARC1; p=none",
    };
    const a = auditEmailSecurity({ config, filename: "dns.txt" });
    const b = auditEmailSecurity({ config, filename: "dns.txt" });
    expect(a.map((f) => f.id)).toEqual(b.map((f) => f.id));
  });

  it("tags every finding with the protocol module and a CWE", () => {
    const findings = run({ dkim_enabled: false, mta_sts: false });
    expect(findings.length).toBeGreaterThan(0);
    for (const f of findings) {
      expect(f.module).toBe("protocol");
      expect(f.tags).toContain("protocol");
      expect(f.cwe?.length ?? 0).toBeGreaterThan(0);
    }
  });
});
