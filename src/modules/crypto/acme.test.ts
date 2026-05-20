import { describe, expect, it } from "vitest";
import { auditAcme } from "./acme.js";

describe("auditAcme", () => {
  it("flags missing renewal automation", () => {
    const f = auditAcme({ config: { auto_renewal: false, caa_configured: true } });
    expect(f.some((x) => x.rule === "acme-no-auto-renewal")).toBe(true);
  });

  it("flags a renewal threshold too close to expiry", () => {
    const f = auditAcme({
      config: { auto_renewal: true, caa_configured: true, renewal_threshold_days: 7 },
    });
    expect(f.some((x) => x.rule === "acme-renewal-threshold-too-low")).toBe(true);
  });

  it("flags http-01 used for a wildcard certificate", () => {
    const f = auditAcme({
      config: {
        auto_renewal: true,
        caa_configured: true,
        wildcard: true,
        challenge_type: "http-01",
      },
    });
    expect(f.some((x) => x.rule === "acme-wildcard-requires-dns-01")).toBe(true);
  });

  it("flags a missing CAA record", () => {
    const f = auditAcme({ config: { auto_renewal: true } });
    expect(f.some((x) => x.rule === "acme-no-caa-record")).toBe(true);
  });

  it("flags a weak certificate key", () => {
    const f = auditAcme({
      config: { auto_renewal: true, caa_configured: true, key_type: "rsa", key_size_bits: 1024 },
    });
    expect(f.some((x) => x.rule === "acme-weak-certificate-key")).toBe(true);
  });

  it("flags use of the staging endpoint", () => {
    const f = auditAcme({
      config: { auto_renewal: true, caa_configured: true, staging_endpoint: true },
    });
    expect(f.some((x) => x.rule === "acme-staging-endpoint")).toBe(true);
  });

  it("flags an account key committed to the repo", () => {
    const f = auditAcme({
      config: { auto_renewal: true, caa_configured: true, account_key_storage: "repo" },
    });
    expect(f.some((x) => x.rule === "acme-account-key-insecure-storage")).toBe(true);
  });

  it("accepts a well-configured ACME setup", () => {
    const f = auditAcme({
      config: {
        provider: "letsencrypt",
        auto_renewal: true,
        renewal_threshold_days: 30,
        caa_configured: true,
        challenge_type: "dns-01",
        wildcard: true,
        key_type: "ecdsa",
        account_key_storage: "kms",
      },
    });
    expect(f).toHaveLength(0);
  });
});
