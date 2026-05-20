import { describe, expect, it } from "vitest";
import { checkZeroTrust, type ZeroTrustConfig } from "./zero-trust.js";

const run = (config: ZeroTrustConfig): ReturnType<typeof checkZeroTrust> =>
  checkZeroTrust({ config });

const has = (config: ZeroTrustConfig, rule: string): boolean =>
  run(config).some((f) => f.rule === rule);

// A config with every tenet satisfied.
const FULL: ZeroTrustConfig = {
  verify_explicitly: true,
  least_privilege_access: true,
  assume_breach: true,
  mfa_enforced: true,
  microsegmentation: true,
  device_trust_verification: true,
  continuous_verification: true,
  no_implicit_network_trust: true,
  encrypted_internal_traffic: true,
  per_request_authorization: true,
  centralized_policy_engine: true,
};

describe("checkZeroTrust — missing tenets", () => {
  it("flags MFA when not enforced", () => {
    expect(has({ ...FULL, mfa_enforced: false }, "zt-mfa-not-enforced")).toBe(true);
  });

  it("flags implicit network trust as high severity", () => {
    const f = run({ ...FULL, no_implicit_network_trust: false }).find(
      (x) => x.rule === "zt-implicit-network-trust",
    );
    expect(f?.severity).toBe("high");
  });

  it("flags unencrypted internal traffic", () => {
    expect(
      has({ ...FULL, encrypted_internal_traffic: false }, "zt-internal-traffic-unencrypted"),
    ).toBe(true);
  });

  it("treats a missing (absent) tenet the same as false", () => {
    // mfa_enforced is deliberately omitted (absent, not false).
    const partial: ZeroTrustConfig = {
      verify_explicitly: true,
      least_privilege_access: true,
      assume_breach: true,
      microsegmentation: true,
      device_trust_verification: true,
      continuous_verification: true,
      no_implicit_network_trust: true,
      encrypted_internal_traffic: true,
      per_request_authorization: true,
      centralized_policy_engine: true,
    };
    expect(has(partial, "zt-mfa-not-enforced")).toBe(true);
  });

  it("does not flag a satisfied tenet", () => {
    expect(has(FULL, "zt-mfa-not-enforced")).toBe(false);
  });
});

describe("checkZeroTrust — maturity summary", () => {
  it("emits no findings at all when every tenet is satisfied", () => {
    expect(run(FULL)).toHaveLength(0);
  });

  it("emits a maturity summary when at least one tenet is missing", () => {
    expect(has({ ...FULL, mfa_enforced: false }, "zt-maturity-summary")).toBe(true);
  });

  it("reports ad-hoc maturity for an empty config", () => {
    const summary = run({}).find((f) => f.rule === "zt-maturity-summary");
    expect(summary?.title).toContain("ad-hoc");
  });

  it("reports advanced-tier progress when most tenets are satisfied", () => {
    const summary = run({ ...FULL, centralized_policy_engine: false }).find(
      (f) => f.rule === "zt-maturity-summary",
    );
    expect(summary?.title).toContain("intermediate");
  });

  it("emits one finding per missing tenet plus the summary", () => {
    // Two tenets missing -> 2 tenet findings + 1 summary.
    const findings = run({
      ...FULL,
      mfa_enforced: false,
      encrypted_internal_traffic: false,
    });
    expect(findings).toHaveLength(3);
  });
});

describe("checkZeroTrust — shape and determinism", () => {
  it("produces deterministic finding IDs across runs", () => {
    const cfg: ZeroTrustConfig = { ...FULL, mfa_enforced: false };
    expect(run(cfg).map((f) => f.id)).toEqual(run(cfg).map((f) => f.id));
  });

  it("tags every finding with the infra module and a CWE", () => {
    const findings = run({});
    expect(findings.length).toBeGreaterThan(0);
    for (const f of findings) {
      expect(f.module).toBe("infra");
      expect(f.tags).toContain("infra");
      expect(f.cwe?.length ?? 0).toBeGreaterThan(0);
    }
  });
});
