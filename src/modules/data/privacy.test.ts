import { describe, expect, it } from "vitest";
import { auditPrivacy, type PrivacyConfig } from "./privacy.js";

const rules = (config: PrivacyConfig): readonly string[] =>
  auditPrivacy({ config }).map((f) => f.rule);

const has = (config: PrivacyConfig, rule: string): boolean => rules(config).includes(rule);

describe("auditPrivacy — missing principles", () => {
  it("flags missing data minimization when false", () => {
    expect(has({ data_minimization: false }, "privacy-no-data-minimization")).toBe(true);
  });

  it("flags a missing principle that is simply not declared", () => {
    expect(has({}, "privacy-no-consent-mechanism")).toBe(true);
  });

  it("flags missing encryption at rest as high severity", () => {
    const f = auditPrivacy({ config: { encryption_at_rest: false } }).find(
      (x) => x.rule === "privacy-no-encryption-at-rest",
    );
    expect(f?.severity).toBe("high");
  });

  it("flags missing encryption in transit as high severity", () => {
    const f = auditPrivacy({ config: { encryption_in_transit: false } }).find(
      (x) => x.rule === "privacy-no-encryption-in-transit",
    );
    expect(f?.severity).toBe("high");
  });

  it("flags missing user data deletion as high severity", () => {
    const f = auditPrivacy({ config: { user_data_deletion: false } }).find(
      (x) => x.rule === "privacy-no-user-data-deletion",
    );
    expect(f?.severity).toBe("high");
  });

  it("flags missing user data export (right to access)", () => {
    expect(has({ user_data_export: false }, "privacy-no-user-data-export")).toBe(true);
  });
});

describe("auditPrivacy — satisfied principles and risks", () => {
  it("does not flag a principle that is true", () => {
    expect(has({ data_minimization: true }, "privacy-no-data-minimization")).toBe(false);
  });

  it("produces no findings when every principle is satisfied", () => {
    const config: PrivacyConfig = {
      data_minimization: true,
      purpose_limitation: true,
      consent_mechanism: true,
      encryption_at_rest: true,
      encryption_in_transit: true,
      default_private: true,
      dpo_designated: true,
      dpia_conducted: true,
      user_data_export: true,
      user_data_deletion: true,
      breach_notification_process: true,
    };
    expect(auditPrivacy({ config })).toHaveLength(0);
  });

  it("flags enabled third-party data sharing as a risk", () => {
    const config: PrivacyConfig = {
      data_minimization: true,
      purpose_limitation: true,
      consent_mechanism: true,
      encryption_at_rest: true,
      encryption_in_transit: true,
      default_private: true,
      dpo_designated: true,
      dpia_conducted: true,
      user_data_export: true,
      user_data_deletion: true,
      breach_notification_process: true,
      third_party_data_sharing: true,
    };
    expect(has(config, "privacy-third-party-data-sharing")).toBe(true);
  });

  it("does not flag third-party sharing when it is false", () => {
    expect(has({ third_party_data_sharing: false }, "privacy-third-party-data-sharing")).toBe(
      false,
    );
  });
});

describe("auditPrivacy — determinism and shape", () => {
  it("produces deterministic finding IDs across runs", () => {
    const config: PrivacyConfig = { encryption_at_rest: false, third_party_data_sharing: true };
    const a = auditPrivacy({ config });
    const b = auditPrivacy({ config });
    expect(a.map((f) => f.id)).toEqual(b.map((f) => f.id));
  });

  it("tags every finding with the data module and a CWE", () => {
    const findings = auditPrivacy({ config: {} });
    expect(findings.length).toBeGreaterThan(0);
    for (const f of findings) {
      expect(f.module).toBe("data");
      expect(f.tags).toContain("data");
      expect(f.cwe?.length ?? 0).toBeGreaterThan(0);
    }
  });
});
