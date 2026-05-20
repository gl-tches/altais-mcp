import { describe, expect, it } from "vitest";
import { checkWebhook, type WebhookAuditInput } from "./webhook.js";

const has = (input: WebhookAuditInput, rule: string): boolean =>
  checkWebhook(input).some((f) => f.rule === rule);

describe("checkWebhook — config posture", () => {
  it("flags missing signature verification", () => {
    expect(
      has({ config: { signature_verified: false } }, "webhook-no-signature-verification"),
    ).toBe(true);
  });

  it("flags a non-constant-time comparison", () => {
    expect(
      has(
        { config: { signature_verified: true, constant_time_comparison: false } },
        "webhook-non-constant-time-compare",
      ),
    ).toBe(true);
  });

  it("flags a weak hash algorithm", () => {
    expect(has({ config: { hash_algorithm: "sha1" } }, "webhook-weak-hash-algorithm")).toBe(true);
  });

  it("does not flag SHA-256", () => {
    expect(has({ config: { hash_algorithm: "sha256" } }, "webhook-weak-hash-algorithm")).toBe(
      false,
    );
  });

  it("flags missing timestamp validation", () => {
    expect(
      has({ config: { timestamp_validation: false } }, "webhook-no-timestamp-validation"),
    ).toBe(true);
  });

  it("flags missing replay protection", () => {
    expect(has({ config: { replay_protection: false } }, "webhook-no-replay-protection")).toBe(
      true,
    );
  });

  it("flags a hardcoded secret source", () => {
    expect(has({ config: { secret_source: "hardcoded" } }, "webhook-hardcoded-secret")).toBe(true);
  });

  it("returns no findings for a hardened config", () => {
    const findings = checkWebhook({
      config: {
        signature_verified: true,
        hash_algorithm: "sha256",
        constant_time_comparison: true,
        timestamp_validation: true,
        replay_protection: true,
        secret_source: "secrets_manager",
      },
    });
    expect(findings).toHaveLength(0);
  });
});

describe("checkWebhook — source scanning", () => {
  it("flags a signature compared with ===", () => {
    const src = "if (signature === expectedSig) { process(); }";
    expect(has({ source: src }, "webhook-non-constant-time-compare")).toBe(true);
  });

  it("does not flag a constant-time comparison", () => {
    const src = "if (crypto.timingSafeEqual(sigBuf, expectedBuf)) { process(); }";
    expect(has({ source: src }, "webhook-non-constant-time-compare")).toBe(false);
  });

  it("flags an HMAC built on md5", () => {
    const src = 'const h = crypto.createHmac("md5", secret);';
    expect(has({ source: src }, "webhook-weak-hash-algorithm")).toBe(true);
  });

  it("flags a hardcoded webhook secret literal", () => {
    const src = 'const webhookSecret = "whsec_aB12cD34eF56gH78iJ90";';
    expect(has({ source: src }, "webhook-hardcoded-secret")).toBe(true);
  });
});

describe("checkWebhook — finding shape", () => {
  it("produces deterministic finding IDs across runs", () => {
    const input: WebhookAuditInput = {
      config: { signature_verified: false },
      source: "if (sig === expected) {}",
      filename: "webhook.ts",
    };
    const a = checkWebhook(input);
    const b = checkWebhook(input);
    expect(a.map((f) => f.id)).toEqual(b.map((f) => f.id));
  });

  it("tags every finding with the protocol module and a CWE", () => {
    const findings = checkWebhook({
      config: { signature_verified: false, secret_source: "hardcoded" },
    });
    expect(findings.length).toBeGreaterThan(0);
    for (const f of findings) {
      expect(f.module).toBe("protocol");
      expect(f.tags).toContain("protocol");
      expect(f.cwe?.length ?? 0).toBeGreaterThan(0);
    }
  });
});
