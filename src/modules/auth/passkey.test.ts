import { describe, expect, it } from "vitest";
import { auditPasskey } from "./passkey.js";

describe("auditPasskey — config", () => {
  it("flags user_verification=discouraged", () => {
    const r = auditPasskey({ config: { user_verification: "discouraged" } });
    expect(r.some((f) => f.rule === "passkey-user-verification-discouraged")).toBe(true);
  });

  it("flags low challenge entropy", () => {
    const r = auditPasskey({ config: { challenge_entropy_bits: 64 } });
    expect(r.some((f) => f.rule === "passkey-low-challenge-entropy")).toBe(true);
  });

  it("flags origin host that does not match rp_id", () => {
    const r = auditPasskey({
      config: { rp_id: "example.com", origins: ["https://app.other.com"] },
    });
    expect(r.some((f) => f.rule === "passkey-origin-rp-mismatch")).toBe(true);
  });

  it("accepts aligned rp_id and origin", () => {
    const r = auditPasskey({
      config: {
        rp_id: "example.com",
        origins: ["https://app.example.com"],
        user_verification: "required",
      },
    });
    expect(r.filter((f) => f.rule === "passkey-origin-rp-mismatch")).toEqual([]);
  });

  it("flags missing sign-count tracking", () => {
    const r = auditPasskey({ config: { stores_sign_count: false } });
    expect(r.some((f) => f.rule === "passkey-no-sign-count-tracking")).toBe(true);
  });
});

describe("auditPasskey — source", () => {
  it("flags userVerification: 'discouraged' in source", () => {
    const r = auditPasskey({
      source: "navigator.credentials.create({ publicKey: { userVerification: 'discouraged' } })",
    });
    expect(r.some((f) => f.rule === "passkey-user-verification-discouraged")).toBe(true);
  });

  it("flags direct attestation request", () => {
    const r = auditPasskey({
      source: "publicKey: { attestation: 'direct' }",
    });
    expect(r.some((f) => f.rule === "passkey-attestation-direct-default")).toBe(true);
  });
});
