import { describe, expect, it } from "vitest";
import { auditKeyMgmt } from "./key-mgmt.js";

describe("auditKeyMgmt — source", () => {
  it("flags a hardcoded key literal", () => {
    const f = auditKeyMgmt({ source: 'const secretKey = "EXAMPLE_FAKE_KEY_000000000000";' });
    expect(f.some((x) => x.rule === "key-hardcoded-in-source")).toBe(true);
  });

  it("flags an embedded PEM private key", () => {
    const f = auditKeyMgmt({
      source: "-----BEGIN RSA PRIVATE KEY-----\nMIIE...\n-----END RSA PRIVATE KEY-----",
    });
    expect(f.some((x) => x.rule === "key-private-pem-in-source")).toBe(true);
  });

  it("does not flag a key reference loaded from a manager", () => {
    const f = auditKeyMgmt({ source: "const key = await kms.getKey(keyRef);" });
    expect(f).toHaveLength(0);
  });
});

describe("auditKeyMgmt — inventory", () => {
  it("flags a key stored in the repo", () => {
    const f = auditKeyMgmt({ keys: [{ name: "deploy", storage: "repo" }] });
    expect(f.some((x) => x.rule === "key-insecure-storage")).toBe(true);
  });

  it("flags a high-value key outside an HSM / KMS", () => {
    const f = auditKeyMgmt({
      keys: [{ name: "release-signer", type: "signing", storage: "env_var" }],
    });
    expect(f.some((x) => x.rule === "key-high-value-not-in-hsm")).toBe(true);
  });

  it("flags a key with no rotation policy", () => {
    const f = auditKeyMgmt({ keys: [{ name: "api", storage: "kms" }] });
    expect(f.some((x) => x.rule === "key-no-rotation-policy")).toBe(true);
  });

  it("flags an overdue rotation", () => {
    const f = auditKeyMgmt({
      keys: [
        {
          name: "api",
          storage: "kms",
          rotation_period_days: 90,
          last_rotated_at: "2020-01-01",
        },
      ],
      as_of: "2026-05-20",
    });
    expect(f.some((x) => x.rule === "key-rotation-overdue")).toBe(true);
  });

  it("flags a key that has never been rotated", () => {
    const f = auditKeyMgmt({
      keys: [{ name: "api", storage: "kms", rotation_period_days: 90, created_at: "2020-01-01" }],
      as_of: "2026-05-20",
    });
    expect(f.some((x) => x.rule === "key-never-rotated")).toBe(true);
  });

  it("flags an undersized RSA key", () => {
    const f = auditKeyMgmt({
      keys: [
        {
          name: "tls",
          storage: "kms",
          algorithm: "RSA",
          key_size_bits: 1024,
          rotation_period_days: 90,
          last_rotated_at: "2026-05-01",
        },
      ],
      as_of: "2026-05-20",
    });
    expect(f.some((x) => x.rule === "key-weak-size")).toBe(true);
  });

  it("accepts a well-managed key without findings", () => {
    const f = auditKeyMgmt({
      keys: [
        {
          name: "api",
          type: "api",
          storage: "kms",
          algorithm: "AES",
          key_size_bits: 256,
          rotation_period_days: 90,
          last_rotated_at: "2026-05-01",
        },
      ],
      as_of: "2026-05-20",
    });
    expect(f).toHaveLength(0);
  });
});
