import { describe, expect, it } from "vitest";
import { auditCrypto } from "./algorithms.js";

describe("auditCrypto — source", () => {
  it("flags MD5 hashing", () => {
    const f = auditCrypto({ source: 'crypto.createHash("md5").update(x);' });
    expect(f.some((x) => x.rule === "crypto-md5")).toBe(true);
  });

  it("flags SHA-1 hashing", () => {
    const f = auditCrypto({ source: 'hashlib.new("sha1")' });
    expect(f.some((x) => x.rule === "crypto-sha1")).toBe(true);
  });

  it("flags DES / 3DES ciphers", () => {
    const f = auditCrypto({ source: 'crypto.createCipheriv("des-cbc", k, iv);' });
    expect(f.some((x) => x.rule === "crypto-des")).toBe(true);
  });

  it("flags RC4", () => {
    const f = auditCrypto({ source: 'const c = "rc4-40";' });
    expect(f.some((x) => x.rule === "crypto-rc4")).toBe(true);
  });

  it("flags ECB mode", () => {
    const f = auditCrypto({ source: 'createCipheriv("aes-256-ecb", k);' });
    expect(f.some((x) => x.rule === "crypto-ecb-mode")).toBe(true);
  });

  it("flags the deprecated crypto.createCipher API", () => {
    const f = auditCrypto({ source: 'crypto.createCipher("aes192", pw);' });
    expect(f.some((x) => x.rule === "crypto-deprecated-createcipher")).toBe(true);
  });

  it("flags a static IV", () => {
    const f = auditCrypto({ source: 'const iv = "0000000000000000";' });
    expect(f.some((x) => x.rule === "crypto-static-iv")).toBe(true);
  });

  it("does not flag SHA-256 or AES-GCM", () => {
    const f = auditCrypto({
      source: 'crypto.createHash("sha256"); createCipheriv("aes-256-gcm", k, iv);',
    });
    expect(f.some((x) => x.rule === "crypto-md5" || x.rule === "crypto-sha1")).toBe(false);
    expect(f.some((x) => x.rule === "crypto-ecb-mode")).toBe(false);
  });
});

describe("auditCrypto — config", () => {
  it("flags a weak algorithm in the inventory", () => {
    const f = auditCrypto({ config: { algorithms: [{ name: "MD5", purpose: "hashing" }] } });
    expect(f.some((x) => x.rule === "crypto-weak-algorithm")).toBe(true);
  });

  it("flags an undersized RSA key", () => {
    const f = auditCrypto({
      config: { algorithms: [{ name: "RSA", purpose: "signing", key_size_bits: 1024 }] },
    });
    expect(f.some((x) => x.rule === "crypto-rsa-key-too-small")).toBe(true);
  });

  it("flags an undersized symmetric key", () => {
    const f = auditCrypto({
      config: { algorithms: [{ name: "AES", purpose: "encryption", key_size_bits: 64 }] },
    });
    expect(f.some((x) => x.rule === "crypto-symmetric-key-too-small")).toBe(true);
  });

  it("accepts a strong inventory without findings", () => {
    const f = auditCrypto({
      config: { algorithms: [{ name: "AES", purpose: "encryption", key_size_bits: 256 }] },
    });
    expect(f).toHaveLength(0);
  });
});
