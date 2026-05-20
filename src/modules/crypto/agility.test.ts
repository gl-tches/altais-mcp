import { describe, expect, it } from "vitest";
import { assessCryptoAgility } from "./agility.js";

describe("assessCryptoAgility — source", () => {
  it("flags algorithm names hardcoded across the codebase", () => {
    const f = assessCryptoAgility({
      source: 'a("aes-256-gcm"); b("sha-256"); c("hmac-sha256");',
    });
    expect(f.some((x) => x.rule === "agility-hardcoded-algorithms")).toBe(true);
  });

  it("does not flag a single isolated algorithm literal", () => {
    const f = assessCryptoAgility({ source: 'cipher("aes-256-gcm");' });
    expect(f.some((x) => x.rule === "agility-hardcoded-algorithms")).toBe(false);
  });
});

describe("assessCryptoAgility — config", () => {
  it("flags ciphertext with no version identifier", () => {
    const f = assessCryptoAgility({ config: { versioned_ciphertext: false } });
    const hit = f.find((x) => x.rule === "agility-no-versioned-ciphertext");
    expect(hit).toBeDefined();
    expect(hit?.severity).toBe("high");
  });

  it("flags non-configurable algorithm selection", () => {
    const f = assessCryptoAgility({ config: { algorithm_from_config: false } });
    expect(f.some((x) => x.rule === "agility-algorithm-not-configurable")).toBe(true);
  });

  it("flags a missing abstraction layer", () => {
    const f = assessCryptoAgility({ config: { abstraction_layer: false } });
    expect(f.some((x) => x.rule === "agility-no-abstraction-layer")).toBe(true);
  });

  it("flags a missing cryptographic inventory", () => {
    const f = assessCryptoAgility({ config: { inventory_exists: false } });
    expect(f.some((x) => x.rule === "agility-no-crypto-inventory")).toBe(true);
  });

  it("flags rotation that requires a redeploy", () => {
    const f = assessCryptoAgility({ config: { rotation_without_redeploy: false } });
    expect(f.some((x) => x.rule === "agility-rotation-requires-redeploy")).toBe(true);
  });

  it("accepts an agile configuration without findings", () => {
    const f = assessCryptoAgility({
      config: {
        algorithm_from_config: true,
        versioned_ciphertext: true,
        abstraction_layer: true,
        inventory_exists: true,
        rotation_without_redeploy: true,
      },
    });
    expect(f).toHaveLength(0);
  });
});
