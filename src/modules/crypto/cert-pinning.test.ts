import { describe, expect, it } from "vitest";
import { auditCertPinning } from "./cert-pinning.js";

describe("auditCertPinning — source", () => {
  it("flags the deprecated HPKP Public-Key-Pins header", () => {
    const f = auditCertPinning({
      source: 'res.setHeader("Public-Key-Pins", \'pin-sha256="abc="; max-age=5184000\');',
    });
    expect(f.some((x) => x.rule === "cert-pinning-hpkp-header")).toBe(true);
  });
});

describe("auditCertPinning — config", () => {
  it("flags absent pinning on a mobile platform", () => {
    const f = auditCertPinning({ config: { pinning_enabled: false, platform: "android" } });
    const hit = f.find((x) => x.rule === "cert-pinning-absent");
    expect(hit).toBeDefined();
    expect(hit?.severity).toBe("medium");
  });

  it("flags leaf-certificate pinning", () => {
    const f = auditCertPinning({
      config: { pinning_enabled: true, pin_type: "leaf_certificate", has_backup_pin: true },
    });
    expect(f.some((x) => x.rule === "cert-pinning-leaf-certificate")).toBe(true);
  });

  it("flags pinning without a backup pin", () => {
    const f = auditCertPinning({
      config: { pinning_enabled: true, pin_type: "public_key", has_backup_pin: false },
    });
    expect(f.some((x) => x.rule === "cert-pinning-no-backup-pin")).toBe(true);
  });

  it("flags non-enforcing pinning", () => {
    const f = auditCertPinning({
      config: {
        pinning_enabled: true,
        pin_type: "public_key",
        has_backup_pin: true,
        enforced: false,
      },
    });
    expect(f.some((x) => x.rule === "cert-pinning-not-enforced")).toBe(true);
  });

  it("accepts enforced SPKI pinning with a backup pin", () => {
    const f = auditCertPinning({
      config: {
        pinning_enabled: true,
        pin_type: "public_key",
        pin_count: 2,
        has_backup_pin: true,
        enforced: true,
      },
    });
    expect(f).toHaveLength(0);
  });
});
