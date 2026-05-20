import { describe, expect, it } from "vitest";
import { inspectSignature } from "./signatures.js";

describe("inspectSignature", () => {
  it("recognizes a cosign bundle with verification material", () => {
    const bundle = JSON.stringify({
      mediaType: "application/vnd.dev.sigstore.bundle+json;version=0.2",
      verificationMaterial: {
        certificate: { rawBytes: "abc" },
        tlogEntries: [{ logIndex: 1 }],
      },
      messageSignature: { signature: "sig" },
    });
    const r = inspectSignature(bundle);
    expect(r.kind).toBe("cosign-signature");
    expect(r.findings).toEqual([]);
  });

  it("flags a cosign bundle missing certificate + tlog", () => {
    const bundle = JSON.stringify({
      messageSignature: { signature: "sig" },
    });
    const r = inspectSignature(bundle);
    const rules = r.findings.map((f) => f.rule);
    expect(rules).toContain("cosign-no-certificate");
    expect(rules).toContain("cosign-no-tlog");
  });

  it("flags a weak-hash GPG signature", () => {
    const sig = `-----BEGIN PGP SIGNATURE-----
Hash: SHA1

iQabc==
-----END PGP SIGNATURE-----`;
    const r = inspectSignature(sig);
    expect(r.kind).toBe("gpg");
    expect(r.findings.some((f) => f.rule === "gpg-weak-hash")).toBe(true);
  });

  it("accepts a SHA256 GPG signature", () => {
    const sig = `-----BEGIN PGP SIGNATURE-----
Hash: SHA256

iQabc==
-----END PGP SIGNATURE-----`;
    const r = inspectSignature(sig);
    expect(r.findings.filter((f) => f.rule === "gpg-weak-hash")).toEqual([]);
  });

  it("flags unknown input", () => {
    const r = inspectSignature("not a signature");
    expect(r.kind).toBe("unknown");
  });
});
