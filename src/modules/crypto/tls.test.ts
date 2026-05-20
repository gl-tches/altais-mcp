import { describe, expect, it } from "vitest";
import { auditTls } from "./tls.js";

describe("auditTls — source", () => {
  it("flags rejectUnauthorized:false", () => {
    const f = auditTls({ source: "const a = { rejectUnauthorized: false };" });
    expect(f.some((x) => x.rule === "tls-verification-disabled")).toBe(true);
  });

  it("flags Python verify=False", () => {
    const f = auditTls({ source: "requests.get(url, verify=False)" });
    expect(f.some((x) => x.rule === "tls-verification-disabled")).toBe(true);
  });

  it("flags Go InsecureSkipVerify:true", () => {
    const f = auditTls({ source: "tls.Config{ InsecureSkipVerify: true }" });
    expect(f.some((x) => x.rule === "tls-verification-disabled")).toBe(true);
  });

  it("flags a pinned deprecated protocol method", () => {
    const f = auditTls({ source: "ctx = SSL.Context(SSL.TLSv1_method)" });
    expect(f.some((x) => x.rule === "tls-deprecated-protocol-pinned")).toBe(true);
  });

  it("does not flag a clean TLS 1.3 setup", () => {
    const f = auditTls({ source: "const a = { minVersion: 'TLSv1.3' };" });
    expect(f).toHaveLength(0);
  });
});

describe("auditTls — config", () => {
  it("flags a deprecated enabled version", () => {
    const f = auditTls({ config: { enabled_versions: ["TLSv1.0", "TLSv1.2"] } });
    expect(f.some((x) => x.rule === "tls-deprecated-protocol-enabled")).toBe(true);
  });

  it("flags a too-low minimum version", () => {
    const f = auditTls({ config: { min_version: "TLSv1.1" } });
    expect(f.some((x) => x.rule === "tls-min-version-too-low")).toBe(true);
  });

  it("flags a weak cipher suite", () => {
    const f = auditTls({ config: { cipher_suites: ["TLS_RSA_WITH_RC4_128_SHA"] } });
    expect(f.some((x) => x.rule === "tls-weak-cipher-suite")).toBe(true);
  });

  it("flags disabled certificate verification", () => {
    const f = auditTls({ config: { verify_certificates: false } });
    expect(f.some((x) => x.rule === "tls-verification-disabled")).toBe(true);
  });

  it("flags TLS compression", () => {
    const f = auditTls({ config: { compression: true } });
    expect(f.some((x) => x.rule === "tls-compression-enabled")).toBe(true);
  });

  it("flags missing HSTS", () => {
    const f = auditTls({ config: { hsts: false } });
    expect(f.some((x) => x.rule === "tls-no-hsts")).toBe(true);
  });

  it("accepts a hardened TLS 1.3 config", () => {
    const f = auditTls({
      config: {
        min_version: "TLSv1.2",
        enabled_versions: ["TLSv1.2", "TLSv1.3"],
        cipher_suites: ["TLS_AES_256_GCM_SHA384"],
        verify_certificates: true,
        hsts: true,
        compression: false,
      },
    });
    expect(f).toHaveLength(0);
  });
});
