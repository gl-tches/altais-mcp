import { describe, expect, it } from "vitest";
import { auditTlsConfig, type TlsConfigAuditConfig } from "./tls-config.js";

const run = (config: TlsConfigAuditConfig): ReturnType<typeof auditTlsConfig> =>
  auditTlsConfig({ config });

const has = (config: TlsConfigAuditConfig, rule: string): boolean =>
  run(config).some((f) => f.rule === rule);

describe("auditTlsConfig — protocol versions", () => {
  it("flags a deprecated enabled protocol", () => {
    expect(
      has({ enabled_versions: ["TLSv1.0", "TLSv1.2"] }, "tls-deprecated-protocol-enabled"),
    ).toBe(true);
  });

  it("rates SSLv3 as critical", () => {
    const f = run({ enabled_versions: ["SSLv3"] }).find(
      (x) => x.rule === "tls-deprecated-protocol-enabled",
    );
    expect(f?.severity).toBe("critical");
  });

  it("flags a min_version below TLS 1.2", () => {
    expect(has({ min_version: "TLSv1.1" }, "tls-min-version-too-low")).toBe(true);
  });

  it("does not flag a min_version of TLS 1.2", () => {
    expect(has({ min_version: "TLSv1.2" }, "tls-min-version-too-low")).toBe(false);
  });

  it("flags an enabled-version set without TLS 1.3", () => {
    expect(has({ enabled_versions: ["TLSv1.2"] }, "tls-no-tls13")).toBe(true);
  });

  it("does not flag when TLS 1.3 is enabled", () => {
    expect(has({ enabled_versions: ["TLSv1.2", "TLSv1.3"] }, "tls-no-tls13")).toBe(false);
  });
});

describe("auditTlsConfig — cipher suites and forward secrecy", () => {
  it("flags a weak cipher suite", () => {
    expect(has({ cipher_suites: ["ECDHE-RSA-RC4-SHA"] }, "tls-weak-cipher-suite")).toBe(true);
  });

  it("flags a non-AEAD cipher suite", () => {
    expect(
      has({ cipher_suites: ["ECDHE-RSA-AES256-CBC-SHA384"] }, "tls-non-aead-cipher-suite"),
    ).toBe(true);
  });

  it("accepts a modern AEAD cipher suite", () => {
    const findings = run({ cipher_suites: ["TLS_AES_256_GCM_SHA384"] });
    expect(findings.some((f) => f.rule === "tls-weak-cipher-suite")).toBe(false);
    expect(findings.some((f) => f.rule === "tls-non-aead-cipher-suite")).toBe(false);
  });

  it("flags forward_secrecy disabled", () => {
    expect(has({ forward_secrecy: false }, "tls-no-forward-secrecy")).toBe(true);
  });

  it("flags a static-RSA cipher suite as missing forward secrecy", () => {
    expect(
      has({ cipher_suites: ["TLS_RSA_WITH_AES_128_GCM_SHA256"] }, "tls-no-forward-secrecy"),
    ).toBe(true);
  });
});

describe("auditTlsConfig — certificate, mTLS, and hygiene", () => {
  it("flags a SHA-1 certificate signature", () => {
    expect(
      has(
        { cert_signature_algorithm: "sha1WithRSAEncryption" },
        "tls-weak-cert-signature-algorithm",
      ),
    ).toBe(true);
  });

  it("does not flag a SHA-256 certificate signature", () => {
    expect(
      has(
        { cert_signature_algorithm: "sha256WithRSAEncryption" },
        "tls-weak-cert-signature-algorithm",
      ),
    ).toBe(false);
  });

  it("flags mTLS enabled without a required client cert", () => {
    expect(
      has({ mtls_enabled: true, client_cert_required: false }, "tls-mtls-client-cert-optional"),
    ).toBe(true);
  });

  it("does not flag mTLS when the client cert is required", () => {
    expect(
      has({ mtls_enabled: true, client_cert_required: true }, "tls-mtls-client-cert-optional"),
    ).toBe(false);
  });

  it("flags OCSP stapling disabled", () => {
    expect(has({ ocsp_stapling: false }, "tls-no-ocsp-stapling")).toBe(true);
  });

  it("flags session tickets as insecure resumption", () => {
    expect(has({ session_resumption: "session_ticket" }, "tls-insecure-session-resumption")).toBe(
      true,
    );
  });

  it("flags HSTS disabled", () => {
    expect(has({ hsts: false }, "tls-no-hsts")).toBe(true);
  });

  it("returns no findings for a hardened configuration", () => {
    const findings = run({
      min_version: "TLSv1.2",
      enabled_versions: ["TLSv1.2", "TLSv1.3"],
      cipher_suites: ["TLS_AES_256_GCM_SHA384", "ECDHE-ECDSA-AES256-GCM-SHA384"],
      mtls_enabled: true,
      client_cert_required: true,
      ocsp_stapling: true,
      session_resumption: "tls13_psk",
      forward_secrecy: true,
      cert_signature_algorithm: "sha256WithRSAEncryption",
      hsts: true,
      certificate_transparency: true,
    });
    expect(findings).toHaveLength(0);
  });
});

describe("auditTlsConfig — finding shape", () => {
  it("produces deterministic finding IDs across runs", () => {
    const config: TlsConfigAuditConfig = { enabled_versions: ["TLSv1.0"], ocsp_stapling: false };
    const a = auditTlsConfig({ config, filename: "tls.conf" });
    const b = auditTlsConfig({ config, filename: "tls.conf" });
    expect(a.map((f) => f.id)).toEqual(b.map((f) => f.id));
  });

  it("tags every finding with the protocol module and a CWE", () => {
    const findings = run({ enabled_versions: ["SSLv3"], hsts: false });
    expect(findings.length).toBeGreaterThan(0);
    for (const f of findings) {
      expect(f.module).toBe("protocol");
      expect(f.tags).toContain("protocol");
      expect(f.cwe?.length ?? 0).toBeGreaterThan(0);
    }
  });
});
