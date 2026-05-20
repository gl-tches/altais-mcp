import { describe, expect, it } from "vitest";
import { auditApiGateway } from "./gateway.js";
import type { GatewayConfig } from "./gateway.js";

function has(config: GatewayConfig, rule: string): boolean {
  return auditApiGateway({ config }).some((f) => f.rule === rule);
}

// A reasonably-hardened gateway configuration used as the negative baseline.
const SECURE_CONFIG: GatewayConfig = {
  authentication_enabled: true,
  authorization_enabled: true,
  tls_enabled: true,
  min_tls_version: "1.3",
  waf_enabled: true,
  request_validation: true,
  request_size_limit_bytes: 1_048_576,
  timeout_seconds: 30,
  rate_limiting_enabled: true,
  logging_enabled: true,
  cors: { allow_all_origins: false, allow_credentials: true },
  ip_allowlist_enabled: true,
  mtls_enabled: true,
  api_keys_rotated: true,
  backend_tls: true,
};

describe("auditApiGateway — authentication and authorization", () => {
  it("flags authentication disabled as critical", () => {
    const findings = auditApiGateway({
      config: { ...SECURE_CONFIG, authentication_enabled: false },
    });
    const f = findings.find((x) => x.rule === "gateway-authentication-disabled");
    expect(f).toBeDefined();
    expect(f?.severity).toBe("critical");
  });

  it("flags authorization disabled", () => {
    expect(
      has({ ...SECURE_CONFIG, authorization_enabled: false }, "gateway-authorization-disabled"),
    ).toBe(true);
  });
});

describe("auditApiGateway — transport", () => {
  it("flags TLS disabled", () => {
    expect(has({ ...SECURE_CONFIG, tls_enabled: false }, "gateway-tls-disabled")).toBe(true);
  });

  it("flags a TLS version below 1.2", () => {
    expect(has({ ...SECURE_CONFIG, min_tls_version: "1.0" }, "gateway-weak-tls-version")).toBe(
      true,
    );
  });

  it("does not flag TLS 1.2 as weak", () => {
    expect(has({ ...SECURE_CONFIG, min_tls_version: "TLSv1.2" }, "gateway-weak-tls-version")).toBe(
      false,
    );
  });

  it("flags cleartext gateway-to-backend traffic", () => {
    expect(has({ ...SECURE_CONFIG, backend_tls: false }, "gateway-cleartext-backend")).toBe(true);
  });
});

describe("auditApiGateway — edge protections", () => {
  it("flags a disabled WAF", () => {
    expect(has({ ...SECURE_CONFIG, waf_enabled: false }, "gateway-waf-disabled")).toBe(true);
  });

  it("flags missing request validation", () => {
    expect(
      has({ ...SECURE_CONFIG, request_validation: false }, "gateway-no-request-validation"),
    ).toBe(true);
  });

  it("flags a missing request size limit", () => {
    const cfg: GatewayConfig = { ...SECURE_CONFIG };
    const { request_size_limit_bytes: _omit, ...withoutLimit } = cfg;
    void _omit;
    expect(has(withoutLimit, "gateway-no-request-size-limit")).toBe(true);
  });

  it("flags a missing timeout", () => {
    const { timeout_seconds: _omit, ...withoutTimeout } = SECURE_CONFIG;
    void _omit;
    expect(has(withoutTimeout, "gateway-no-timeout")).toBe(true);
  });

  it("flags an over-long timeout", () => {
    expect(has({ ...SECURE_CONFIG, timeout_seconds: 300 }, "gateway-long-timeout")).toBe(true);
  });

  it("flags rate limiting disabled", () => {
    expect(
      has({ ...SECURE_CONFIG, rate_limiting_enabled: false }, "gateway-rate-limiting-disabled"),
    ).toBe(true);
  });

  it("flags logging disabled", () => {
    expect(has({ ...SECURE_CONFIG, logging_enabled: false }, "gateway-logging-disabled")).toBe(
      true,
    );
  });
});

describe("auditApiGateway — CORS", () => {
  it("flags wildcard origin combined with credentials", () => {
    expect(
      has(
        { ...SECURE_CONFIG, cors: { allow_all_origins: true, allow_credentials: true } },
        "gateway-cors-wildcard-with-credentials",
      ),
    ).toBe(true);
  });

  it("flags a wildcard origin without credentials at lower severity", () => {
    expect(
      has(
        { ...SECURE_CONFIG, cors: { allow_all_origins: true, allow_credentials: false } },
        "gateway-cors-wildcard-origin",
      ),
    ).toBe(true);
  });
});

describe("auditApiGateway — baseline and shape", () => {
  it("produces no findings for a hardened configuration", () => {
    expect(auditApiGateway({ config: SECURE_CONFIG })).toHaveLength(0);
  });

  it("produces deterministic finding IDs across runs", () => {
    const cfg: GatewayConfig = { authentication_enabled: false, tls_enabled: false };
    const a = auditApiGateway({ config: cfg, filename: "gw.yaml" });
    const b = auditApiGateway({ config: cfg, filename: "gw.yaml" });
    expect(a.map((f) => f.id)).toEqual(b.map((f) => f.id));
  });

  it("tags every finding with the api module, a CWE, and the api tag", () => {
    const findings = auditApiGateway({ config: { authentication_enabled: false } });
    expect(findings.length).toBeGreaterThan(0);
    for (const f of findings) {
      expect(f.module).toBe("api");
      expect(f.cwe?.length ?? 0).toBeGreaterThan(0);
      expect(f.tags).toContain("api");
    }
  });
});
