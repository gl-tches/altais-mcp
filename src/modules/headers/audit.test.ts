import { describe, expect, it } from "vitest";
import { auditHeaders } from "./audit.js";

function rules(
  headers: Record<string, string>,
  context?: "html-app" | "api" | "static-asset",
): string[] {
  return auditHeaders({ headers, ...(context !== undefined ? { context } : {}) }).map(
    (f) => f.rule,
  );
}

describe("auditHeaders - CSP", () => {
  it("flags missing CSP on an html app", () => {
    expect(rules({})).toContain("csp-missing");
  });

  it("does not flag missing CSP on an API context", () => {
    expect(rules({}, "api")).not.toContain("csp-missing");
  });

  it("flags `unsafe-inline` in script-src", () => {
    const r = rules({
      "content-security-policy":
        "default-src 'self'; script-src 'self' 'unsafe-inline'; frame-ancestors 'none'",
    });
    expect(r).toContain("csp-unsafe-inline");
  });

  it("flags `unsafe-eval`", () => {
    const r = rules({
      "content-security-policy":
        "default-src 'self'; script-src 'self' 'unsafe-eval'; frame-ancestors 'none'",
    });
    expect(r).toContain("csp-unsafe-eval");
  });

  it("flags wildcard source in script-src", () => {
    const r = rules({
      "content-security-policy": "default-src 'self'; script-src *; frame-ancestors 'none'",
    });
    expect(r).toContain("csp-wildcard-source");
  });

  it("flags missing frame-ancestors when X-Frame-Options is absent", () => {
    const r = rules({ "content-security-policy": "default-src 'self'" });
    expect(r).toContain("csp-no-frame-ancestors");
  });

  it("accepts a tight CSP with no findings about CSP", () => {
    const r = rules({
      "content-security-policy":
        "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self'; frame-ancestors 'none'; base-uri 'self'; object-src 'none'",
      "strict-transport-security": "max-age=63072000; includeSubDomains; preload",
      "x-content-type-options": "nosniff",
      "x-frame-options": "DENY",
      "referrer-policy": "strict-origin-when-cross-origin",
      "permissions-policy": "camera=(), microphone=(), geolocation=()",
    });
    expect(r.filter((x) => x.startsWith("csp-"))).toEqual([]);
  });
});

describe("auditHeaders - HSTS", () => {
  it("flags missing HSTS", () => {
    expect(rules({})).toContain("hsts-missing");
  });

  it("flags HSTS without max-age", () => {
    expect(rules({ "strict-transport-security": "includeSubDomains" })).toContain(
      "hsts-no-max-age",
    );
  });

  it("flags HSTS with short max-age", () => {
    expect(rules({ "strict-transport-security": "max-age=3600" })).toContain("hsts-short-max-age");
  });

  it("flags HSTS missing includeSubDomains", () => {
    expect(rules({ "strict-transport-security": "max-age=63072000" })).toContain(
      "hsts-no-include-subdomains",
    );
  });

  it("accepts strong HSTS", () => {
    const r = rules({
      "strict-transport-security": "max-age=63072000; includeSubDomains; preload",
    });
    expect(r.filter((x) => x.startsWith("hsts-"))).toEqual([]);
  });
});

describe("auditHeaders - clickjacking", () => {
  it("flags missing X-Frame-Options when CSP has no frame-ancestors", () => {
    expect(rules({ "content-security-policy": "default-src 'self'" })).toContain(
      "x-frame-options-missing",
    );
  });

  it("accepts X-Frame-Options: DENY", () => {
    const r = rules({ "x-frame-options": "DENY" });
    expect(r).not.toContain("x-frame-options-missing");
  });

  it("flags obsolete ALLOW-FROM value", () => {
    const r = rules({ "x-frame-options": "ALLOW-FROM https://example.com" });
    expect(r).toContain("x-frame-options-allow-from");
  });
});

describe("auditHeaders - nosniff / referrer / permissions", () => {
  it("flags missing X-Content-Type-Options", () => {
    expect(rules({})).toContain("x-content-type-options-missing");
  });

  it("flags non-nosniff X-Content-Type-Options", () => {
    expect(rules({ "x-content-type-options": "nope" })).toContain("x-content-type-options-invalid");
  });

  it("flags missing Referrer-Policy", () => {
    expect(rules({})).toContain("referrer-policy-missing");
  });

  it("flags permissive Referrer-Policy", () => {
    expect(rules({ "referrer-policy": "unsafe-url" })).toContain("referrer-policy-permissive");
  });

  it("flags missing Permissions-Policy on html-app", () => {
    expect(rules({})).toContain("permissions-policy-missing");
  });
});

describe("auditHeaders - cookies + info leak + cors", () => {
  it("flags session cookie missing Secure", () => {
    expect(rules({ "set-cookie": "session=abc; HttpOnly; SameSite=Lax" })).toContain(
      "cookie-no-secure",
    );
  });

  it("flags session cookie missing HttpOnly", () => {
    expect(rules({ "set-cookie": "session=abc; Secure; SameSite=Lax" })).toContain(
      "cookie-no-httponly",
    );
  });

  it("flags session cookie missing SameSite", () => {
    expect(rules({ "set-cookie": "session=abc; Secure; HttpOnly" })).toContain(
      "cookie-no-samesite",
    );
  });

  it("does not flag a non-session cookie", () => {
    expect(rules({ "set-cookie": "preferences=darkmode" })).not.toContain("cookie-no-httponly");
  });

  it("flags Server header leak", () => {
    expect(rules({ server: "nginx/1.27.0" })).toContain("server-header-leak");
  });

  it("flags X-Powered-By leak", () => {
    expect(rules({ "x-powered-by": "Express" })).toContain("x-powered-by-leak");
  });

  it("flags CORS wildcard with credentials", () => {
    expect(
      rules({
        "access-control-allow-origin": "*",
        "access-control-allow-credentials": "true",
      }),
    ).toContain("cors-wildcard-with-credentials");
  });
});
