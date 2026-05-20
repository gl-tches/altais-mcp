import { describe, expect, it } from "vitest";
import { auditOAuth } from "./oauth.js";

describe("auditOAuth — source patterns", () => {
  it("flags implicit flow", () => {
    const findings = auditOAuth({
      source: 'const url = "/auth?response_type=token&client_id=...";',
    });
    expect(findings.some((f) => f.rule === "oauth-implicit-flow")).toBe(true);
  });

  it("flags password grant", () => {
    const findings = auditOAuth({
      source: 'fetch("/token", { body: "grant_type=password&username=..." })',
    });
    expect(findings.some((f) => f.rule === "oauth-password-grant")).toBe(true);
  });

  it("flags PKCE method=plain", () => {
    const findings = auditOAuth({ source: 'code_challenge_method = "plain"' });
    expect(findings.some((f) => f.rule === "oauth-pkce-plain")).toBe(true);
  });

  it("flags wildcard redirect_uri", () => {
    const findings = auditOAuth({ source: 'redirect_uri: "https://*.example.com/cb"' });
    expect(findings.some((f) => f.rule === "oauth-wildcard-redirect")).toBe(true);
  });

  it("flags token in localStorage", () => {
    const findings = auditOAuth({ source: 'localStorage.setItem("access_token", token);' });
    expect(findings.some((f) => f.rule === "oauth-token-in-localstorage")).toBe(true);
  });
});

describe("auditOAuth — config", () => {
  it("flags authorization_code without PKCE", () => {
    const findings = auditOAuth({ config: { flow: "authorization_code", pkce: { used: false } } });
    expect(findings.some((f) => f.rule === "oauth-no-pkce")).toBe(true);
  });

  it("flags non-localhost HTTP redirect", () => {
    const findings = auditOAuth({
      config: { redirect_uris: ["http://app.example.com/cb"] },
    });
    expect(findings.some((f) => f.rule === "oauth-http-redirect")).toBe(true);
  });

  it("accepts localhost HTTP redirect", () => {
    const findings = auditOAuth({
      config: { redirect_uris: ["http://localhost:3000/cb"] },
    });
    expect(findings.filter((f) => f.rule === "oauth-http-redirect")).toEqual([]);
  });

  it("flags missing state", () => {
    const findings = auditOAuth({ config: { uses_state: false } });
    expect(findings.some((f) => f.rule === "oauth-no-state")).toBe(true);
  });

  it("flags localStorage token storage", () => {
    const findings = auditOAuth({ config: { token_storage: "localStorage" } });
    expect(findings.some((f) => f.rule === "oauth-token-in-storage")).toBe(true);
  });

  it("flags refresh token rotation disabled", () => {
    const findings = auditOAuth({
      config: { refresh_token_rotation: false },
    });
    expect(findings.some((f) => f.rule === "oauth-no-refresh-rotation")).toBe(true);
  });

  it("accepts a clean PKCE + S256 + state config", () => {
    const findings = auditOAuth({
      config: {
        flow: "authorization_code",
        pkce: { used: true, method: "S256" },
        redirect_uris: ["https://app.example.com/cb"],
        uses_state: true,
        uses_nonce_for_oidc: true,
        token_storage: "httponly_cookie",
        refresh_token_rotation: true,
      },
    });
    expect(findings).toEqual([]);
  });
});
