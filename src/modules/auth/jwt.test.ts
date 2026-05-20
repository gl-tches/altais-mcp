import { describe, expect, it } from "vitest";
import { auditJwt } from "./jwt.js";

function makeToken(header: Record<string, unknown>, payload: Record<string, unknown>): string {
  const h = Buffer.from(JSON.stringify(header)).toString("base64url");
  const p = Buffer.from(JSON.stringify(payload)).toString("base64url");
  return `${h}.${p}.sig`;
}

describe("auditJwt — source", () => {
  it("flags jwt.decode (no verify)", () => {
    const findings = auditJwt({ source: "const p = jwt.decode(token);" });
    expect(findings.some((f) => f.rule === "jwt-decode-without-verify")).toBe(true);
  });

  it("flags jwt.verify call without algorithms option", () => {
    const findings = auditJwt({ source: "jwt.verify(token, secret);" });
    expect(findings.some((f) => f.rule === "jwt-verify-no-algorithms")).toBe(true);
  });
});

describe("auditJwt — token", () => {
  it("flags alg:none token", () => {
    const t = makeToken({ alg: "none", typ: "JWT" }, { sub: "u", exp: 9999999999 });
    const findings = auditJwt({ token: t });
    expect(findings.some((f) => f.rule === "jwt-alg-none")).toBe(true);
  });

  it("flags HS256 token (symmetric)", () => {
    const t = makeToken({ alg: "HS256", typ: "JWT" }, { sub: "u", exp: 9999999999, aud: "x" });
    const findings = auditJwt({ token: t });
    expect(findings.some((f) => f.rule === "jwt-symmetric-alg")).toBe(true);
  });

  it("flags token without exp", () => {
    const t = makeToken({ alg: "RS256" }, { sub: "u", aud: "x" });
    const findings = auditJwt({ token: t });
    expect(findings.some((f) => f.rule === "jwt-no-exp")).toBe(true);
  });

  it("flags long-lived token", () => {
    const t = makeToken(
      { alg: "RS256" },
      {
        sub: "u",
        exp: Math.floor(Date.now() / 1000) + 365 * 86400,
        aud: "x",
      },
    );
    const findings = auditJwt({ token: t });
    expect(findings.some((f) => f.rule === "jwt-long-lived")).toBe(true);
  });

  it("flags token without aud", () => {
    const t = makeToken({ alg: "RS256" }, { sub: "u", exp: Math.floor(Date.now() / 1000) + 3600 });
    const findings = auditJwt({ token: t });
    expect(findings.some((f) => f.rule === "jwt-no-aud")).toBe(true);
  });

  it("flags malformed token", () => {
    const findings = auditJwt({ token: "not.a-jwt" });
    expect(findings.some((f) => f.rule === "jwt-malformed")).toBe(true);
  });
});

describe("auditJwt — config", () => {
  it("flags missing accepted_algorithms", () => {
    const findings = auditJwt({ config: {} });
    expect(findings.some((f) => f.rule === "jwt-verify-no-algorithms")).toBe(true);
  });

  it("flags mixed algorithm families", () => {
    const findings = auditJwt({
      config: { accepted_algorithms: ["HS256", "RS256"], required_aud: ["x"] },
    });
    expect(findings.some((f) => f.rule === "jwt-mixed-algorithm-families")).toBe(true);
  });

  it("flags explicit alg:none in allowlist", () => {
    const findings = auditJwt({ config: { accepted_algorithms: ["none"] } });
    expect(findings.some((f) => f.rule === "jwt-alg-none")).toBe(true);
  });

  it("flags verify_exp=false", () => {
    const findings = auditJwt({
      config: { accepted_algorithms: ["RS256"], required_aud: ["x"], verify_exp: false },
    });
    expect(findings.some((f) => f.rule === "jwt-verify-exp-disabled")).toBe(true);
  });
});
