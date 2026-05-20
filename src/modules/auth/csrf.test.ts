import { describe, expect, it } from "vitest";
import { auditCsrf } from "./csrf.js";

describe("auditCsrf — source", () => {
  it("flags explicit csurf disabled for state-changing methods", () => {
    const r = auditCsrf({ source: "csurf({ ignoreMethods: ['GET', 'POST'] })" });
    expect(r.some((f) => f.rule === "csrf-token-disabled")).toBe(true);
  });

  it("flags wildcard CORS with credentials", () => {
    const r = auditCsrf({
      source:
        "res.setHeader('Access-Control-Allow-Origin', '*');\nres.setHeader('Access-Control-Allow-Credentials', 'true');",
    });
    expect(r.some((f) => f.rule === "csrf-cors-credentials-with-wildcard")).toBe(true);
  });
});

describe("auditCsrf — config", () => {
  it("flags cookie auth without any CSRF mitigation", () => {
    const r = auditCsrf({
      config: {
        auth_via: "cookie",
        csrf_token: "none",
        samesite: "Lax",
        checks_origin_header: false,
      },
    });
    expect(r.some((f) => f.rule === "csrf-no-mitigation")).toBe(true);
  });

  it("accepts SameSite=Strict cookie auth", () => {
    const r = auditCsrf({
      config: {
        auth_via: "cookie",
        csrf_token: "none",
        samesite: "Strict",
        checks_origin_header: true,
      },
    });
    expect(r.filter((f) => f.rule === "csrf-no-mitigation")).toEqual([]);
  });

  it("flags SameSite=None without CSRF token", () => {
    const r = auditCsrf({
      config: { auth_via: "cookie", samesite: "None", csrf_token: "none" },
    });
    expect(r.some((f) => f.rule === "csrf-samesite-none-no-token")).toBe(true);
  });

  it("does not flag bearer auth", () => {
    const r = auditCsrf({ config: { auth_via: "bearer" } });
    expect(r.filter((f) => f.rule.startsWith("csrf-"))).toEqual([]);
  });
});
