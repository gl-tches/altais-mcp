import { describe, expect, it } from "vitest";
import { auditRbac } from "./rbac.js";

describe("auditRbac", () => {
  it("flags policy.default = allow", () => {
    const r = auditRbac({
      policy: { default: "allow", roles: [{ name: "viewer", permissions: ["docs:read"] }] },
    });
    expect(r.some((f) => f.rule === "rbac-default-allow")).toBe(true);
  });

  it("flags `*` on `*` superuser permission", () => {
    const r = auditRbac({
      policy: { roles: [{ name: "root", permissions: ["*:*"] }] },
    });
    expect(r.some((f) => f.rule === "rbac-superuser")).toBe(true);
  });

  it("flags wildcard action on dangerous resource", () => {
    const r = auditRbac({
      policy: { roles: [{ name: "admin", permissions: ["delete:*"] }] },
    });
    expect(r.some((f) => f.rule === "rbac-wildcard-on-dangerous-resource")).toBe(true);
  });

  it("flags self-elevation via roles:grant", () => {
    const r = auditRbac({
      policy: { roles: [{ name: "manager", permissions: ["roles:grant"] }] },
    });
    expect(r.some((f) => f.rule === "rbac-self-elevation")).toBe(true);
  });

  it("flags inheritance cycle", () => {
    const r = auditRbac({
      policy: {
        roles: [
          { name: "a", inherits: ["b"], permissions: [] },
          { name: "b", inherits: ["a"], permissions: [] },
        ],
      },
    });
    expect(r.some((f) => f.rule === "rbac-inheritance-cycle")).toBe(true);
  });

  it("flags unknown parent role", () => {
    const r = auditRbac({
      policy: {
        roles: [{ name: "user", inherits: ["nonexistent"], permissions: [] }],
      },
    });
    expect(r.some((f) => f.rule === "rbac-unknown-parent")).toBe(true);
  });

  it("accepts a tight policy with explicit permissions", () => {
    const r = auditRbac({
      policy: {
        default: "deny",
        roles: [{ name: "viewer", permissions: ["docs:read", "docs:list"] }],
      },
    });
    expect(r).toEqual([]);
  });
});
