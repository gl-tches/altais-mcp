import { describe, expect, it } from "vitest";
import { checkNhiIsolation } from "./nhi-isolation.js";

describe("checkNhiIsolation", () => {
  it("flags pre-prod identity that can reach prod", () => {
    const r = checkNhiIsolation({
      identities: [{ name: "ci-bot", environment: "dev", cross_environment_access: ["prod"] }],
    });
    expect(r.some((f) => f.rule === "nhi-preprod-reaches-prod")).toBe(true);
  });

  it("flags identity with no boundary annotation", () => {
    const r = checkNhiIsolation({
      identities: [{ name: "ambiguous" }],
    });
    expect(r.some((f) => f.rule === "nhi-no-boundary")).toBe(true);
  });

  it("flags wildcard scope at isolation level", () => {
    const r = checkNhiIsolation({
      identities: [{ name: "svc", environment: "prod", scopes: ["s3:*"] }],
    });
    expect(r.some((f) => f.rule === "nhi-isolation-broad-scope")).toBe(true);
  });

  it("accepts a properly isolated identity", () => {
    const r = checkNhiIsolation({
      identities: [
        { name: "svc", environment: "prod", namespace: "payments", scopes: ["s3:GetObject"] },
      ],
    });
    expect(r).toEqual([]);
  });
});
