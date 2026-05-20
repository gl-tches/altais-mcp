import { describe, expect, it } from "vitest";
import { auditNhi } from "./nhi.js";

describe("auditNhi", () => {
  it("flags an NHI with no owner", () => {
    const r = auditNhi({
      identities: [{ name: "deploy-bot", kind: "service_account" }],
    });
    expect(r.some((f) => f.rule === "nhi-no-owner")).toBe(true);
  });

  it("flags a static-key credential", () => {
    const r = auditNhi({
      identities: [
        { name: "ci-runner", kind: "ci_runner", owner: "infra", credential_type: "static_key" },
      ],
    });
    expect(r.some((f) => f.rule === "nhi-long-lived-static-key")).toBe(true);
  });

  it("flags overdue rotation", () => {
    const r = auditNhi({
      identities: [
        {
          name: "x",
          kind: "api_key",
          owner: "team",
          credential_type: "static_key",
          credential_age_days: 200,
          rotation_period_days: 90,
        },
      ],
    });
    expect(r.some((f) => f.rule === "nhi-credential-not-rotated")).toBe(true);
  });

  it("flags wildcard scope", () => {
    const r = auditNhi({
      identities: [{ name: "x", kind: "service_account", owner: "team", scopes: ["*"] }],
    });
    expect(r.some((f) => f.rule === "nhi-overprivileged-wildcard-scope")).toBe(true);
  });

  it("flags credential committed to repo", () => {
    const r = auditNhi({
      identities: [{ name: "x", kind: "api_key", owner: "team", stored_in_repo: true }],
    });
    expect(r.find((f) => f.rule === "nhi-credential-in-repo")?.severity).toBe("critical");
  });

  it("accepts a clean workload-identity NHI", () => {
    const r = auditNhi({
      identities: [
        {
          name: "svc",
          kind: "workload_identity",
          owner: "team",
          credential_type: "workload_identity",
          scopes: ["s3:GetObject"],
        },
      ],
    });
    expect(r).toEqual([]);
  });
});
