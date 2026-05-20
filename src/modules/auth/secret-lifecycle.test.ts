import { describe, expect, it } from "vitest";
import { auditSecretLifecycle } from "./secret-lifecycle.js";

const DAY = 86_400_000;

describe("auditSecretLifecycle", () => {
  it("flags secrets stored in a repository", () => {
    const r = auditSecretLifecycle({
      secrets: [{ name: "stripe-key", kind: "api_key", stored_in: "repo" }],
    });
    expect(r.some((f) => f.rule === "secret-stored-in-repo")).toBe(true);
  });

  it("flags overdue rotation", () => {
    const lastRotated = new Date(Date.now() - 365 * DAY).toISOString();
    const r = auditSecretLifecycle({
      secrets: [{ name: "k", kind: "api_key", last_rotated_at: lastRotated }],
    });
    expect(r.some((f) => f.rule === "secret-rotation-overdue")).toBe(true);
  });

  it("flags never-rotated secrets older than the threshold", () => {
    const created = new Date(Date.now() - 365 * DAY).toISOString();
    const r = auditSecretLifecycle({
      secrets: [{ name: "k", kind: "api_key", created_at: created }],
    });
    expect(r.some((f) => f.rule === "secret-never-rotated")).toBe(true);
  });

  it("flags missing expiry", () => {
    const r = auditSecretLifecycle({
      secrets: [{ name: "k", kind: "signing_key" }],
    });
    expect(r.some((f) => f.rule === "secret-no-expiry")).toBe(true);
  });

  it("flags an expired-but-listed secret", () => {
    const expired = new Date(Date.now() - 10 * DAY).toISOString();
    const r = auditSecretLifecycle({
      secrets: [{ name: "k", kind: "api_key", expires_at: expired }],
    });
    expect(r.some((f) => f.rule === "secret-expired-still-in-use")).toBe(true);
  });

  it("accepts a managed, rotated, expiring secret", () => {
    const now = Date.now();
    const r = auditSecretLifecycle({
      secrets: [
        {
          name: "k",
          kind: "api_key",
          last_rotated_at: new Date(now - 30 * DAY).toISOString(),
          expires_at: new Date(now + 60 * DAY).toISOString(),
          stored_in: "vault",
          revocation_procedure_documented: true,
          audit_logged: true,
        },
      ],
    });
    expect(r).toEqual([]);
  });
});
