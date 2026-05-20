import { describe, expect, it } from "vitest";
import { auditSession } from "./session.js";

describe("auditSession — source", () => {
  it("flags secure: false", () => {
    const r = auditSession({ source: "app.use(session({ cookie: { secure: false } }))" });
    expect(r.some((f) => f.rule === "session-secure-false")).toBe(true);
  });

  it("flags httpOnly: false", () => {
    const r = auditSession({ source: "cookie: { httpOnly: false }" });
    expect(r.some((f) => f.rule === "session-httponly-false")).toBe(true);
  });

  it("flags SameSite=None", () => {
    const r = auditSession({ source: "sameSite: 'none'" });
    expect(r.some((f) => f.rule === "session-samesite-none")).toBe(true);
  });
});

describe("auditSession — config", () => {
  it("flags secure=false", () => {
    const r = auditSession({ config: { cookie: { secure: false } } });
    expect(r.some((f) => f.rule === "session-secure-false")).toBe(true);
  });

  it("flags missing SameSite", () => {
    const r = auditSession({ config: { cookie: { secure: true, httpOnly: true } } });
    expect(r.some((f) => f.rule === "session-samesite-missing")).toBe(true);
  });

  it("flags fixation", () => {
    const r = auditSession({ config: { regenerate_on_login: false } });
    expect(r.some((f) => f.rule === "session-fixation")).toBe(true);
  });

  it("flags absence of logout invalidation", () => {
    const r = auditSession({ config: { invalidate_on_logout: false } });
    expect(r.some((f) => f.rule === "session-no-logout-invalidation")).toBe(true);
  });

  it("flags long absolute timeout", () => {
    const r = auditSession({ config: { absolute_timeout_seconds: 365 * 86400 } });
    expect(r.some((f) => f.rule === "session-long-absolute-timeout")).toBe(true);
  });

  it("flags low entropy session ID", () => {
    const r = auditSession({ config: { id_entropy_bits: 64 } });
    expect(r.some((f) => f.rule === "session-low-entropy-id")).toBe(true);
  });
});
