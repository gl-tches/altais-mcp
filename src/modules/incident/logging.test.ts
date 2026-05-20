import { describe, expect, it } from "vitest";
import { auditLogging } from "./logging.js";

const rules = (input: Parameters<typeof auditLogging>[0]): string[] =>
  auditLogging(input).map((f) => f.rule);

describe("auditLogging — config checks", () => {
  it("flags a missing audit log", () => {
    expect(rules({ config: { has_audit_log: false } })).toContain("no-audit-log");
  });

  it("flags missing authentication, authorization, and admin-action logging", () => {
    const r = rules({
      config: {
        logs_authentication: false,
        logs_authorization: false,
        logs_admin_actions: false,
      },
    });
    expect(r).toContain("missing-authentication-logging");
    expect(r).toContain("missing-authorization-logging");
    expect(r).toContain("missing-admin-action-logging");
  });

  it("flags absent log-injection protection", () => {
    expect(rules({ config: { log_injection_protection: false } })).toContain(
      "no-log-injection-protection",
    );
  });

  it("flags sensitive data logged without redaction", () => {
    expect(rules({ config: { logs_sensitive_data: true, pii_redaction: false } })).toContain(
      "logs-sensitive-data-without-redaction",
    );
  });

  it("flags too-short retention", () => {
    expect(rules({ config: { retention_days: 7 } })).toContain("retention-too-short");
  });

  it("does not flag a fully compliant logging configuration", () => {
    const r = rules({
      config: {
        has_audit_log: true,
        logs_authentication: true,
        logs_authorization: true,
        logs_admin_actions: true,
        log_injection_protection: true,
        centralized: true,
        tamper_protection: true,
        retention_days: 400,
        logs_sensitive_data: false,
        pii_redaction: true,
        includes_timestamp: true,
        includes_actor: true,
      },
    });
    expect(r).toHaveLength(0);
  });
});

describe("auditLogging — source patterns", () => {
  it("flags user input concatenated into a log call", () => {
    const r = rules({
      source: 'logger.info("login attempt for " + req.body.username);',
    });
    expect(r).toContain("log-injection-unsanitized-input");
  });

  it("flags a secret written to a log call", () => {
    const r = rules({ source: "console.log(`token is ${token}`);" });
    expect(r).toContain("sensitive-data-in-log");
  });

  it("does not flag a clean structured log call", () => {
    const r = rules({
      source: 'logger.info("user logged in", { userId });',
    });
    expect(r).toHaveLength(0);
  });
});

describe("auditLogging — finding shape", () => {
  it("produces deterministic finding IDs across runs", () => {
    const a = auditLogging({ config: { has_audit_log: false } });
    const b = auditLogging({ config: { has_audit_log: false } });
    expect(a.map((f) => f.id)).toEqual(b.map((f) => f.id));
  });

  it("tags every finding with the incident module and a CWE", () => {
    const findings = auditLogging({
      config: { has_audit_log: false, log_injection_protection: false },
    });
    expect(findings.length).toBeGreaterThan(0);
    for (const f of findings) {
      expect(f.module).toBe("incident");
      expect(f.tags).toContain("incident");
      expect(f.cwe?.length ?? 0).toBeGreaterThan(0);
    }
  });
});
