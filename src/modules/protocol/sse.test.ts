import { describe, expect, it } from "vitest";
import { auditSse, type SseAuditInput } from "./sse.js";

const has = (input: SseAuditInput, rule: string): boolean =>
  auditSse(input).some((f) => f.rule === rule);

describe("auditSse — config posture", () => {
  it("flags TLS disabled", () => {
    expect(has({ config: { tls: false } }, "sse-plaintext-http")).toBe(true);
  });

  it("flags missing Origin validation", () => {
    expect(has({ config: { origin_validation: false } }, "sse-no-origin-check")).toBe(true);
  });

  it("flags missing authentication", () => {
    expect(has({ config: { authentication: false } }, "sse-no-authentication")).toBe(true);
  });

  it("flags missing reconnection backoff", () => {
    expect(has({ config: { reconnection_backoff: false } }, "sse-no-reconnection-backoff")).toBe(
      true,
    );
  });

  it("flags unrestricted CORS", () => {
    expect(has({ config: { cors_restricted: false } }, "sse-unrestricted-cors")).toBe(true);
  });

  it("flags a missing per-connection limit", () => {
    expect(has({ config: { per_connection_limit: false } }, "sse-no-connection-limit")).toBe(true);
  });

  it("returns no findings for a hardened config", () => {
    const findings = auditSse({
      config: {
        origin_validation: true,
        authentication: true,
        tls: true,
        reconnection_backoff: true,
        cors_restricted: true,
        per_connection_limit: true,
      },
    });
    expect(findings).toHaveLength(0);
  });
});

describe("auditSse — source scanning", () => {
  it("flags an http:// EventSource URL", () => {
    const src = 'const es = new EventSource("http://api.example.com/events");';
    expect(has({ source: src }, "sse-plaintext-http")).toBe(true);
  });

  it("does not flag an https:// EventSource URL", () => {
    const src = 'const es = new EventSource("https://api.example.com/events");';
    expect(has({ source: src }, "sse-plaintext-http")).toBe(false);
  });

  it("flags a wildcard CORS header", () => {
    const src = 'res.setHeader("Access-Control-Allow-Origin", "*");';
    expect(has({ source: src }, "sse-wildcard-cors")).toBe(true);
  });
});

describe("auditSse — finding shape", () => {
  it("produces deterministic finding IDs across runs", () => {
    const input: SseAuditInput = {
      config: { tls: false, authentication: false },
      filename: "events.ts",
    };
    const a = auditSse(input);
    const b = auditSse(input);
    expect(a.map((f) => f.id)).toEqual(b.map((f) => f.id));
  });

  it("tags every finding with the protocol module and a CWE", () => {
    const findings = auditSse({ config: { tls: false, origin_validation: false } });
    expect(findings.length).toBeGreaterThan(0);
    for (const f of findings) {
      expect(f.module).toBe("protocol");
      expect(f.tags).toContain("protocol");
      expect(f.cwe?.length ?? 0).toBeGreaterThan(0);
    }
  });
});
