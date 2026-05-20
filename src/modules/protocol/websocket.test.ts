import { describe, expect, it } from "vitest";
import { auditWebSocket, type WebSocketAuditInput } from "./websocket.js";

const has = (input: WebSocketAuditInput, rule: string): boolean =>
  auditWebSocket(input).some((f) => f.rule === rule);

describe("auditWebSocket — config posture", () => {
  it("flags TLS disabled", () => {
    expect(has({ config: { tls: false } }, "websocket-plaintext-ws")).toBe(true);
  });

  it("flags missing Origin validation", () => {
    expect(has({ config: { origin_validation: false } }, "websocket-no-origin-check")).toBe(true);
  });

  it("flags missing authentication", () => {
    expect(has({ config: { authentication: false } }, "websocket-no-authentication")).toBe(true);
  });

  it("flags unbounded message size", () => {
    expect(has({ config: { message_size_limit: false } }, "websocket-unbounded-message-size")).toBe(
      true,
    );
  });

  it("flags missing rate limiting", () => {
    expect(has({ config: { rate_limiting: false } }, "websocket-no-rate-limiting")).toBe(true);
  });

  it("returns no findings for a hardened config", () => {
    const findings = auditWebSocket({
      config: {
        tls: true,
        origin_validation: true,
        authentication: true,
        message_size_limit: true,
        rate_limiting: true,
        csrf_protection: true,
      },
    });
    expect(findings).toHaveLength(0);
  });
});

describe("auditWebSocket — source scanning", () => {
  it("flags a ws:// connection URL", () => {
    const src = 'const sock = new WebSocket("ws://api.example.com/stream");';
    expect(has({ source: src }, "websocket-plaintext-ws")).toBe(true);
  });

  it("does not flag a wss:// connection URL", () => {
    const src = 'const sock = new WebSocket("wss://api.example.com/stream");';
    expect(has({ source: src }, "websocket-plaintext-ws")).toBe(false);
  });

  it("flags verifyClient: true (no Origin check)", () => {
    const src = "const wss = new WebSocketServer({ verifyClient: true });";
    expect(has({ source: src }, "websocket-no-origin-check")).toBe(true);
  });
});

describe("auditWebSocket — finding shape", () => {
  it("produces deterministic finding IDs across runs", () => {
    const input: WebSocketAuditInput = {
      config: { tls: false, authentication: false },
      filename: "ws.ts",
    };
    const a = auditWebSocket(input);
    const b = auditWebSocket(input);
    expect(a.map((f) => f.id)).toEqual(b.map((f) => f.id));
  });

  it("tags every finding with the protocol module and a CWE", () => {
    const findings = auditWebSocket({ config: { tls: false, origin_validation: false } });
    expect(findings.length).toBeGreaterThan(0);
    for (const f of findings) {
      expect(f.module).toBe("protocol");
      expect(f.tags).toContain("protocol");
      expect(f.cwe?.length ?? 0).toBeGreaterThan(0);
    }
  });
});
