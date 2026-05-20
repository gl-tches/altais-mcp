import { describe, expect, it } from "vitest";
import { auditGrpc, type GrpcAuditInput } from "./grpc.js";

const has = (input: GrpcAuditInput, rule: string): boolean =>
  auditGrpc(input).some((f) => f.rule === rule);

describe("auditGrpc — config posture", () => {
  it("flags an insecure channel", () => {
    expect(has({ config: { insecure_channel: true } }, "grpc-insecure-channel")).toBe(true);
  });

  it("flags TLS disabled", () => {
    expect(has({ config: { tls_enabled: false } }, "grpc-insecure-channel")).toBe(true);
  });

  it("flags a missing auth interceptor", () => {
    expect(has({ config: { auth_interceptor: false } }, "grpc-no-auth-interceptor")).toBe(true);
  });

  it("flags missing deadline propagation", () => {
    expect(has({ config: { deadline_propagation: false } }, "grpc-no-deadline-propagation")).toBe(
      true,
    );
  });

  it("flags reflection enabled in production", () => {
    expect(
      has({ config: { reflection_enabled: true, production: true } }, "grpc-reflection-enabled"),
    ).toBe(true);
  });

  it("does not flag reflection outside production", () => {
    expect(
      has({ config: { reflection_enabled: true, production: false } }, "grpc-reflection-enabled"),
    ).toBe(false);
  });

  it("flags unbounded message size", () => {
    expect(has({ config: { max_message_size: false } }, "grpc-unbounded-message-size")).toBe(true);
  });

  it("returns no findings for a hardened production config", () => {
    const findings = auditGrpc({
      config: {
        tls_enabled: true,
        insecure_channel: false,
        auth_interceptor: true,
        deadline_propagation: true,
        reflection_enabled: false,
        max_message_size: true,
        production: true,
      },
    });
    expect(findings).toHaveLength(0);
  });
});

describe("auditGrpc — source scanning", () => {
  it("flags createInsecure in source", () => {
    const src = "const channel = new grpc.Client(addr, grpc.credentials.createInsecure());";
    expect(has({ source: src }, "grpc-insecure-channel")).toBe(true);
  });

  it("flags Go grpc.WithInsecure", () => {
    const src = "conn, err := grpc.Dial(addr, grpc.WithInsecure())";
    expect(has({ source: src }, "grpc-insecure-channel")).toBe(true);
  });

  it("flags registered server reflection", () => {
    const src = "reflection.register(server);";
    expect(has({ source: src }, "grpc-reflection-enabled")).toBe(true);
  });
});

describe("auditGrpc — finding shape", () => {
  it("produces deterministic finding IDs across runs", () => {
    const input: GrpcAuditInput = {
      config: { insecure_channel: true, auth_interceptor: false },
      filename: "server.ts",
    };
    const a = auditGrpc(input);
    const b = auditGrpc(input);
    expect(a.map((f) => f.id)).toEqual(b.map((f) => f.id));
  });

  it("tags every finding with the protocol module and a CWE", () => {
    const findings = auditGrpc({ config: { insecure_channel: true, deadline_propagation: false } });
    expect(findings.length).toBeGreaterThan(0);
    for (const f of findings) {
      expect(f.module).toBe("protocol");
      expect(f.tags).toContain("protocol");
      expect(f.cwe?.length ?? 0).toBeGreaterThan(0);
    }
  });
});
