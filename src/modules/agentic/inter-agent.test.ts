import { describe, expect, it } from "vitest";
import { auditInterAgentComms } from "./inter-agent.js";

describe("auditInterAgentComms — positive", () => {
  it("flags unauthenticated A2A messages", () => {
    const f = auditInterAgentComms({ config: { message_authentication: false } });
    const hit = f.find((x) => x.rule === "inter-agent-no-authentication");
    expect(hit?.severity).toBe("high");
  });

  it("flags missing integrity and signing", () => {
    const f = auditInterAgentComms({
      config: { message_integrity: false, message_signing: false },
    });
    expect(f.map((x) => x.rule)).toEqual(
      expect.arrayContaining(["inter-agent-no-integrity", "inter-agent-no-signing"]),
    );
  });

  it("flags missing origin validation", () => {
    const f = auditInterAgentComms({ config: { origin_validation: false } });
    expect(f.some((x) => x.rule === "inter-agent-no-origin-validation")).toBe(true);
  });

  it("flags a cleartext channel", () => {
    const f = auditInterAgentComms({ config: { encrypted_channel: false } });
    const hit = f.find((x) => x.rule === "inter-agent-cleartext-channel");
    expect(hit?.cwe).toContain("CWE-319");
  });

  it("flags missing replay protection", () => {
    const f = auditInterAgentComms({ config: { replay_protection: false } });
    const hit = f.find((x) => x.rule === "inter-agent-no-replay-protection");
    expect(hit?.cwe).toContain("CWE-294");
  });
});

describe("auditInterAgentComms — negative", () => {
  it("returns nothing for a hardened channel", () => {
    const f = auditInterAgentComms({
      config: {
        message_authentication: true,
        message_integrity: true,
        origin_validation: true,
        encrypted_channel: true,
        message_signing: true,
        replay_protection: true,
      },
    });
    expect(f).toHaveLength(0);
  });

  it("returns nothing when no config is supplied", () => {
    expect(auditInterAgentComms({})).toHaveLength(0);
  });
});

describe("auditInterAgentComms — shape & determinism", () => {
  it("produces deterministic IDs across runs", () => {
    const a = auditInterAgentComms({ config: { message_authentication: false } });
    const b = auditInterAgentComms({ config: { message_authentication: false } });
    expect(a.map((x) => x.id)).toEqual(b.map((x) => x.id));
  });

  it("tags every finding with the module, a CWE, and ASI07", () => {
    const f = auditInterAgentComms({ config: { message_authentication: false } });
    expect(f.length).toBeGreaterThan(0);
    for (const x of f) {
      expect(x.module).toBe("agentic");
      expect((x.cwe ?? []).length).toBeGreaterThan(0);
      expect(x.tags).toContain("agentic");
      expect(x.tags).toContain("ASI07");
    }
  });
});
