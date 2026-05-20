import { describe, expect, it } from "vitest";
import { auditAgentIdentity } from "./agent-identity.js";

describe("auditAgentIdentity — positive", () => {
  it("flags a shared agent identity", () => {
    const f = auditAgentIdentity({ config: { per_agent_identity: false } });
    expect(f.some((x) => x.rule === "identity-shared-agent-identity")).toBe(true);
  });

  it("flags privilege inheritance", () => {
    const f = auditAgentIdentity({ config: { privilege_inheritance: true } });
    expect(f.some((x) => x.rule === "identity-privilege-inheritance")).toBe(true);
  });

  it("flags a runtime privilege-escalation path as critical", () => {
    const f = auditAgentIdentity({ config: { can_escalate_privileges: true } });
    const hit = f.find((x) => x.rule === "identity-privilege-escalation-path");
    expect(hit?.severity).toBe("critical");
  });

  it("flags missing confused-deputy protection and credential retention", () => {
    const f = auditAgentIdentity({
      config: {
        confused_deputy_protection: false,
        cross_session_credential_retention: true,
      },
    });
    expect(f.map((x) => x.rule)).toEqual(
      expect.arrayContaining([
        "identity-no-confused-deputy-protection",
        "identity-cross-session-credential-retention",
      ]),
    );
  });

  it("flags unscoped credentials and conflated user identity", () => {
    const f = auditAgentIdentity({
      config: { scoped_credentials: false, human_user_distinct_from_agent: false },
    });
    expect(f.map((x) => x.rule)).toEqual(
      expect.arrayContaining(["identity-unscoped-credentials", "identity-user-agent-conflated"]),
    );
  });
});

describe("auditAgentIdentity — negative", () => {
  it("returns nothing for a hardened identity model", () => {
    const f = auditAgentIdentity({
      config: {
        per_agent_identity: true,
        privilege_inheritance: false,
        can_escalate_privileges: false,
        confused_deputy_protection: true,
        cross_session_credential_retention: false,
        scoped_credentials: true,
        human_user_distinct_from_agent: true,
      },
    });
    expect(f).toHaveLength(0);
  });

  it("returns nothing when no config is supplied", () => {
    expect(auditAgentIdentity({})).toHaveLength(0);
  });
});

describe("auditAgentIdentity — shape & determinism", () => {
  it("produces deterministic IDs across runs", () => {
    const a = auditAgentIdentity({ config: { can_escalate_privileges: true } });
    const b = auditAgentIdentity({ config: { can_escalate_privileges: true } });
    expect(a.map((x) => x.id)).toEqual(b.map((x) => x.id));
  });

  it("tags every finding with the module, a CWE, and ASI03", () => {
    const f = auditAgentIdentity({ config: { per_agent_identity: false } });
    expect(f.length).toBeGreaterThan(0);
    for (const x of f) {
      expect(x.module).toBe("agentic");
      expect((x.cwe ?? []).length).toBeGreaterThan(0);
      expect(x.tags).toContain("agentic");
      expect(x.tags).toContain("ASI03");
    }
  });
});
