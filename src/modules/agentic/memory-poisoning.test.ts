import { describe, expect, it } from "vitest";
import { auditMemoryPoisoning } from "./memory-poisoning.js";

describe("auditMemoryPoisoning — positive", () => {
  it("flags missing memory validation", () => {
    const f = auditMemoryPoisoning({ config: { memory_validation: false } });
    const hit = f.find((x) => x.rule === "memory-no-validation");
    expect(hit?.severity).toBe("high");
  });

  it("flags cross-user memory bleed", () => {
    const f = auditMemoryPoisoning({ config: { memory_isolation_per_user: false } });
    expect(f.some((x) => x.rule === "memory-cross-user-bleed")).toBe(true);
  });

  it("flags untrusted RAG sources and persisted untrusted content", () => {
    const f = auditMemoryPoisoning({
      config: { rag_source_trust_verified: false, untrusted_content_persisted: true },
    });
    expect(f.map((x) => x.rule)).toEqual(
      expect.arrayContaining([
        "memory-untrusted-rag-sources",
        "memory-untrusted-content-persisted",
      ]),
    );
  });

  it("flags shared mutable state and missing provenance", () => {
    const f = auditMemoryPoisoning({
      config: { shared_state_between_agents: true, memory_provenance: false },
    });
    expect(f.map((x) => x.rule)).toEqual(
      expect.arrayContaining(["memory-shared-mutable-state", "memory-no-provenance"]),
    );
  });
});

describe("auditMemoryPoisoning — negative", () => {
  it("returns nothing for a hardened memory config", () => {
    const f = auditMemoryPoisoning({
      config: {
        memory_validation: true,
        memory_isolation_per_user: true,
        rag_source_trust_verified: true,
        shared_state_between_agents: false,
        memory_provenance: true,
        untrusted_content_persisted: false,
      },
    });
    expect(f).toHaveLength(0);
  });

  it("returns nothing when no config is supplied", () => {
    expect(auditMemoryPoisoning({})).toHaveLength(0);
  });
});

describe("auditMemoryPoisoning — shape & determinism", () => {
  it("produces deterministic IDs across runs", () => {
    const a = auditMemoryPoisoning({ config: { memory_validation: false } });
    const b = auditMemoryPoisoning({ config: { memory_validation: false } });
    expect(a.map((x) => x.id)).toEqual(b.map((x) => x.id));
  });

  it("tags every finding with the module, a CWE, and ASI06", () => {
    const f = auditMemoryPoisoning({ config: { memory_validation: false } });
    expect(f.length).toBeGreaterThan(0);
    for (const x of f) {
      expect(x.module).toBe("agentic");
      expect((x.cwe ?? []).length).toBeGreaterThan(0);
      expect(x.tags).toContain("agentic");
      expect(x.tags).toContain("ASI06");
    }
  });
});
