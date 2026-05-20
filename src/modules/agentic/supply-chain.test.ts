import { describe, expect, it } from "vitest";
import { auditAgenticSupplyChain } from "./supply-chain.js";

describe("auditAgenticSupplyChain — positive", () => {
  it("flags unsigned manifests", () => {
    const f = auditAgenticSupplyChain({ config: { manifests_signed: false } });
    const hit = f.find((x) => x.rule === "supply-chain-unsigned-manifests");
    expect(hit?.severity).toBe("high");
  });

  it("flags unverified plugins", () => {
    const f = auditAgenticSupplyChain({ config: { plugins_verified: false } });
    expect(f.some((x) => x.rule === "supply-chain-unverified-plugins")).toBe(true);
  });

  it("flags unverified agent cards and unpinned registries", () => {
    const f = auditAgenticSupplyChain({
      config: { agent_cards_verified: false, registry_pinned: false },
    });
    expect(f.map((x) => x.rule)).toEqual(
      expect.arrayContaining([
        "supply-chain-unverified-agent-cards",
        "supply-chain-unpinned-registry",
      ]),
    );
  });

  it("flags missing typosquat check and provenance", () => {
    const f = auditAgenticSupplyChain({
      config: { typosquat_checked: false, provenance_attestation: false },
    });
    expect(f.map((x) => x.rule)).toEqual(
      expect.arrayContaining(["supply-chain-no-typosquat-check", "supply-chain-no-provenance"]),
    );
  });

  it("flags an MCP server from an untrusted source", () => {
    const f = auditAgenticSupplyChain({
      config: { mcp_servers: [{ name: "files", source: "unknown" }] },
    });
    expect(f.some((x) => x.rule === "supply-chain-untrusted-mcp-server")).toBe(true);
  });
});

describe("auditAgenticSupplyChain — negative", () => {
  it("returns nothing for a hardened supply chain", () => {
    const f = auditAgenticSupplyChain({
      config: {
        mcp_servers: [{ name: "files", source: "vendor" }],
        manifests_signed: true,
        plugins_verified: true,
        agent_cards_verified: true,
        registry_pinned: true,
        typosquat_checked: true,
        provenance_attestation: true,
      },
    });
    expect(f).toHaveLength(0);
  });

  it("returns nothing when no config is supplied", () => {
    expect(auditAgenticSupplyChain({})).toHaveLength(0);
  });
});

describe("auditAgenticSupplyChain — shape & determinism", () => {
  it("produces deterministic IDs across runs", () => {
    const a = auditAgenticSupplyChain({ config: { manifests_signed: false } });
    const b = auditAgenticSupplyChain({ config: { manifests_signed: false } });
    expect(a.map((x) => x.id)).toEqual(b.map((x) => x.id));
  });

  it("tags every finding with the module, a CWE, and ASI04", () => {
    const f = auditAgenticSupplyChain({ config: { manifests_signed: false } });
    expect(f.length).toBeGreaterThan(0);
    for (const x of f) {
      expect(x.module).toBe("agentic");
      expect((x.cwe ?? []).length).toBeGreaterThan(0);
      expect(x.tags).toContain("agentic");
      expect(x.tags).toContain("ASI04");
    }
  });
});
