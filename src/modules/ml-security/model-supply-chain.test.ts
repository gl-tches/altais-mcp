import { describe, expect, it } from "vitest";
import { auditModelSupplyChain } from "./model-supply-chain.js";

const rules = (input: Parameters<typeof auditModelSupplyChain>[0]): string[] =>
  auditModelSupplyChain(input).map((f) => f.rule);

describe("auditModelSupplyChain — format and integrity", () => {
  it("flags a pickle-format model as code-executing", () => {
    expect(rules({ config: { format: "pickle" } })).toContain(
      "model-supply-chain-executable-format",
    );
  });

  it("does not flag a safetensors model on format", () => {
    expect(rules({ config: { format: "safetensors" } })).not.toContain(
      "model-supply-chain-executable-format",
    );
  });

  it("flags an unsigned model", () => {
    expect(rules({ config: { signed: false } })).toContain("model-supply-chain-unsigned");
  });

  it("flags missing checksum verification and unpinned revision", () => {
    const r = rules({ config: { checksum_verified: false, pinned_revision: false } });
    expect(r).toContain("model-supply-chain-no-checksum");
    expect(r).toContain("model-supply-chain-unpinned-revision");
  });
});

describe("auditModelSupplyChain — source trust", () => {
  it("flags an unknown source as untrusted", () => {
    expect(rules({ config: { source: "unknown" } })).toContain(
      "model-supply-chain-untrusted-source",
    );
  });

  it("flags an external hub source", () => {
    expect(rules({ config: { source: "huggingface" } })).toContain(
      "model-supply-chain-external-source",
    );
  });

  it("does not flag an internal source", () => {
    const r = rules({ config: { source: "internal" } });
    expect(r).not.toContain("model-supply-chain-untrusted-source");
    expect(r).not.toContain("model-supply-chain-external-source");
  });

  it("flags an artifact not scanned for malware", () => {
    expect(rules({ config: { scanned_for_malware: false } })).toContain(
      "model-supply-chain-not-scanned",
    );
  });

  it("returns no findings for a fully verified internal model", () => {
    expect(
      auditModelSupplyChain({
        config: {
          source: "internal",
          format: "safetensors",
          signed: true,
          checksum_verified: true,
          scanned_for_malware: true,
          pinned_revision: true,
        },
      }),
    ).toHaveLength(0);
  });
});

describe("auditModelSupplyChain — shape and determinism", () => {
  it("produces deterministic finding IDs", () => {
    const a = auditModelSupplyChain({ config: { format: "pickle" } });
    const b = auditModelSupplyChain({ config: { format: "pickle" } });
    expect(a.map((f) => f.id)).toEqual(b.map((f) => f.id));
  });

  it("tags every finding with the ml_security module, ml-security tag, and a CWE", () => {
    const findings = auditModelSupplyChain({
      config: { format: "pickle", signed: false },
    });
    expect(findings.length).toBeGreaterThan(0);
    for (const f of findings) {
      expect(f.module).toBe("ml_security");
      expect(f.tags).toContain("ml-security");
      expect(f.cwe?.length ?? 0).toBeGreaterThan(0);
    }
  });
});
