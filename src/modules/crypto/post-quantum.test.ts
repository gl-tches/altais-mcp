import { describe, expect, it } from "vitest";
import { assessPqReadiness } from "./post-quantum.js";

describe("assessPqReadiness — source", () => {
  it("flags a quantum-vulnerable algorithm in source", () => {
    const f = assessPqReadiness({ source: 'const suite = "ECDH-P256";' });
    expect(f.some((x) => x.rule === "pq-quantum-vulnerable-algorithm")).toBe(true);
  });

  it("emits an informational finding when no PQC algorithm is present", () => {
    const f = assessPqReadiness({ source: "key = RSA.generate(2048)" });
    expect(f.some((x) => x.rule === "pq-no-pqc-algorithm-detected")).toBe(true);
  });
});

describe("assessPqReadiness — config", () => {
  it("flags quantum-vulnerable algorithms in the inventory", () => {
    const f = assessPqReadiness({ config: { algorithms: ["RSA-2048", "ECDSA-P256"] } });
    expect(f.filter((x) => x.rule === "pq-quantum-vulnerable-algorithm").length).toBe(2);
  });

  it("flags harvest-now-decrypt-later exposure for long-retention data", () => {
    const f = assessPqReadiness({
      config: { algorithms: ["RSA-2048"], data_retention_years: 10 },
    });
    const hit = f.find((x) => x.rule === "pq-harvest-now-decrypt-later");
    expect(hit).toBeDefined();
    expect(hit?.severity).toBe("high");
  });

  it("flags the absence of hybrid key exchange", () => {
    const f = assessPqReadiness({
      config: { algorithms: ["ECDH-P256"], uses_hybrid: false },
    });
    expect(f.some((x) => x.rule === "pq-no-hybrid-key-exchange")).toBe(true);
  });

  it("does not flag a PQC-only inventory", () => {
    const f = assessPqReadiness({ config: { algorithms: ["ML-KEM-768", "ML-DSA-65"] } });
    expect(f).toHaveLength(0);
  });
});
