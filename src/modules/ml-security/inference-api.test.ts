import { describe, expect, it } from "vitest";
import { auditInferenceApi } from "./inference-api.js";

const rules = (input: Parameters<typeof auditInferenceApi>[0]): string[] =>
  auditInferenceApi(input).map((f) => f.rule);

describe("auditInferenceApi — config", () => {
  it("flags missing rate limiting as model-extraction risk", () => {
    expect(rules({ config: { rate_limited: false } })).toContain("inference-api-no-rate-limiting");
  });

  it("flags missing authentication", () => {
    expect(rules({ config: { authentication: false } })).toContain(
      "inference-api-no-authentication",
    );
  });

  it("flags exposed logits and confidence scores", () => {
    const r = rules({ config: { returns_logits: true, returns_confidence_scores: true } });
    expect(r).toContain("inference-api-exposes-logits");
    expect(r).toContain("inference-api-exposes-confidence-scores");
  });

  it("flags missing input validation as adversarial-evasion risk", () => {
    expect(rules({ config: { input_validation: false } })).toContain(
      "inference-api-no-input-validation",
    );
  });

  it("flags an unthrottled batch endpoint", () => {
    expect(rules({ config: { batch_endpoint: true } })).toContain(
      "inference-api-unthrottled-batch",
    );
  });

  it("does not flag a batch endpoint that is rate limited", () => {
    expect(rules({ config: { batch_endpoint: true, rate_limited: true } })).not.toContain(
      "inference-api-unthrottled-batch",
    );
  });

  it("returns no findings for a fully hardened API", () => {
    expect(
      auditInferenceApi({
        config: {
          rate_limited: true,
          authentication: true,
          returns_confidence_scores: false,
          returns_logits: false,
          input_validation: true,
          batch_endpoint: false,
          monitoring: true,
          query_logging: true,
        },
      }),
    ).toHaveLength(0);
  });
});

describe("auditInferenceApi — source and shape", () => {
  it("flags logits exposure in source", () => {
    expect(rules({ source: 'return {"logits": out.logits}' })).toContain(
      "inference-api-returns-logits-source",
    );
  });

  it("produces deterministic finding IDs", () => {
    const a = auditInferenceApi({ config: { rate_limited: false } });
    const b = auditInferenceApi({ config: { rate_limited: false } });
    expect(a.map((f) => f.id)).toEqual(b.map((f) => f.id));
  });

  it("tags every finding with the ml_security module, ml-security tag, and a CWE", () => {
    const findings = auditInferenceApi({
      config: { rate_limited: false, authentication: false },
    });
    expect(findings.length).toBeGreaterThan(0);
    for (const f of findings) {
      expect(f.module).toBe("ml_security");
      expect(f.tags).toContain("ml-security");
      expect(f.cwe?.length ?? 0).toBeGreaterThan(0);
    }
  });
});
