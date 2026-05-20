import { describe, expect, it } from "vitest";
import { checkLlmTop10 } from "./llm-top10.js";

describe("checkLlmTop10 — coverage", () => {
  it("marks every category needs_review with an empty config", () => {
    const r = checkLlmTop10({});
    expect(r.categories).toHaveLength(10);
    expect(r.categories.every((c) => c.status === "needs_review")).toBe(true);
    expect(r.findings).toHaveLength(10);
  });

  it("marks a covered category as covered and emits no finding for it", () => {
    const r = checkLlmTop10({ config: { agency_limited: true } });
    const llm06 = r.categories.find((c) => c.id === "LLM06");
    expect(llm06?.status).toBe("covered");
    expect(r.findings.some((f) => f.rule === "llm06-excessive-agency")).toBe(false);
  });

  it("marks every category covered when all controls are present", () => {
    const r = checkLlmTop10({
      config: {
        prompt_injection_defenses: true,
        output_pii_filtering: true,
        supply_chain_verified: true,
        data_validation: true,
        output_sanitization: true,
        agency_limited: true,
        system_prompt_protected: true,
        vector_store_secured: true,
        grounding_enabled: true,
        consumption_limited: true,
      },
    });
    expect(r.categories.every((c) => c.status === "covered")).toBe(true);
    expect(r.findings).toHaveLength(0);
  });

  it("downgrades LLM01 to needs_review when source shows prompt-string interpolation", () => {
    const r = checkLlmTop10({
      config: { prompt_injection_defenses: true },
      source: 'prompt = f"answer this: {user_input}"',
    });
    expect(r.categories.find((c) => c.id === "LLM01")?.status).toBe("needs_review");
  });

  it("downgrades LLM05 to needs_review when source shows an output sink", () => {
    const r = checkLlmTop10({
      config: { output_sanitization: true },
      source: "el.innerHTML = completion",
    });
    expect(r.categories.find((c) => c.id === "LLM05")?.status).toBe("needs_review");
  });

  it("includes LLM01 through LLM10 in order", () => {
    const ids = checkLlmTop10({}).categories.map((c) => c.id);
    expect(ids).toEqual([
      "LLM01",
      "LLM02",
      "LLM03",
      "LLM04",
      "LLM05",
      "LLM06",
      "LLM07",
      "LLM08",
      "LLM09",
      "LLM10",
    ]);
  });
});

describe("checkLlmTop10 — shape and determinism", () => {
  it("produces deterministic finding IDs", () => {
    const a = checkLlmTop10({ config: { agency_limited: true } });
    const b = checkLlmTop10({ config: { agency_limited: true } });
    expect(a.findings.map((f) => f.id)).toEqual(b.findings.map((f) => f.id));
  });

  it("tags every finding with the ml_security module, ml-security tag, and a CWE", () => {
    const findings = checkLlmTop10({}).findings;
    expect(findings.length).toBeGreaterThan(0);
    for (const f of findings) {
      expect(f.module).toBe("ml_security");
      expect(f.tags).toContain("ml-security");
      expect(f.cwe?.length ?? 0).toBeGreaterThan(0);
    }
  });
});
