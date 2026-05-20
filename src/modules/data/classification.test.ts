import { describe, expect, it } from "vitest";
import { classifyData, classifyDataFindings } from "./classification.js";

describe("classifyData — tier assignment", () => {
  it("classifies a password field as restricted", () => {
    const r = classifyData({ fields: [{ name: "password" }] });
    expect(r.classifications[0]?.tier).toBe("restricted");
  });

  it("classifies an SSN field as restricted", () => {
    const r = classifyData({ fields: [{ name: "ssn" }] });
    expect(r.classifications[0]?.tier).toBe("restricted");
  });

  it("classifies a health field as restricted", () => {
    const r = classifyData({ fields: [{ name: "medical_history" }] });
    expect(r.classifications[0]?.tier).toBe("restricted");
  });

  it("classifies an email field as confidential", () => {
    const r = classifyData({ fields: [{ name: "email" }] });
    expect(r.classifications[0]?.tier).toBe("confidential");
  });

  it("classifies a home address as confidential", () => {
    const r = classifyData({ fields: [{ name: "home_address" }] });
    expect(r.classifications[0]?.tier).toBe("confidential");
  });

  it("classifies created_at as internal", () => {
    const r = classifyData({ fields: [{ name: "created_at" }] });
    expect(r.classifications[0]?.tier).toBe("internal");
  });

  it("classifies a slug as public", () => {
    const r = classifyData({ fields: [{ name: "slug" }] });
    expect(r.classifications[0]?.tier).toBe("public");
  });

  it("defaults an unknown field to internal", () => {
    const r = classifyData({ fields: [{ name: "widget_count" }] });
    expect(r.classifications[0]?.tier).toBe("internal");
  });

  it("uses the description to drive classification", () => {
    const r = classifyData({
      fields: [{ name: "field_a", description: "the user's credit card number" }],
    });
    expect(r.classifications[0]?.tier).toBe("restricted");
  });
});

describe("classifyData — findings", () => {
  it("emits a finding for restricted and confidential fields only", () => {
    const findings = classifyDataFindings({
      fields: [{ name: "password" }, { name: "email" }, { name: "slug" }, { name: "created_at" }],
    });
    expect(findings).toHaveLength(2);
    expect(findings.some((f) => f.rule === "data-classified-restricted")).toBe(true);
    expect(findings.some((f) => f.rule === "data-classified-confidential")).toBe(true);
  });

  it("emits no findings for only public / internal fields", () => {
    expect(classifyDataFindings({ fields: [{ name: "slug" }, { name: "user_id" }] })).toHaveLength(
      0,
    );
  });

  it("scores restricted findings as high and confidential as medium", () => {
    const findings = classifyDataFindings({ fields: [{ name: "ssn" }, { name: "phone" }] });
    expect(findings.find((f) => f.rule === "data-classified-restricted")?.severity).toBe("high");
    expect(findings.find((f) => f.rule === "data-classified-confidential")?.severity).toBe(
      "medium",
    );
  });

  it("produces deterministic finding IDs across runs", () => {
    const input = { fields: [{ name: "ssn" }, { name: "email" }] };
    const a = classifyDataFindings(input);
    const b = classifyDataFindings(input);
    expect(a.map((f) => f.id)).toEqual(b.map((f) => f.id));
  });

  it("tags every finding with the data module and a CWE", () => {
    const findings = classifyDataFindings({ fields: [{ name: "password" }] });
    expect(findings.length).toBeGreaterThan(0);
    for (const f of findings) {
      expect(f.module).toBe("data");
      expect(f.tags).toContain("data");
      expect(f.cwe?.length ?? 0).toBeGreaterThan(0);
    }
  });
});
