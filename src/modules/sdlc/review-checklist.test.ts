import { describe, expect, it } from "vitest";
import { generateReviewChecklist } from "./review-checklist.js";

describe("generateReviewChecklist — base content", () => {
  it("always includes input validation, authorization, and secrets categories", () => {
    const art = generateReviewChecklist({
      change_type: "feature",
      languages: [],
      sensitivity: "low",
    });
    const categories = art.items.map((i) => i.category);
    expect(categories).toContain("Input validation");
    expect(categories).toContain("Authorization");
    expect(categories).toContain("Secrets");
  });
});

describe("generateReviewChecklist — change-type weighting", () => {
  it("adds supply-chain items for a dependency change", () => {
    const art = generateReviewChecklist({
      change_type: "dependency",
      languages: [],
      sensitivity: "medium",
    });
    expect(art.items.some((i) => i.category === "Supply chain")).toBe(true);
  });

  it("adds key-management items for a crypto change", () => {
    const art = generateReviewChecklist({
      change_type: "crypto",
      languages: [],
      sensitivity: "medium",
    });
    expect(art.items.some((i) => i.category === "Key management")).toBe(true);
  });

  it("adds a regression item for a bugfix", () => {
    const art = generateReviewChecklist({
      change_type: "bugfix",
      languages: [],
      sensitivity: "low",
    });
    expect(art.items.some((i) => i.category === "Regression")).toBe(true);
  });
});

describe("generateReviewChecklist — sensitivity and languages", () => {
  it("elevates every recommended item to mandatory for high sensitivity", () => {
    const art = generateReviewChecklist({
      change_type: "feature",
      languages: [],
      sensitivity: "high",
    });
    expect(art.items.every((i) => i.priority === "must")).toBe(true);
  });

  it("keeps some `should` items for low sensitivity", () => {
    const art = generateReviewChecklist({
      change_type: "feature",
      languages: [],
      sensitivity: "low",
    });
    expect(art.items.some((i) => i.priority === "should")).toBe(true);
  });

  it("adds a language-pitfalls item for a known language", () => {
    const art = generateReviewChecklist({
      change_type: "feature",
      languages: ["python"],
      sensitivity: "low",
    });
    expect(art.items.some((i) => i.category === "Language pitfalls")).toBe(true);
  });
});

describe("generateReviewChecklist — output shape", () => {
  it("renders a markdown checklist with checkbox items", () => {
    const art = generateReviewChecklist({
      change_type: "auth",
      languages: [],
      sensitivity: "medium",
    });
    expect(art.content).toContain("# Security review checklist");
    expect(art.content).toContain("- [ ]");
  });

  it("is deterministic across runs", () => {
    const cfg = { change_type: "auth", languages: ["go"], sensitivity: "high" } as const;
    expect(generateReviewChecklist(cfg).content).toBe(generateReviewChecklist(cfg).content);
  });
});
