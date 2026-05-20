import { describe, expect, it } from "vitest";
import { loadOwaspKnowledge } from "./knowledge.js";

describe("loadOwaspKnowledge", () => {
  it("loads the bundled knowledge file", async () => {
    const k = await loadOwaspKnowledge();
    expect(k.web_top_10_2025).toHaveLength(10);
    expect(k.api_top_10_2023).toHaveLength(10);
    expect(k.mobile_top_10_2024).toHaveLength(10);
    expect(k.serverless_top_10).toHaveLength(10);
    expect(k.asvs.controls.length).toBeGreaterThan(20);
  });

  it("Web Top 10:2025 IDs are A01..A10:2025", async () => {
    const k = await loadOwaspKnowledge();
    const ids = k.web_top_10_2025.map((c) => c.id).sort();
    expect(ids).toEqual([
      "A01:2025",
      "A02:2025",
      "A03:2025",
      "A04:2025",
      "A05:2025",
      "A06:2025",
      "A07:2025",
      "A08:2025",
      "A09:2025",
      "A10:2025",
    ]);
  });

  it("A03:2025 is Software Supply Chain Failures", async () => {
    const k = await loadOwaspKnowledge();
    const a03 = k.web_top_10_2025.find((c) => c.id === "A03:2025");
    expect(a03?.name).toMatch(/Supply Chain/);
  });

  it("A10:2025 is Mishandling of Exceptional Conditions", async () => {
    const k = await loadOwaspKnowledge();
    const a10 = k.web_top_10_2025.find((c) => c.id === "A10:2025");
    expect(a10?.name).toMatch(/Exceptional/i);
  });

  it("every category has at least one CWE and detection hint", async () => {
    const k = await loadOwaspKnowledge();
    for (const list of [
      k.web_top_10_2025,
      k.api_top_10_2023,
      k.mobile_top_10_2024,
      k.serverless_top_10,
    ]) {
      for (const c of list) {
        expect(c.cwes.length).toBeGreaterThan(0);
        expect(c.detection_hints.length).toBeGreaterThan(0);
        expect(c.remediation.length).toBeGreaterThan(20);
      }
    }
  });

  it("ASVS controls span sections V1..V14 with valid levels", async () => {
    const k = await loadOwaspKnowledge();
    const sections = new Set(k.asvs.controls.map((c) => c.section));
    expect(sections.size).toBeGreaterThanOrEqual(10);
    for (const c of k.asvs.controls) {
      expect([1, 2, 3]).toContain(c.level);
      expect(c.section).toMatch(/^V\d+$/);
    }
  });
});
