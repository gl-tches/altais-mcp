import { describe, expect, it } from "vitest";
import { ratingFromAverage, scoreDread } from "./dread.js";

describe("scoreDread", () => {
  it("computes total + average", () => {
    const r = scoreDread({
      threat: "SQL injection on /search",
      damage: 9,
      reproducibility: 9,
      exploitability: 8,
      affected_users: 10,
      discoverability: 7,
    });
    expect(r.total).toBe(43);
    expect(r.average).toBeCloseTo(8.6, 1);
    expect(r.rating).toBe("critical");
  });

  it("clamps out-of-range inputs", () => {
    const r = scoreDread({
      threat: "x",
      damage: 99,
      reproducibility: -5,
      exploitability: 1.4,
      affected_users: 5.6,
      discoverability: 0,
    });
    expect(r.scores.damage).toBe(10);
    expect(r.scores.reproducibility).toBe(1);
    expect(r.scores.exploitability).toBe(1);
    expect(r.scores.affected_users).toBe(6);
    expect(r.scores.discoverability).toBe(1);
  });

  it("preserves the threat label and optional justification", () => {
    const r = scoreDread({
      threat: "Stored XSS in comments",
      damage: 5,
      reproducibility: 5,
      exploitability: 5,
      affected_users: 5,
      discoverability: 5,
      justification: "Affects all readers of an attacker-posted comment",
    });
    expect(r.threat).toBe("Stored XSS in comments");
    expect(r.justification).toMatch(/comment/);
  });
});

describe("ratingFromAverage", () => {
  it("maps to thresholds", () => {
    expect(ratingFromAverage(0)).toBe("info");
    expect(ratingFromAverage(1.5)).toBe("info");
    expect(ratingFromAverage(2)).toBe("low");
    expect(ratingFromAverage(3.9)).toBe("low");
    expect(ratingFromAverage(4)).toBe("medium");
    expect(ratingFromAverage(5.9)).toBe("medium");
    expect(ratingFromAverage(6)).toBe("high");
    expect(ratingFromAverage(7.9)).toBe("high");
    expect(ratingFromAverage(8)).toBe("critical");
    expect(ratingFromAverage(10)).toBe("critical");
  });
});
