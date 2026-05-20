import { describe, expect, it } from "vitest";
import { auditRandomness } from "./randomness.js";

describe("auditRandomness", () => {
  it("flags Math.random()", () => {
    const f = auditRandomness({ source: "const jitter = Math.random() * 100;" });
    expect(f.some((x) => x.rule === "random-math-random")).toBe(true);
  });

  it("escalates Math.random() used in a token context to high severity", () => {
    const f = auditRandomness({ source: "const token = Math.random().toString(36);" });
    const hit = f.find((x) => x.rule === "random-math-random-security-context");
    expect(hit).toBeDefined();
    expect(hit?.severity).toBe("high");
  });

  it("flags the Python random module", () => {
    const f = auditRandomness({ source: "code = random.randint(1000, 9999)" });
    expect(f.some((x) => x.rule === "random-python-random")).toBe(true);
  });

  it("flags java.util.Random", () => {
    const f = auditRandomness({ source: "Random r = new Random();" });
    expect(f.some((x) => x.rule === "random-java-util-random")).toBe(true);
  });

  it("flags Go math/rand", () => {
    const f = auditRandomness({ source: 'import "math/rand"' });
    expect(f.some((x) => x.rule === "random-go-math-rand")).toBe(true);
  });

  it("flags a time-seeded PRNG", () => {
    const f = auditRandomness({ source: "srand(time(NULL));" });
    expect(f.some((x) => x.rule === "random-time-seed")).toBe(true);
  });

  it("does not flag crypto.randomBytes", () => {
    const f = auditRandomness({ source: "const token = crypto.randomBytes(32);" });
    expect(f).toHaveLength(0);
  });
});
