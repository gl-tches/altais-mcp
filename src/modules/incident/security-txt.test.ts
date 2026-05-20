import { describe, expect, it } from "vitest";
import { generateSecurityTxt } from "./security-txt.js";

describe("generateSecurityTxt", () => {
  it("emits a Contact and an Expires field", () => {
    const r = generateSecurityTxt({ contact: "security@example.com" });
    expect(r.content).toContain("Contact:");
    expect(r.content).toContain("Expires:");
  });

  it("wraps a bare email address in a mailto: scheme", () => {
    const r = generateSecurityTxt({ contact: "security@example.com" });
    expect(r.content).toContain("Contact: mailto:security@example.com");
  });

  it("preserves a URL contact unchanged", () => {
    const r = generateSecurityTxt({ contact: "https://example.com/report" });
    expect(r.content).toContain("Contact: https://example.com/report");
  });

  it("includes optional fields when supplied", () => {
    const r = generateSecurityTxt({
      contact: "security@example.com",
      encryption: "https://example.com/pgp.txt",
      policy: "https://example.com/policy",
      preferred_languages: "en, fr",
      canonical: "https://example.com/.well-known/security.txt",
    });
    expect(r.content).toContain("Encryption: https://example.com/pgp.txt");
    expect(r.content).toContain("Policy: https://example.com/policy");
    expect(r.content).toContain("Preferred-Languages: en, fr");
    expect(r.content).toContain("Canonical:");
  });

  it("omits optional fields that are not supplied", () => {
    const r = generateSecurityTxt({ contact: "security@example.com" });
    expect(r.content).not.toContain("Encryption:");
    expect(r.content).not.toContain("Hiring:");
  });

  it("reports the .well-known placement path", () => {
    const r = generateSecurityTxt({ contact: "security@example.com" });
    expect(r.placement).toBe("/.well-known/security.txt");
    expect(r.notes.some((n) => n.includes(".well-known"))).toBe(true);
  });

  it("produces a future-dated Expires field that respects expires_days", () => {
    const short = generateSecurityTxt({ contact: "security@example.com", expires_days: 30 });
    const long = generateSecurityTxt({ contact: "security@example.com", expires_days: 365 });
    expect(Date.parse(short.expires)).toBeLessThan(Date.parse(long.expires));
  });

  it("is deterministic for the same input", () => {
    const a = generateSecurityTxt({ contact: "security@example.com", expires_days: 90 });
    const b = generateSecurityTxt({ contact: "security@example.com", expires_days: 90 });
    expect(a.content).toEqual(b.content);
  });
});
