import { describe, expect, it } from "vitest";
import { detectPii } from "./pii.js";

const rules = (source: string): readonly string[] => detectPii({ source }).map((f) => f.rule);

const has = (source: string, rule: string): boolean => rules(source).includes(rule);

describe("detectPii — value detection", () => {
  it("detects an email address", () => {
    expect(has("contact = 'jane.doe@example.com'", "pii-email-address")).toBe(true);
  });

  it("detects a US SSN", () => {
    expect(has("ssn_value = 123-45-6789", "pii-us-ssn")).toBe(true);
  });

  it("detects a Luhn-valid credit card number", () => {
    // 4111111111111111 is a well-known Visa test number (Luhn-valid).
    expect(has("card = 4111 1111 1111 1111", "pii-credit-card")).toBe(true);
  });

  it("does not flag a Luhn-invalid 16-digit number", () => {
    expect(has("orderNumber = 1234567812345678", "pii-credit-card")).toBe(false);
  });

  it("detects an IPv4 address", () => {
    expect(has("client_ip = '203.0.113.42'", "pii-ipv4-address")).toBe(true);
  });

  it("detects an IBAN", () => {
    expect(has("account = GB82WEST12345698765432", "pii-iban")).toBe(true);
  });

  it("detects a date of birth", () => {
    expect(has("birth = 14/03/1987", "pii-date-of-birth")).toBe(true);
  });

  it("detects a phone number", () => {
    expect(has("call +1 415 555 0132 now", "pii-phone-number")).toBe(true);
  });
});

describe("detectPii — identifier detection", () => {
  it("flags a PII-revealing column name in code", () => {
    expect(has("const ssn = row.social_security_number;", "pii-identifier-ssn")).toBe(true);
  });

  it("flags first_name / last_name identifiers", () => {
    expect(has("user.first_name + ' ' + user.last_name", "pii-identifier-name")).toBe(true);
  });

  it("flags a passport identifier", () => {
    expect(has("schema.passport_number = column();", "pii-identifier-government-id")).toBe(true);
  });

  it("does not flag benign source with no PII", () => {
    expect(detectPii({ source: "const total = price * quantity;" })).toHaveLength(0);
  });
});

describe("detectPii — output safety and shape", () => {
  it("never echoes the raw SSN value in evidence", () => {
    const findings = detectPii({ source: "ssn = 123-45-6789" });
    const ssn = findings.find((f) => f.rule === "pii-us-ssn");
    expect(ssn).toBeDefined();
    expect(ssn?.evidence).not.toContain("123-45-6789");
    expect(ssn?.evidence).toContain("***-**-6789");
  });

  it("masks the local part of an email in evidence", () => {
    const findings = detectPii({ source: "x = 'jane.doe@example.com'" });
    const email = findings.find((f) => f.rule === "pii-email-address");
    expect(email?.evidence).not.toContain("jane.doe@example.com");
    expect(email?.evidence).toContain("@example.com");
  });

  it("produces deterministic finding IDs across runs", () => {
    const src = "ssn = 123-45-6789; email = a@b.com";
    const a = detectPii({ source: src });
    const b = detectPii({ source: src });
    expect(a.map((f) => f.id)).toEqual(b.map((f) => f.id));
  });

  it("tags every finding with the data module and a CWE", () => {
    const findings = detectPii({ source: "ssn = 123-45-6789" });
    expect(findings.length).toBeGreaterThan(0);
    for (const f of findings) {
      expect(f.module).toBe("data");
      expect(f.tags).toContain("data");
      expect(f.cwe?.length ?? 0).toBeGreaterThan(0);
    }
  });
});
