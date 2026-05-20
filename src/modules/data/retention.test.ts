import { describe, expect, it } from "vitest";
import { checkRetention, type RetentionPolicy } from "./retention.js";

const rules = (policy: RetentionPolicy): readonly string[] =>
  checkRetention({ policies: [policy] }).map((f) => f.rule);

const has = (policy: RetentionPolicy, rule: string): boolean => rules(policy).includes(rule);

describe("checkRetention — policy checks", () => {
  it("flags a missing retention period", () => {
    expect(
      has({ data_category: "logs", automated_deletion: true }, "retention-missing-period"),
    ).toBe(true);
  });

  it("flags indefinite retention (non-positive period)", () => {
    expect(
      has(
        { data_category: "logs", retention_period_days: -1, automated_deletion: true },
        "retention-indefinite",
      ),
    ).toBe(true);
  });

  it("flags excessively long retention beyond the threshold", () => {
    expect(
      has(
        { data_category: "logs", retention_period_days: 5000, automated_deletion: true },
        "retention-excessive",
      ),
    ).toBe(true);
  });

  it("flags a category with no automated deletion", () => {
    expect(
      has({ data_category: "logs", retention_period_days: 90 }, "retention-no-automated-deletion"),
    ).toBe(true);
  });

  it("flags a deletion_method of none", () => {
    expect(
      has(
        {
          data_category: "logs",
          retention_period_days: 90,
          automated_deletion: true,
          deletion_method: "none",
        },
        "retention-no-deletion-method",
      ),
    ).toBe(true);
  });

  it("flags a PII category that uses only soft delete", () => {
    expect(
      has(
        {
          data_category: "user_profile",
          retention_period_days: 90,
          automated_deletion: true,
          deletion_method: "soft_delete",
          contains_pii: true,
          legal_basis: "consent",
        },
        "retention-pii-soft-delete-only",
      ),
    ).toBe(true);
  });

  it("flags a PII category with no legal basis", () => {
    expect(
      has(
        {
          data_category: "user_profile",
          retention_period_days: 90,
          automated_deletion: true,
          deletion_method: "hard_delete",
          contains_pii: true,
        },
        "retention-pii-no-legal-basis",
      ),
    ).toBe(true);
  });

  it("does not flag a fully compliant policy", () => {
    expect(
      checkRetention({
        policies: [
          {
            data_category: "user_profile",
            retention_period_days: 365,
            automated_deletion: true,
            deletion_method: "hard_delete",
            contains_pii: true,
            legal_basis: "contract",
          },
        ],
      }),
    ).toHaveLength(0);
  });
});

describe("checkRetention — source scan", () => {
  it("flags hardcoded indefinite retention in source", () => {
    const findings = checkRetention({
      policies: [
        {
          data_category: "events",
          retention_period_days: 30,
          automated_deletion: true,
        },
      ],
      source: "const retention = 'forever';",
    });
    expect(findings.some((f) => f.rule === "retention-source-indefinite")).toBe(true);
  });

  it("does not flag source with a finite retention value", () => {
    const findings = checkRetention({
      policies: [
        {
          data_category: "events",
          retention_period_days: 30,
          automated_deletion: true,
        },
      ],
      source: "const retention_days = 30;",
    });
    expect(findings.some((f) => f.rule === "retention-source-indefinite")).toBe(false);
  });
});

describe("checkRetention — determinism and shape", () => {
  it("produces deterministic finding IDs across runs", () => {
    const input = {
      policies: [{ data_category: "logs", contains_pii: true }],
      source: "ttl = never",
    };
    const a = checkRetention(input);
    const b = checkRetention(input);
    expect(a.map((f) => f.id)).toEqual(b.map((f) => f.id));
  });

  it("tags every finding with the data module and a CWE", () => {
    const findings = checkRetention({ policies: [{ data_category: "logs", contains_pii: true }] });
    expect(findings.length).toBeGreaterThan(0);
    for (const f of findings) {
      expect(f.module).toBe("data");
      expect(f.tags).toContain("data");
      expect(f.cwe?.length ?? 0).toBeGreaterThan(0);
    }
  });
});
