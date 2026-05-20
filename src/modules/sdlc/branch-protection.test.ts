import { describe, expect, it } from "vitest";
import { auditBranchProtection } from "./branch-protection.js";

const hasRule = (
  config: Parameters<typeof auditBranchProtection>[0]["config"],
  rule: string,
): boolean => auditBranchProtection({ config }).some((f) => f.rule === rule);

describe("auditBranchProtection — required reviews", () => {
  it("flags zero required reviews", () => {
    expect(hasRule({ required_reviews: 0 }, "branch-no-required-review")).toBe(true);
  });

  it("flags an absent required_reviews setting", () => {
    expect(hasRule({}, "branch-no-required-review")).toBe(true);
  });

  it("does not flag one or more required reviews", () => {
    expect(hasRule({ required_reviews: 2 }, "branch-no-required-review")).toBe(false);
  });
});

describe("auditBranchProtection — status checks and pushes", () => {
  it("flags missing required status checks", () => {
    expect(
      hasRule(
        { required_reviews: 1, required_status_checks: false },
        "branch-no-required-status-checks",
      ),
    ).toBe(true);
  });

  it("accepts a non-empty status-check array", () => {
    expect(
      hasRule(
        { required_reviews: 1, required_status_checks: ["ci", "test"] },
        "branch-no-required-status-checks",
      ),
    ).toBe(false);
  });

  it("flags allowed force pushes", () => {
    expect(hasRule({ restrict_force_push: false }, "branch-force-push-allowed")).toBe(true);
  });

  it("flags allowed branch deletion", () => {
    expect(hasRule({ restrict_deletions: false }, "branch-deletion-allowed")).toBe(true);
  });

  it("flags admins bypassing protection", () => {
    expect(hasRule({ enforce_for_admins: false }, "branch-admins-bypass-protection")).toBe(true);
  });
});

describe("auditBranchProtection — signing and conversations", () => {
  it("flags no required signed commits", () => {
    expect(hasRule({ require_signed_commits: false }, "branch-signed-commits-not-required")).toBe(
      true,
    );
  });

  it("flags unresolved conversations not blocking merge", () => {
    expect(
      hasRule(
        { require_conversation_resolution: false },
        "branch-conversations-not-required-resolved",
      ),
    ).toBe(true);
  });
});

describe("auditBranchProtection — finding shape", () => {
  it("returns no findings for a fully protected branch", () => {
    const findings = auditBranchProtection({
      config: {
        required_reviews: 2,
        dismiss_stale_reviews: true,
        required_status_checks: ["ci"],
        require_up_to_date: true,
        enforce_for_admins: true,
        restrict_force_push: true,
        restrict_deletions: true,
        require_signed_commits: true,
        require_linear_history: true,
        require_conversation_resolution: true,
      },
    });
    expect(findings).toHaveLength(0);
  });

  it("produces deterministic finding IDs across runs", () => {
    const config = { required_reviews: 0, restrict_force_push: false };
    const a = auditBranchProtection({ config });
    const b = auditBranchProtection({ config });
    expect(a.map((f) => f.id)).toEqual(b.map((f) => f.id));
  });

  it("tags every finding with the sdlc module and a CWE", () => {
    const findings = auditBranchProtection({ config: { required_reviews: 0 } });
    expect(findings.length).toBeGreaterThan(0);
    for (const f of findings) {
      expect(f.module).toBe("sdlc");
      expect(f.tags).toContain("sdlc");
      expect(f.cwe?.length ?? 0).toBeGreaterThan(0);
    }
  });
});
