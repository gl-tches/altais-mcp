import { describe, expect, it } from "vitest";
import { checkSignedCommits, parseGitLog } from "./signed-commits.js";

const hasRule = (input: Parameters<typeof checkSignedCommits>[0], rule: string): boolean =>
  checkSignedCommits(input).some((f) => f.rule === rule);

describe("parseGitLog", () => {
  it("counts %G? good markers as signed and verified", () => {
    const stats = parseGitLog("abc1234 commit one G\ndef5678 commit two G\n");
    expect(stats).toEqual({ total: 2, signed: 2, verified: 2 });
  });

  it("counts N markers as unsigned", () => {
    const stats = parseGitLog("abc1234 commit one G\ndef5678 commit two N\n");
    expect(stats.signed).toBe(1);
    expect(stats.total).toBe(2);
  });

  it("counts a bad signature as signed but unverified", () => {
    const stats = parseGitLog("abc1234 commit one B\n");
    expect(stats.signed).toBe(1);
    expect(stats.verified).toBe(0);
  });

  it("recognizes a `Good signature` text marker on a commit line", () => {
    const stats = parseGitLog("abc1234 one gpg: Good signature\ndef5678 two gpg: Good signature\n");
    expect(stats.verified).toBe(2);
  });
});

describe("checkSignedCommits — config-driven", () => {
  it("flags signing not enforced", () => {
    expect(hasRule({ config: { signing_enforced: false } }, "commit-signing-not-enforced")).toBe(
      true,
    );
  });

  it("flags unsigned commits from a config summary", () => {
    expect(
      hasRule(
        { config: { total_commits: 10, signed_commits: 6, verified_commits: 6 } },
        "unsigned-commits-present",
      ),
    ).toBe(true);
  });

  it("flags unverified signatures from a config summary", () => {
    expect(
      hasRule(
        { config: { total_commits: 10, signed_commits: 10, verified_commits: 7 } },
        "unverified-commit-signatures",
      ),
    ).toBe(true);
  });

  it("does not flag a fully signed and verified history", () => {
    const findings = checkSignedCommits({
      config: { signing_enforced: true, total_commits: 5, signed_commits: 5, verified_commits: 5 },
    });
    expect(findings).toHaveLength(0);
  });
});

describe("checkSignedCommits — git_log-driven", () => {
  it("flags unsigned commits parsed from git log", () => {
    expect(hasRule({ git_log: "abc1234 one G\ndef5678 two N\n" }, "unsigned-commits-present")).toBe(
      true,
    );
  });

  it("produces deterministic finding IDs across runs", () => {
    const input = { config: { signing_enforced: false } };
    const a = checkSignedCommits(input);
    const b = checkSignedCommits(input);
    expect(a.map((f) => f.id)).toEqual(b.map((f) => f.id));
  });

  it("tags every finding with the sdlc module and a CWE", () => {
    const findings = checkSignedCommits({ config: { signing_enforced: false } });
    expect(findings.length).toBeGreaterThan(0);
    for (const f of findings) {
      expect(f.module).toBe("sdlc");
      expect(f.tags).toContain("sdlc");
      expect(f.cwe?.length ?? 0).toBeGreaterThan(0);
    }
  });
});
