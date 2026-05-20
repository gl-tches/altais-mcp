import { describe, expect, it } from "vitest";
import { checkCodeowners, parseCodeowners } from "./codeowners.js";

const hasRule = (input: Parameters<typeof checkCodeowners>[0], rule: string): boolean =>
  checkCodeowners(input).some((f) => f.rule === rule);

describe("parseCodeowners", () => {
  it("parses pattern and owner tokens, skipping comments", () => {
    const rules = parseCodeowners("# header\n* @org/team\n/auth/ @org/security\n");
    expect(rules).toHaveLength(2);
    expect(rules[0]?.pattern).toBe("*");
    expect(rules[1]?.owners).toEqual(["@org/security"]);
  });
});

describe("checkCodeowners — catch-all", () => {
  it("flags a missing catch-all rule", () => {
    expect(hasRule({ content: "/auth/ @org/security\n" }, "codeowners-no-catch-all")).toBe(true);
  });

  it("does not flag when a catch-all exists", () => {
    const content = "* @org/team\n/auth/ @org/security\n";
    expect(hasRule({ content }, "codeowners-no-catch-all")).toBe(false);
  });
});

describe("checkCodeowners — sensitive paths", () => {
  it("flags a sensitive path with no specific rule", () => {
    expect(hasRule({ content: "* @org/team\n" }, "codeowners-sensitive-path-uncovered")).toBe(true);
  });

  it("does not flag a covered sensitive path", () => {
    const content = "* @org/team\n/auth/ @org/sec\n/crypto/ @org/sec\n";
    const findings = checkCodeowners({ content, sensitive_paths: ["auth", "crypto"] });
    expect(findings.some((f) => f.rule === "codeowners-sensitive-path-uncovered")).toBe(false);
  });

  it("honors a custom sensitive_paths list", () => {
    expect(
      hasRule(
        { content: "* @org/team\n", sensitive_paths: ["payments"] },
        "codeowners-sensitive-path-uncovered",
      ),
    ).toBe(true);
  });
});

describe("checkCodeowners — owner validity", () => {
  it("flags a rule with a pattern but no owner", () => {
    expect(hasRule({ content: "* @org/team\n/legacy/\n" }, "codeowners-rule-without-owner")).toBe(
      true,
    );
  });

  it("flags a malformed owner token", () => {
    expect(
      hasRule({ content: "* @org/team\n/auth/ not-an-owner\n" }, "codeowners-malformed-owner"),
    ).toBe(true);
  });

  it("flags single-owner coverage as info", () => {
    const content = "* @org/team\n/auth/ @org/team\n/crypto/ @org/team\n";
    expect(hasRule({ content }, "codeowners-single-owner-coverage")).toBe(true);
  });
});

describe("checkCodeowners — finding shape", () => {
  it("produces deterministic finding IDs across runs", () => {
    const input = { content: "/auth/ @org/security\n" };
    const a = checkCodeowners(input);
    const b = checkCodeowners(input);
    expect(a.map((f) => f.id)).toEqual(b.map((f) => f.id));
  });

  it("tags every finding with the sdlc module and a CWE", () => {
    const findings = checkCodeowners({ content: "/auth/ @org/security\n" });
    expect(findings.length).toBeGreaterThan(0);
    for (const f of findings) {
      expect(f.module).toBe("sdlc");
      expect(f.tags).toContain("sdlc");
      expect(f.cwe?.length ?? 0).toBeGreaterThan(0);
    }
  });
});
