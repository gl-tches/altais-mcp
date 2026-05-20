import { describe, expect, it } from "vitest";
import { auditCiCd } from "./ci-cd.js";

const hasRule = (input: Parameters<typeof auditCiCd>[0], rule: string): boolean =>
  auditCiCd(input).some((f) => f.rule === rule);

describe("auditCiCd — config gates", () => {
  it("flags a missing SAST gate", () => {
    expect(hasRule({ config: { has_sast: false } }, "ci-missing-sast-gate")).toBe(true);
  });

  it("flags a missing dependency scan", () => {
    expect(hasRule({ config: { has_dependency_scan: false } }, "ci-missing-dependency-scan")).toBe(
      true,
    );
  });

  it("flags a missing secret scan", () => {
    expect(hasRule({ config: { has_secret_scan: false } }, "ci-missing-secret-scan")).toBe(true);
  });

  it("flags a missing container scan", () => {
    expect(hasRule({ config: { has_container_scan: false } }, "ci-missing-container-scan")).toBe(
      true,
    );
  });

  it("flags a pipeline that does not block on failure", () => {
    expect(hasRule({ config: { blocks_on_failure: false } }, "ci-does-not-block-on-failure")).toBe(
      true,
    );
  });

  it("does not flag a gate that is present", () => {
    expect(hasRule({ config: { has_sast: true } }, "ci-missing-sast-gate")).toBe(false);
  });

  it("does not flag an unspecified gate", () => {
    expect(auditCiCd({ config: { has_sast: true } })).toHaveLength(0);
  });
});

describe("auditCiCd — pipeline YAML scanning", () => {
  it("flags an unpinned third-party action", () => {
    const yaml = "jobs:\n  build:\n    steps:\n      - uses: foo/bar-action@v1\n";
    expect(hasRule({ content: yaml }, "ci-unpinned-third-party-action")).toBe(true);
  });

  it("does not flag a SHA-pinned third-party action", () => {
    const sha = "a".repeat(40);
    const yaml = `jobs:\n  build:\n    steps:\n      - uses: foo/bar@${sha}\n`;
    expect(hasRule({ content: yaml }, "ci-unpinned-third-party-action")).toBe(false);
  });

  it("does not flag first-party actions/* by tag", () => {
    const yaml = "jobs:\n  build:\n    steps:\n      - uses: actions/checkout@v4\n";
    expect(hasRule({ content: yaml }, "ci-unpinned-third-party-action")).toBe(false);
  });

  it("flags permissions: write-all", () => {
    expect(hasRule({ content: "permissions: write-all\n" }, "ci-broad-write-permissions")).toBe(
      true,
    );
  });

  it("flags a secret echoed to the log", () => {
    const yaml = "    steps:\n      - run: echo ${{ secrets.API_TOKEN }}\n";
    expect(hasRule({ content: yaml }, "ci-secret-echoed-to-log")).toBe(true);
  });
});

describe("auditCiCd — finding shape", () => {
  it("rejects input with neither content nor config via the caller schema", () => {
    // auditCiCd itself returns empty when nothing is provided.
    expect(auditCiCd({})).toHaveLength(0);
  });

  it("produces deterministic finding IDs across runs", () => {
    const input = { config: { has_sast: false, has_secret_scan: false } };
    const a = auditCiCd(input);
    const b = auditCiCd(input);
    expect(a.map((f) => f.id)).toEqual(b.map((f) => f.id));
  });

  it("tags every finding with the sdlc module and a CWE", () => {
    const findings = auditCiCd({ config: { has_sast: false } });
    expect(findings.length).toBeGreaterThan(0);
    for (const f of findings) {
      expect(f.module).toBe("sdlc");
      expect(f.tags).toContain("sdlc");
      expect(f.cwe?.length ?? 0).toBeGreaterThan(0);
    }
  });
});
