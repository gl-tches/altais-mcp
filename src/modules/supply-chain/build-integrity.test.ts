import { describe, expect, it } from "vitest";
import { checkBuildIntegrity } from "./build-integrity.js";

describe("checkBuildIntegrity", () => {
  it("flags action pinned to a moving tag", () => {
    const yaml = `
jobs:
  build:
    steps:
      - uses: third-party/action@v3
`;
    const r = checkBuildIntegrity(yaml, ".github/workflows/ci.yml");
    expect(r.findings.some((f) => f.rule === "action-unpinned-tag")).toBe(true);
  });

  it("flags action pinned to a branch", () => {
    const yaml = `jobs:\n  x:\n    steps:\n      - uses: who/what@main\n`;
    const r = checkBuildIntegrity(yaml, undefined);
    expect(r.findings.some((f) => f.rule === "action-floating-branch")).toBe(true);
  });

  it("flags a secret echoed to logs", () => {
    const yaml = `
steps:
  - run: echo "token=\${{ secrets.GITHUB_TOKEN }}"
`;
    const r = checkBuildIntegrity(yaml, undefined);
    expect(r.findings.some((f) => f.rule === "secret-echoed-in-step")).toBe(true);
  });

  it("flags top-level write-all permissions", () => {
    const yaml = `permissions: write-all\njobs: {}\n`;
    const r = checkBuildIntegrity(yaml, undefined);
    expect(r.findings.some((f) => f.rule === "permissions-write-all")).toBe(true);
  });

  it("flags curl|bash", () => {
    const yaml = `steps:\n  - run: curl https://example.com/install.sh | bash\n`;
    const r = checkBuildIntegrity(yaml, undefined);
    expect(r.findings.some((f) => f.rule === "curl-bash-pipeline")).toBe(true);
  });

  it("accepts a SHA-pinned action without flagging it", () => {
    const yaml = `steps:\n  - uses: who/what@abcdef0123456789abcdef0123456789abcdef01\n`;
    const r = checkBuildIntegrity(yaml, undefined);
    expect(r.findings.filter((f) => f.rule.startsWith("action-"))).toEqual([]);
  });
});
