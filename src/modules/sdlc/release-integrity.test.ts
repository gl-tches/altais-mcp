import { describe, expect, it } from "vitest";
import { checkReleaseIntegrity } from "./release-integrity.js";

const hasRule = (
  config: Parameters<typeof checkReleaseIntegrity>[0]["config"],
  rule: string,
): boolean => checkReleaseIntegrity({ config }).some((f) => f.rule === rule);

describe("checkReleaseIntegrity — missing controls", () => {
  it("flags unsigned artifacts", () => {
    expect(hasRule({ artifacts_signed: false }, "release-artifacts-unsigned")).toBe(true);
  });

  it("flags missing checksums", () => {
    expect(hasRule({ checksums_published: false }, "release-no-checksums")).toBe(true);
  });

  it("flags a missing SBOM", () => {
    expect(hasRule({ sbom_published: false }, "release-no-sbom")).toBe(true);
  });

  it("flags missing provenance", () => {
    expect(hasRule({ provenance_attestation: false }, "release-no-provenance")).toBe(true);
  });

  it("flags releases from an unprotected branch", () => {
    expect(
      hasRule({ release_from_protected_branch: false }, "release-from-unprotected-branch"),
    ).toBe(true);
  });

  it("flags unsigned tags", () => {
    expect(hasRule({ tags_signed: false }, "release-tags-unsigned")).toBe(true);
  });
});

describe("checkReleaseIntegrity — present controls", () => {
  it("does not flag a control that is present", () => {
    expect(hasRule({ artifacts_signed: true }, "release-artifacts-unsigned")).toBe(false);
  });

  it("returns no findings when every control is satisfied", () => {
    const findings = checkReleaseIntegrity({
      config: {
        artifacts_signed: true,
        checksums_published: true,
        reproducible_build: true,
        sbom_published: true,
        provenance_attestation: true,
        release_from_protected_branch: true,
        changelog_maintained: true,
        tags_signed: true,
      },
    });
    expect(findings).toHaveLength(0);
  });
});

describe("checkReleaseIntegrity — finding shape", () => {
  it("produces deterministic finding IDs across runs", () => {
    const config = { artifacts_signed: false, sbom_published: false };
    const a = checkReleaseIntegrity({ config });
    const b = checkReleaseIntegrity({ config });
    expect(a.map((f) => f.id)).toEqual(b.map((f) => f.id));
  });

  it("tags every finding with the sdlc module and a CWE", () => {
    const findings = checkReleaseIntegrity({ config: { artifacts_signed: false } });
    expect(findings.length).toBeGreaterThan(0);
    for (const f of findings) {
      expect(f.module).toBe("sdlc");
      expect(f.tags).toContain("sdlc");
      expect(f.cwe?.length ?? 0).toBeGreaterThan(0);
    }
  });
});
