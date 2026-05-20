import { describe, expect, it } from "vitest";
import { draftAdvisory } from "./advisory.js";

describe("draftAdvisory", () => {
  it("includes all the standard GHSA sections", () => {
    const r = draftAdvisory({ title: "SQL injection in search", severity: "high" });
    for (const section of [
      "## Summary",
      "## Severity",
      "## Affected versions",
      "## Patched versions",
      "## Impact",
      "## Remediation",
      "## References",
      "## Timeline",
      "## Credits",
    ]) {
      expect(r.markdown).toContain(section);
    }
  });

  it("renders the title as the top-level heading", () => {
    const r = draftAdvisory({ title: "XSS in comments", severity: "moderate" });
    expect(r.markdown).toContain("# XSS in comments");
  });

  it("renders the severity rating", () => {
    const r = draftAdvisory({ title: "Auth bypass", severity: "critical" });
    expect(r.markdown).toContain("**Rating:** critical");
  });

  it("includes a CVE reference and an NVD link when a CVE is supplied", () => {
    const r = draftAdvisory({
      title: "Path traversal",
      severity: "high",
      cve: "CVE-2024-12345",
    });
    expect(r.markdown).toContain("CVE-2024-12345");
    expect(r.markdown).toContain("https://nvd.nist.gov/vuln/detail/CVE-2024-12345");
  });

  it("links each CWE to its MITRE definition", () => {
    const r = draftAdvisory({
      title: "Deserialization flaw",
      severity: "high",
      cwe: ["CWE-502"],
    });
    expect(r.markdown).toContain("https://cwe.mitre.org/data/definitions/502.html");
  });

  it("recommends the patched version in the remediation section", () => {
    const r = draftAdvisory({
      title: "Issue",
      severity: "low",
      patched_version: "3.2.1",
    });
    expect(r.markdown).toContain("Upgrade to 3.2.1 or later");
  });

  it("uses placeholders when optional prose is omitted", () => {
    const r = draftAdvisory({ title: "Issue", severity: "low" });
    expect(r.markdown).toContain("_Provide a concise");
  });

  it("is deterministic for the same input", () => {
    const cfg = { title: "Issue", severity: "high", cve: "CVE-2024-0001" } as const;
    expect(draftAdvisory(cfg).markdown).toEqual(draftAdvisory(cfg).markdown);
  });
});
