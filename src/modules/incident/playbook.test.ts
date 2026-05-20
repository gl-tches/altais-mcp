import { describe, expect, it } from "vitest";
import { generatePlaybook } from "./playbook.js";

describe("generatePlaybook", () => {
  it("covers all six NIST SP 800-61 lifecycle phases", () => {
    const pb = generatePlaybook({ scenario: "ransomware" });
    const phaseNames = pb.phases.map((p) => p.name);
    expect(phaseNames).toEqual([
      "Preparation",
      "Detection & Analysis",
      "Containment",
      "Eradication",
      "Recovery",
      "Post-Incident Activity",
    ]);
  });

  it("references NIST SP 800-61 as the framework", () => {
    const pb = generatePlaybook({ scenario: "data-breach" });
    expect(pb.framework).toContain("800-61");
    expect(pb.references.some((r) => r.includes("csrc.nist.gov"))).toBe(true);
  });

  it("includes the standard incident-response roles", () => {
    const pb = generatePlaybook({ scenario: "phishing" });
    const roleNames = pb.roles.map((r) => r.role);
    expect(roleNames).toContain("Incident Commander");
    expect(roleNames).toContain("Communications Lead");
  });

  it("adds insider-specific roles for the insider-threat scenario", () => {
    const pb = generatePlaybook({ scenario: "insider-threat" });
    const roleNames = pb.roles.map((r) => r.role);
    expect(roleNames).toContain("HR Partner");
    expect(roleNames).toContain("Legal Counsel");
  });

  it("produces scenario-specific containment steps", () => {
    const ransomware = generatePlaybook({ scenario: "ransomware" });
    const ddos = generatePlaybook({ scenario: "ddos" });
    const ransomwareContainment = ransomware.phases.find((p) => p.name === "Containment");
    const ddosContainment = ddos.phases.find((p) => p.name === "Containment");
    expect(ransomwareContainment?.steps).not.toEqual(ddosContainment?.steps);
  });

  it("includes optional context when supplied", () => {
    const pb = generatePlaybook({
      scenario: "malware",
      context: "Affects the payments cluster.",
    });
    expect(pb.context).toBe("Affects the payments cluster.");
  });

  it("omits context when not supplied", () => {
    const pb = generatePlaybook({ scenario: "malware" });
    expect(pb.context).toBeUndefined();
  });

  it("is deterministic for the same input", () => {
    const a = generatePlaybook({ scenario: "credential-leak", context: "ci pipeline" });
    const b = generatePlaybook({ scenario: "credential-leak", context: "ci pipeline" });
    expect(JSON.stringify(a)).toEqual(JSON.stringify(b));
  });

  it("provides communication guidance for every scenario", () => {
    const scenarios = [
      "ransomware",
      "data-breach",
      "account-takeover",
      "ddos",
      "supply-chain-compromise",
      "insider-threat",
      "credential-leak",
      "malware",
      "phishing",
    ] as const;
    for (const scenario of scenarios) {
      const pb = generatePlaybook({ scenario });
      expect(pb.communication.length).toBeGreaterThan(0);
    }
  });
});
