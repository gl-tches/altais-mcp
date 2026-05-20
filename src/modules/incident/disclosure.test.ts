import { describe, expect, it } from "vitest";
import { generateDisclosureProgram } from "./disclosure.js";

describe("generateDisclosureProgram", () => {
  it("titles a VDP when bounty is not set", () => {
    const r = generateDisclosureProgram({
      organization: "Acme",
      contact: "security@acme.test",
    });
    expect(r.markdown).toContain("# Acme Vulnerability Disclosure Policy");
  });

  it("titles a bug-bounty program when bounty is true", () => {
    const r = generateDisclosureProgram({
      organization: "Acme",
      contact: "security@acme.test",
      bounty: true,
    });
    expect(r.markdown).toContain("# Acme Bug Bounty Program");
  });

  it("includes the core policy sections", () => {
    const r = generateDisclosureProgram({
      organization: "Acme",
      contact: "security@acme.test",
    });
    for (const section of [
      "## Scope",
      "## How to report",
      "## Our commitment",
      "## Researcher expectations",
      "## Safe harbor",
      "## Rewards",
      "## References",
    ]) {
      expect(r.markdown).toContain(section);
    }
  });

  it("renders the supplied in-scope and out-of-scope items", () => {
    const r = generateDisclosureProgram({
      organization: "Acme",
      contact: "security@acme.test",
      scope_in: ["*.acme.test"],
      scope_out: ["status.acme.test"],
    });
    expect(r.markdown).toContain("- *.acme.test");
    expect(r.markdown).toContain("- status.acme.test");
  });

  it("includes a safe-harbor clause by default and omits it when disabled", () => {
    const withHarbor = generateDisclosureProgram({
      organization: "Acme",
      contact: "security@acme.test",
    });
    expect(withHarbor.markdown).toContain("will not pursue or support legal action");
    const without = generateDisclosureProgram({
      organization: "Acme",
      contact: "security@acme.test",
      safe_harbor: false,
    });
    expect(without.markdown).toContain("does not currently include a formal safe-harbor");
  });

  it("renders the acknowledgment SLA", () => {
    const r = generateDisclosureProgram({
      organization: "Acme",
      contact: "security@acme.test",
      response_sla_days: 3,
    });
    expect(r.markdown).toContain("within **3 business days**");
  });

  it("describes monetary rewards only for a bounty program", () => {
    const vdp = generateDisclosureProgram({
      organization: "Acme",
      contact: "security@acme.test",
    });
    expect(vdp.markdown).toContain("does not currently offer monetary");
    const bounty = generateDisclosureProgram({
      organization: "Acme",
      contact: "security@acme.test",
      bounty: true,
    });
    expect(bounty.markdown).toContain("may receive a monetary bounty");
  });

  it("is deterministic for the same input", () => {
    const cfg = { organization: "Acme", contact: "security@acme.test" } as const;
    expect(generateDisclosureProgram(cfg).markdown).toEqual(
      generateDisclosureProgram(cfg).markdown,
    );
  });
});
