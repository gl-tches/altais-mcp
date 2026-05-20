import { describe, expect, it } from "vitest";
import { generateVex } from "./vex.js";

describe("generateVex", () => {
  it("emits an OpenVEX document", () => {
    const doc = generateVex({
      format: "openvex",
      statements: [
        {
          vulnerability: "CVE-2024-1234",
          products: [{ identifier: "pkg:npm/example@1.0.0" }],
          status: "not_affected",
          justification: "vulnerable_code_not_in_execute_path",
        },
      ],
    }) as { "@context": string; statements: { status: string; justification?: string }[] };
    expect(doc["@context"]).toMatch(/openvex/);
    expect(doc.statements[0]?.status).toBe("not_affected");
    expect(doc.statements[0]?.justification).toBe("vulnerable_code_not_in_execute_path");
  });

  it("emits a CycloneDX VEX with mapped state", () => {
    const doc = generateVex({
      format: "cyclonedx-vex",
      statements: [
        {
          vulnerability: "CVE-2024-1234",
          products: [{ identifier: "pkg:npm/example@1.0.0" }],
          status: "affected",
        },
      ],
    }) as { bomFormat: string; vulnerabilities: { analysis: { state: string } }[] };
    expect(doc.bomFormat).toBe("CycloneDX");
    expect(doc.vulnerabilities[0]?.analysis.state).toBe("exploitable");
  });

  it("preserves multiple products per statement", () => {
    const doc = generateVex({
      format: "openvex",
      statements: [
        {
          vulnerability: "CVE-x",
          products: [{ identifier: "a" }, { identifier: "b" }],
          status: "fixed",
        },
      ],
    }) as { statements: { products: unknown[] }[] };
    expect(doc.statements[0]?.products).toHaveLength(2);
  });
});
