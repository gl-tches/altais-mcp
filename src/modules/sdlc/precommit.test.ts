import { describe, expect, it } from "vitest";
import { generatePrecommit } from "./precommit.js";

describe("generatePrecommit — secret scanning", () => {
  it("wires gitleaks and detect-secrets when `secrets` is requested", () => {
    const art = generatePrecommit({ languages: [], checks: ["secrets"] });
    expect(art.content).toContain("gitleaks");
    expect(art.content).toContain("detect-secrets");
    expect(art.hooks).toContain("gitleaks");
  });

  it("emits a baseline note for detect-secrets", () => {
    const art = generatePrecommit({ languages: [], checks: ["secrets"] });
    expect(art.notes.some((n) => n.includes(".secrets.baseline"))).toBe(true);
  });
});

describe("generatePrecommit — language linters", () => {
  it("wires ruff for python lint", () => {
    const art = generatePrecommit({ languages: ["python"], checks: ["lint"] });
    expect(art.content).toContain("ruff");
    expect(art.hooks).toContain("ruff");
  });

  it("wires eslint for typescript lint", () => {
    const art = generatePrecommit({ languages: ["typescript"], checks: ["lint"] });
    expect(art.content).toContain("eslint");
  });

  it("notes an unmapped language", () => {
    const art = generatePrecommit({ languages: ["cobol"], checks: ["lint"] });
    expect(art.notes.some((n) => n.includes("cobol"))).toBe(true);
  });
});

describe("generatePrecommit — sast and other checks", () => {
  it("wires semgrep for sast and bandit for python", () => {
    const art = generatePrecommit({ languages: ["python"], checks: ["sast"] });
    expect(art.content).toContain("semgrep");
    expect(art.content).toContain("bandit");
  });

  it("wires large-file and private-key hooks", () => {
    const art = generatePrecommit({
      languages: [],
      checks: ["large-files", "private-key"],
    });
    expect(art.content).toContain("check-added-large-files");
    expect(art.content).toContain("detect-private-key");
  });

  it("wires a dependency-audit hook", () => {
    const art = generatePrecommit({ languages: [], checks: ["dependency-audit"] });
    expect(art.content).toContain("dependency-audit");
  });
});

describe("generatePrecommit — output shape", () => {
  it("always emits the pre-commit header and repos key", () => {
    const art = generatePrecommit({ languages: [], checks: ["secrets"] });
    expect(art.content).toContain("repos:");
    expect(art.filename).toBe(".pre-commit-config.yaml");
  });

  it("is deterministic across runs", () => {
    const a = generatePrecommit({ languages: ["python"], checks: ["secrets", "sast", "lint"] });
    const b = generatePrecommit({ languages: ["python"], checks: ["secrets", "sast", "lint"] });
    expect(a.content).toBe(b.content);
  });

  it("dedupes repeated checks", () => {
    const art = generatePrecommit({
      languages: ["python", "python"],
      checks: ["secrets", "secrets"],
    });
    expect(art.checks).toEqual(["secrets"]);
  });
});
