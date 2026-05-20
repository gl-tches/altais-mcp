import { describe, expect, it } from "vitest";
import { assessSlsa, assessSlsaLevel } from "./slsa-level.js";

describe("assessSlsa — level determination", () => {
  it("returns level 0 for an ad-hoc build", () => {
    expect(assessSlsa({}).level).toBe(0);
  });

  it("returns level 1 for a scripted build with provenance", () => {
    expect(assessSlsa({ scripted_build: true, provenance_generated: true }).level).toBe(1);
  });

  it("returns level 2 for a hosted build with signed service provenance", () => {
    const r = assessSlsa({
      scripted_build: true,
      provenance_generated: true,
      build_service: true,
      provenance_service_generated: true,
      provenance_authenticated: true,
    });
    expect(r.level).toBe(2);
  });

  it("returns level 3 when isolated, hermetic, and parameterless are all met", () => {
    const r = assessSlsa({
      scripted_build: true,
      provenance_generated: true,
      build_service: true,
      provenance_service_generated: true,
      provenance_authenticated: true,
      isolated_build: true,
      hermetic: true,
      parameterless: true,
    });
    expect(r.level).toBe(3);
    expect(r.next_level).toBeNull();
  });

  it("does not jump to level 2 if a level 1 requirement is missing", () => {
    const r = assessSlsa({
      scripted_build: true,
      build_service: true,
      provenance_service_generated: true,
      provenance_authenticated: true,
    });
    expect(r.level).toBe(0);
  });
});

describe("assessSlsa — next-level guidance", () => {
  it("lists exactly the missing requirements to reach the next level", () => {
    const r = assessSlsa({ scripted_build: true, provenance_generated: true });
    expect(r.next_level).toBe(2);
    expect(r.missing_for_next.length).toBeGreaterThan(0);
    expect(r.missing_for_next.every((m) => m.startsWith("L2:"))).toBe(true);
  });
});

describe("assessSlsaLevel — finding", () => {
  it("emits exactly one finding stating the current level", () => {
    const findings = assessSlsaLevel({ config: {} });
    expect(findings).toHaveLength(1);
    expect(findings[0]?.rule).toBe("slsa-build-track-level-0");
  });

  it("produces deterministic finding IDs across runs", () => {
    const config = { scripted_build: true, provenance_generated: true };
    const a = assessSlsaLevel({ config });
    const b = assessSlsaLevel({ config });
    expect(a.map((f) => f.id)).toEqual(b.map((f) => f.id));
  });

  it("tags the finding with the sdlc module and a CWE", () => {
    const findings = assessSlsaLevel({ config: {} });
    for (const f of findings) {
      expect(f.module).toBe("sdlc");
      expect(f.tags).toContain("sdlc");
      expect(f.cwe?.length ?? 0).toBeGreaterThan(0);
    }
  });
});
