import { describe, expect, it } from "vitest";
import { recommendSiem } from "./siem.js";

describe("recommendSiem", () => {
  it("returns platform-specific notes for each platform", () => {
    expect(recommendSiem({ platform: "splunk" }).platform_notes).toMatch(/Splunk/i);
    expect(recommendSiem({ platform: "elastic" }).platform_notes).toMatch(/Elastic/i);
    expect(recommendSiem({ platform: "sentinel" }).platform_notes).toMatch(/Sentinel/i);
  });

  it("recommends core log sources when none are onboarded", () => {
    const r = recommendSiem({ platform: "datadog" });
    expect(r.recommended_log_sources.length).toBeGreaterThan(0);
    expect(r.already_onboarded).toHaveLength(0);
  });

  it("excludes log sources that are already onboarded", () => {
    const r = recommendSiem({
      platform: "elastic",
      log_sources: ["Authentication and identity-provider logs (sign-ins, MFA, federation)"],
    });
    expect(r.already_onboarded.length).toBeGreaterThan(0);
    expect(r.recommended_log_sources.some((s) => s.toLowerCase().includes("authentication"))).toBe(
      false,
    );
  });

  it("excludes detections that already exist", () => {
    const r = recommendSiem({
      platform: "cloudwatch",
      existing_detections: ["Brute-force and password-spray authentication attempts"],
    });
    expect(r.priority_detections.some((d) => d.toLowerCase().includes("brute-force"))).toBe(false);
  });

  it("always returns priority detections, dashboards, and alerting guidance", () => {
    const r = recommendSiem({ platform: "chronicle" });
    expect(r.priority_detections.length).toBeGreaterThan(0);
    expect(r.recommended_dashboards.length).toBeGreaterThan(0);
    expect(r.alerting_guidance.length).toBeGreaterThan(0);
  });

  it("includes canary-trigger detection in the priority list", () => {
    const r = recommendSiem({ platform: "other" });
    expect(r.priority_detections.some((d) => d.toLowerCase().includes("canary"))).toBe(true);
  });

  it("is deterministic for the same input", () => {
    const a = recommendSiem({ platform: "splunk", log_sources: ["dns"] });
    const b = recommendSiem({ platform: "splunk", log_sources: ["dns"] });
    expect(JSON.stringify(a)).toEqual(JSON.stringify(b));
  });
});
