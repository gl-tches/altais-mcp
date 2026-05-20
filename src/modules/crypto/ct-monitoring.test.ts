import { describe, expect, it } from "vitest";
import { auditCtLogs } from "./ct-monitoring.js";

describe("auditCtLogs — source", () => {
  it("flags the deprecated Expect-CT header", () => {
    const f = auditCtLogs({ source: 'res.setHeader("Expect-CT", "max-age=86400, enforce");' });
    expect(f.some((x) => x.rule === "ct-expect-ct-header-deprecated")).toBe(true);
  });
});

describe("auditCtLogs — config", () => {
  it("flags missing CT monitoring", () => {
    const f = auditCtLogs({ config: { monitoring_enabled: false } });
    expect(f.some((x) => x.rule === "ct-no-monitoring")).toBe(true);
  });

  it("flags a domain coverage gap", () => {
    const f = auditCtLogs({
      config: {
        monitoring_enabled: true,
        owned_domains: ["a.com", "b.com"],
        monitored_domains: ["a.com"],
        alerting_enabled: true,
      },
    });
    expect(f.some((x) => x.rule === "ct-domain-coverage-gap")).toBe(true);
  });

  it("flags monitoring without alerting", () => {
    const f = auditCtLogs({
      config: { monitoring_enabled: true, alerting_enabled: false },
    });
    expect(f.some((x) => x.rule === "ct-no-alerting")).toBe(true);
  });

  it("flags a server that does not deliver SCTs", () => {
    const f = auditCtLogs({
      config: { monitoring_enabled: true, alerting_enabled: true, requires_sct: false },
    });
    expect(f.some((x) => x.rule === "ct-sct-not-required")).toBe(true);
  });

  it("accepts a fully covered, alerting CT setup", () => {
    const f = auditCtLogs({
      config: {
        monitoring_enabled: true,
        owned_domains: ["a.com"],
        monitored_domains: ["a.com"],
        alerting_enabled: true,
        requires_sct: true,
      },
    });
    expect(f).toHaveLength(0);
  });
});
