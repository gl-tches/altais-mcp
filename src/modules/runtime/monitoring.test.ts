import { describe, expect, it } from "vitest";
import { auditMonitoring, type MonitoringAuditInput } from "./monitoring.js";

const FULLY_COVERED: MonitoringAuditInput = {
  logs_authentication: true,
  logs_authorization_failures: true,
  logs_input_validation_failures: true,
  logs_admin_actions: true,
  alerting_enabled: true,
  alert_routing: true,
  siem_integrated: true,
  metrics_collected: true,
  anomaly_detection: true,
  dashboards: true,
  on_call: true,
  mean_time_to_detect_minutes: 10,
};

const FULLY_UNCOVERED: MonitoringAuditInput = {
  logs_authentication: false,
  logs_authorization_failures: false,
  logs_input_validation_failures: false,
  logs_admin_actions: false,
  alerting_enabled: false,
  alert_routing: false,
  siem_integrated: false,
  metrics_collected: false,
  anomaly_detection: false,
  dashboards: false,
  on_call: false,
  mean_time_to_detect_minutes: 240,
};

describe("auditMonitoring — clean posture", () => {
  it("reports no findings when every control is in place", () => {
    const r = auditMonitoring(FULLY_COVERED);
    expect(r.findings).toHaveLength(0);
    expect(r.coverage.gaps).toBe(0);
    expect(r.coverage.security_event_logging_present).toBe(4);
  });
});

describe("auditMonitoring — missing controls", () => {
  it("flags every gap when no control is in place", () => {
    const r = auditMonitoring(FULLY_UNCOVERED);
    expect(r.findings.length).toBeGreaterThan(8);
    expect(r.coverage.gaps).toBe(r.findings.length);
    expect(r.coverage.security_event_logging_present).toBe(0);
  });

  it("flags missing security-event logging as high severity with CWE-778", () => {
    const r = auditMonitoring({ ...FULLY_COVERED, logs_authentication: false });
    const f = r.findings.find((x) => x.rule === "monitoring-no-auth-logging");
    expect(f).toBeDefined();
    expect(f?.severity).toBe("high");
    expect(f?.cwe).toContain("CWE-778");
  });

  it("flags missing alerting as high severity", () => {
    const r = auditMonitoring({ ...FULLY_COVERED, alerting_enabled: false });
    const f = r.findings.find((x) => x.rule === "monitoring-no-alerting");
    expect(f?.severity).toBe("high");
  });

  it("flags missing dashboards as medium severity", () => {
    const r = auditMonitoring({ ...FULLY_COVERED, dashboards: false });
    const f = r.findings.find((x) => x.rule === "monitoring-no-dashboards");
    expect(f?.severity).toBe("medium");
  });

  it("flags a slow mean time to detect as medium severity", () => {
    const r = auditMonitoring({ ...FULLY_COVERED, mean_time_to_detect_minutes: 120 });
    const f = r.findings.find((x) => x.rule === "monitoring-slow-mttd");
    expect(f).toBeDefined();
    expect(f?.severity).toBe("medium");
  });

  it("does not flag MTTD at or below the threshold", () => {
    const r = auditMonitoring({ ...FULLY_COVERED, mean_time_to_detect_minutes: 60 });
    expect(r.findings.find((x) => x.rule === "monitoring-slow-mttd")).toBeUndefined();
  });

  it("flags missing SIEM integration and anomaly detection", () => {
    const r = auditMonitoring({
      ...FULLY_COVERED,
      siem_integrated: false,
      anomaly_detection: false,
    });
    expect(r.findings.find((x) => x.rule === "monitoring-no-siem")).toBeDefined();
    expect(r.findings.find((x) => x.rule === "monitoring-no-anomaly-detection")).toBeDefined();
  });

  it("flags missing on-call routing", () => {
    const r = auditMonitoring({ ...FULLY_COVERED, on_call: false });
    expect(r.findings.find((x) => x.rule === "monitoring-no-on-call")).toBeDefined();
  });
});

describe("auditMonitoring — finding shape", () => {
  it("produces well-formed runtime findings", () => {
    const r = auditMonitoring(FULLY_UNCOVERED);
    for (const f of r.findings) {
      expect(f.module).toBe("runtime");
      expect(f.cwe?.length).toBeGreaterThan(0);
      expect(f.tags).toContain("runtime");
      expect(f.references.length).toBeGreaterThan(0);
      expect(f.remediation.length).toBeGreaterThan(0);
      expect(f.status).toBe("open");
    }
  });

  it("uses a finding location when a filename is given", () => {
    const r = auditMonitoring({ ...FULLY_UNCOVERED, filename: "monitoring.toml" });
    expect(r.findings[0]?.location?.file).toBe("monitoring.toml");
  });

  it("is deterministic — same input produces identical finding IDs", () => {
    const a = auditMonitoring(FULLY_UNCOVERED);
    const b = auditMonitoring(FULLY_UNCOVERED);
    expect(a.findings.map((f) => f.id)).toEqual(b.findings.map((f) => f.id));
  });
});
