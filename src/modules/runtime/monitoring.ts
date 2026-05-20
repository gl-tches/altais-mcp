// Monitoring auditor (altais_audit_monitoring).
//
// Takes a declarative description of an application's monitoring and
// observability posture and flags the gaps that leave a security
// incident undetected: missing security-event logging, no alerting, no
// SIEM integration, no anomaly detection, a slow mean-time-to-detect,
// and no on-call routing. This is an auditor: it pushes Finding objects.

import type { Finding } from "../../core/types.js";
import { buildRuntimeFinding } from "./finding.js";

export interface MonitoringAuditInput {
  readonly logs_authentication: boolean;
  readonly logs_authorization_failures: boolean;
  readonly logs_input_validation_failures: boolean;
  readonly logs_admin_actions: boolean;
  readonly alerting_enabled: boolean;
  readonly alert_routing: boolean;
  readonly siem_integrated: boolean;
  readonly metrics_collected: boolean;
  readonly anomaly_detection: boolean;
  readonly dashboards: boolean;
  readonly on_call: boolean;
  readonly mean_time_to_detect_minutes: number;
  readonly filename?: string;
}

const REFS: readonly string[] = [
  "https://owasp.org/Top10/A09_2021-Security_Logging_and_Monitoring_Failures/",
  "https://owasp.org/www-project-proactive-controls/v3/en/c9-security-logging",
  "https://cwe.mitre.org/data/definitions/778.html",
];

// MTTD above this many minutes is considered slow enough to flag.
const SLOW_MTTD_MINUTES = 60;

interface SecurityLogCheck {
  readonly rule: string;
  readonly enabled: boolean;
  readonly eventLabel: string;
}

export interface MonitoringCoverageSummary {
  readonly security_event_logging_present: number;
  readonly security_event_logging_total: number;
  readonly alerting_enabled: boolean;
  readonly siem_integrated: boolean;
  readonly anomaly_detection: boolean;
  readonly mean_time_to_detect_minutes: number;
  readonly gaps: number;
}

export interface MonitoringAuditResult {
  readonly findings: readonly Finding[];
  readonly coverage: MonitoringCoverageSummary;
}

function mk(
  file: string | undefined,
  rule: string,
  severity: Finding["severity"],
  title: string,
  description: string,
  remediation: string,
  cwe: readonly string[],
  evidence: string,
): Finding {
  return buildRuntimeFinding(
    {
      rule,
      severity,
      title,
      description,
      remediation,
      cwe,
      references: REFS,
      evidence,
      tags: ["monitoring", "observability"],
    },
    file,
  );
}

export function auditMonitoring(input: MonitoringAuditInput): MonitoringAuditResult {
  const file = input.filename;
  const findings: Finding[] = [];

  // ── Security-event logging coverage (CWE-778) ────────────────────────────
  const logChecks: readonly SecurityLogCheck[] = [
    {
      rule: "monitoring-no-auth-logging",
      enabled: input.logs_authentication,
      eventLabel: "authentication events",
    },
    {
      rule: "monitoring-no-authz-failure-logging",
      enabled: input.logs_authorization_failures,
      eventLabel: "authorization failures",
    },
    {
      rule: "monitoring-no-input-validation-logging",
      enabled: input.logs_input_validation_failures,
      eventLabel: "input-validation failures",
    },
    {
      rule: "monitoring-no-admin-action-logging",
      enabled: input.logs_admin_actions,
      eventLabel: "administrative actions",
    },
  ];

  for (const check of logChecks) {
    if (!check.enabled) {
      findings.push(
        mk(
          file,
          check.rule,
          "high",
          `Security-event logging is missing for ${check.eventLabel}`,
          `The application does not record ${check.eventLabel}. Without this audit trail an attacker's activity is invisible: there is nothing to alert on, nothing to investigate during incident response, and no evidence for forensics.`,
          `Emit a structured, tamper-resistant log record for every one of these events, including actor, source IP, timestamp, target resource, and outcome. Forward the records to a central, append-only log store.`,
          ["CWE-778", "CWE-223"],
          `${check.eventLabel}: logging disabled`,
        ),
      );
    }
  }

  // ── Alerting ─────────────────────────────────────────────────────────────
  if (!input.alerting_enabled) {
    findings.push(
      mk(
        file,
        "monitoring-no-alerting",
        "high",
        "No alerting is configured on security events",
        "Logs are collected but no alerts fire on suspicious activity. Detection then depends on someone manually reading logs, so attacks proceed undetected for as long as no one happens to look.",
        "Define alert rules for high-signal events — repeated authentication failures, privilege escalation, authorization-failure spikes, and admin actions outside change windows — and wire them to a notification channel.",
        ["CWE-778"],
        "alerting_enabled: false",
      ),
    );
  }

  if (!input.alert_routing) {
    findings.push(
      mk(
        file,
        "monitoring-no-alert-routing",
        "medium",
        "Alerts have no routing to a responder",
        "Even if alerts fire, they are not routed to a person or team that can act on them. An alert that lands in an unwatched inbox is equivalent to no alert at all.",
        "Route security alerts to a defined destination (PagerDuty / Opsgenie / a monitored channel) with an escalation policy, and test the path end-to-end.",
        ["CWE-778"],
        "alert_routing: false",
      ),
    );
  }

  if (!input.on_call) {
    findings.push(
      mk(
        file,
        "monitoring-no-on-call",
        "medium",
        "No on-call rotation owns security alerts",
        "There is no on-call rotation responsible for responding to security alerts. Alerts raised outside business hours have no owner, extending attacker dwell time.",
        "Establish a 24/7 on-call rotation with a documented escalation policy and a runbook for the most common security alerts.",
        ["CWE-778"],
        "on_call: false",
      ),
    );
  }

  // ── SIEM integration ─────────────────────────────────────────────────────
  if (!input.siem_integrated) {
    findings.push(
      mk(
        file,
        "monitoring-no-siem",
        "medium",
        "Logs are not integrated with a SIEM",
        "Application logs are not forwarded to a SIEM. Cross-service correlation, long-term retention, and detection content are therefore unavailable, and an attacker who reaches the host can tamper with local logs.",
        "Forward security-relevant logs to a centralized SIEM with immutable, off-host retention, and enable correlation rules across application, infrastructure, and identity sources.",
        ["CWE-778", "CWE-779"],
        "siem_integrated: false",
      ),
    );
  }

  // ── Anomaly detection ────────────────────────────────────────────────────
  if (!input.anomaly_detection) {
    findings.push(
      mk(
        file,
        "monitoring-no-anomaly-detection",
        "medium",
        "No anomaly detection on application behavior",
        "Monitoring relies only on static thresholds, so novel attacks that stay under those thresholds — slow brute force, low-and-slow data exfiltration, unusual access patterns — go unnoticed.",
        "Add behavioral / anomaly detection on key signals (request rates, data egress volume, geographic access patterns, error rates) to catch attacks that static rules miss.",
        ["CWE-778"],
        "anomaly_detection: false",
      ),
    );
  }

  // ── Metrics ──────────────────────────────────────────────────────────────
  if (!input.metrics_collected) {
    findings.push(
      mk(
        file,
        "monitoring-no-metrics",
        "medium",
        "No application metrics are collected",
        "Without baseline metrics (request rates, latency, error rates, resource use) there is no way to spot the deviations that often accompany an attack, and no historical baseline to investigate against.",
        "Instrument the application to emit metrics to a time-series backend and retain enough history to establish behavioral baselines.",
        ["CWE-778"],
        "metrics_collected: false",
      ),
    );
  }

  // ── Dashboards ───────────────────────────────────────────────────────────
  if (!input.dashboards) {
    findings.push(
      mk(
        file,
        "monitoring-no-dashboards",
        "medium",
        "No security / operations dashboards exist",
        "There is no dashboard giving responders an at-a-glance view of authentication failures, error spikes, and traffic anomalies. Triage is slower and incidents are easier to miss.",
        "Build dashboards that surface security-relevant signals — auth-failure trends, authorization-denial rates, anomaly alerts — for both operations and security responders.",
        ["CWE-778"],
        "dashboards: false",
      ),
    );
  }

  // ── Mean time to detect ──────────────────────────────────────────────────
  if (input.mean_time_to_detect_minutes > SLOW_MTTD_MINUTES) {
    findings.push(
      mk(
        file,
        "monitoring-slow-mttd",
        "medium",
        `Mean time to detect is slow (${String(input.mean_time_to_detect_minutes)} minutes)`,
        `A mean time to detect of ${String(input.mean_time_to_detect_minutes)} minutes exceeds the ${String(SLOW_MTTD_MINUTES)}-minute target. The longer an intrusion goes undetected, the more data is exposed and the wider the blast radius before containment begins.`,
        "Reduce MTTD by adding real-time alerting on high-signal events, tuning alert thresholds to cut noise, and rehearsing detection with regular tabletop or purple-team exercises.",
        ["CWE-778"],
        `mean_time_to_detect_minutes: ${String(input.mean_time_to_detect_minutes)}`,
      ),
    );
  }

  const logsPresent = logChecks.filter((c) => c.enabled).length;

  const coverage: MonitoringCoverageSummary = {
    security_event_logging_present: logsPresent,
    security_event_logging_total: logChecks.length,
    alerting_enabled: input.alerting_enabled,
    siem_integrated: input.siem_integrated,
    anomaly_detection: input.anomaly_detection,
    mean_time_to_detect_minutes: input.mean_time_to_detect_minutes,
    gaps: findings.length,
  };

  return { findings, coverage };
}
