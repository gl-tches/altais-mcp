// SIEM integration guidance generator (altais_recommend_siem).
//
// Produces platform-aware SIEM onboarding guidance: which log sources to
// connect first, the priority detection use-cases to build, dashboards to
// stand up, and alerting advice. The output is a self-contained artifact —
// no Finding objects are pushed.

export type SiemPlatform =
  | "splunk"
  | "elastic"
  | "cloudwatch"
  | "sentinel"
  | "datadog"
  | "chronicle"
  | "other";

export interface SiemConfig {
  readonly platform: SiemPlatform;
  readonly log_sources?: readonly string[];
  readonly existing_detections?: readonly string[];
}

export interface SiemRecommendation {
  readonly platform: SiemPlatform;
  readonly platform_notes: string;
  readonly recommended_log_sources: readonly string[];
  readonly already_onboarded: readonly string[];
  readonly priority_detections: readonly string[];
  readonly recommended_dashboards: readonly string[];
  readonly alerting_guidance: readonly string[];
  readonly references: readonly string[];
}

const REFS: readonly string[] = [
  "https://csrc.nist.gov/pubs/sp/800/92/final",
  "https://attack.mitre.org/",
  "https://www.cisa.gov/resources-tools/services/logging-made-easy",
];

const PLATFORM_NOTES: Readonly<Record<SiemPlatform, string>> = {
  splunk:
    "Onboard data via the Universal Forwarder and platform-specific Splunk add-ons (TAs); build detections as saved searches and correlation searches, and consider Enterprise Security for an out-of-the-box content pack.",
  elastic:
    "Use Elastic Agent with integrations (Fleet) to ship and normalize data to the Elastic Common Schema; enable the prebuilt detection rules in the Security app and tune them to your environment.",
  cloudwatch:
    "Centralize logs into CloudWatch Logs and route security signals through CloudTrail, GuardDuty, and Security Hub; build detections with Logs Insights queries and metric-filter alarms.",
  sentinel:
    "Connect data via Microsoft Sentinel data connectors, normalize with the Advanced SIEM Information Model (ASIM), and enable the analytics-rule templates from the Content hub.",
  datadog:
    "Ship logs through the Datadog Agent and enable Cloud SIEM; use the out-of-the-box detection rules and the Log Pipelines to parse and enrich incoming events.",
  chronicle:
    "Ingest via Google SecOps (Chronicle) forwarders and feeds; data is normalized to the Unified Data Model (UDM), and curated detections plus YARA-L rules provide the detection layer.",
  other:
    "Forward logs over a standard protocol (syslog, the OpenTelemetry collector, or a vendor agent), normalize fields to a common schema, and build detections from the priority use-cases below.",
};

// The log sources every security-relevant SIEM deployment should onboard.
const CORE_LOG_SOURCES: readonly string[] = [
  "Authentication and identity-provider logs (sign-ins, MFA, federation)",
  "Cloud control-plane / audit logs (CloudTrail, Azure Activity, GCP Audit)",
  "Endpoint / EDR telemetry (process, file, and network events)",
  "Application and API access logs",
  "Network and firewall / VPC flow logs",
  "DNS query logs",
  "Web application firewall and load-balancer logs",
  "Operating-system and host logs (Linux auditd, Windows Security event log)",
  "Database audit logs",
  "CI/CD and source-control audit logs",
];

// Priority detection use-cases, ordered by signal-to-effort.
const PRIORITY_DETECTIONS: readonly string[] = [
  "Brute-force and password-spray authentication attempts",
  "Impossible-travel and anomalous sign-in location",
  "MFA disabled, reset, or repeatedly failed",
  "New or anomalous privileged-account creation or role assignment",
  "Disabling or tampering with logging, EDR, or security controls",
  "Known-malicious indicator matches against threat intelligence",
  "Data exfiltration — large or anomalous outbound transfers and DLP hits",
  "Cloud resource changes outside the change-management window",
  "Canary-token and honeypot triggers",
  "Lateral movement — anomalous internal authentication and remote-execution patterns",
];

const RECOMMENDED_DASHBOARDS: readonly string[] = [
  "Authentication overview — sign-in success/failure rates, MFA usage, and top failed accounts",
  "Privileged-activity dashboard — admin actions, role changes, and break-glass account use",
  "Cloud control-plane changes — resource creation, IAM edits, and security-group modifications",
  "Detection-coverage dashboard — alert volume by use-case, MITRE ATT&CK coverage, and unmonitored sources",
  "Incident-triage dashboard — open alerts by severity, age, and assignee",
];

const ALERTING_GUIDANCE: readonly string[] = [
  "Assign every detection a severity and route by severity — high-severity alerts page an on-call responder, lower-severity alerts queue for review.",
  "Tune detections against a baseline before enabling paging to keep false positives low and avoid alert fatigue.",
  "Suppress and group duplicate alerts so a single incident does not generate a storm of notifications.",
  "Track alert metrics — volume, false-positive rate, and mean time to triage — and review them regularly.",
  "Map each detection to a MITRE ATT&CK technique so coverage gaps are visible.",
  "Wire alerts into the incident-response process: an actionable alert should create a tracked incident, not just an email.",
];

function normalizeSet(values: readonly string[] | undefined): Set<string> {
  const out = new Set<string>();
  for (const v of values ?? []) {
    const t = v.trim().toLowerCase();
    if (t !== "") out.add(t);
  }
  return out;
}

export function recommendSiem(config: SiemConfig): SiemRecommendation {
  const existingSources = normalizeSet(config.log_sources);
  const recommended: string[] = [];
  const onboarded: string[] = [];
  for (const src of CORE_LOG_SOURCES) {
    // A source counts as onboarded if a configured log_sources entry is a
    // substring of it or vice versa (loose, case-insensitive match).
    const lower = src.toLowerCase();
    let matched = false;
    for (const have of existingSources) {
      if (lower.includes(have) || have.includes(lower)) {
        matched = true;
        break;
      }
    }
    if (matched) onboarded.push(src);
    else recommended.push(src);
  }

  const existingDetections = normalizeSet(config.existing_detections);
  const priority = PRIORITY_DETECTIONS.filter((d) => {
    const lower = d.toLowerCase();
    for (const have of existingDetections) {
      if (lower.includes(have) || have.includes(lower)) return false;
    }
    return true;
  });

  return {
    platform: config.platform,
    platform_notes: PLATFORM_NOTES[config.platform],
    recommended_log_sources: recommended,
    already_onboarded: onboarded,
    priority_detections: priority,
    recommended_dashboards: RECOMMENDED_DASHBOARDS,
    alerting_guidance: ALERTING_GUIDANCE,
    references: REFS,
  };
}
