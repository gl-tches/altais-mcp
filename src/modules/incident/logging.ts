// Audit-logging auditor (altais_audit_logging).
//
// Assesses audit-trail completeness and log-injection prevention from an
// optional source snippet and/or a declarative logging-configuration
// object. Source patterns catch the two highest-signal code smells —
// unsanitized user input written into a log call, and sensitive values
// written to a log call. The config object covers the surrounding
// programme: which security events are recorded, whether logs are
// centralized, tamper-protected, and retained long enough.

import type { Finding } from "../../core/types.js";
import { buildIncidentFinding, scanWithPatterns, type SourcePattern } from "./finding.js";

export interface LoggingConfig {
  readonly has_audit_log?: boolean;
  readonly logs_authentication?: boolean;
  readonly logs_authorization?: boolean;
  readonly logs_admin_actions?: boolean;
  readonly log_injection_protection?: boolean;
  readonly centralized?: boolean;
  readonly tamper_protection?: boolean;
  readonly retention_days?: number;
  readonly logs_sensitive_data?: boolean;
  readonly pii_redaction?: boolean;
  readonly includes_timestamp?: boolean;
  readonly includes_actor?: boolean;
}

export interface LoggingAuditInput {
  readonly source?: string;
  readonly config?: LoggingConfig;
  readonly filename?: string;
}

const REFS = [
  "https://owasp.org/www-project-application-security-verification-standard/",
  "https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html",
  "https://cwe.mitre.org/data/definitions/778.html",
  "https://cwe.mitre.org/data/definitions/117.html",
  "https://cwe.mitre.org/data/definitions/532.html",
];

// Minimum retention for a security audit trail. Many frameworks (PCI-DSS,
// SOC 2) expect a year of retained logs; flag anything well short of that.
const MIN_RETENTION_DAYS = 90;

const SOURCE_PATTERNS: readonly SourcePattern[] = [
  {
    rule: "log-injection-unsanitized-input",
    // A logging call whose argument splices request-derived input via
    // string concatenation or a template literal.
    regex:
      /\b(?:log(?:ger)?|console)\s*\.\s*(?:info|warn|error|debug|log)\s*\([^)]*(?:req\.(?:body|query|params|headers)|request\.|user[A-Za-z]*Input|params\.|getParameter)[^)]*\)/i,
    severity: "high",
    title: "User-controlled input written to a log without neutralization",
    description:
      "Request-derived input is concatenated directly into a log message. An attacker can embed newline or carriage-return characters to forge additional log entries (log injection / log forging), or inject terminal escape sequences and markup that are interpreted when the log is later viewed.",
    remediation:
      "Neutralize CR/LF and control characters before logging untrusted input, prefer structured (key/value or JSON) logging so user data is a discrete field, and never interpolate raw input into the log message string.",
    cwe: ["CWE-117"],
    tags: ["logging", "log-injection"],
  },
  {
    rule: "sensitive-data-in-log",
    // A logging call whose argument names a credential/PII-looking value.
    regex:
      /\b(?:log(?:ger)?|console)\s*\.\s*(?:info|warn|error|debug|log)\s*\([^)]*\b(?:password|passwd|secret|api[_-]?key|token|ssn|credit[_-]?card|card[_-]?number|authorization)\b[^)]*\)/i,
    severity: "high",
    title: "Sensitive value written to an application log",
    description:
      "A credential, token, or other sensitive value is passed to a log call. Logs are frequently shipped to centralized stores, indexed, and read by operators, so logging secrets or PII silently widens their exposure and creates a compliance violation.",
    remediation:
      "Remove the sensitive field from the log call, or redact it (mask all but the last few characters). Maintain a deny-list of sensitive keys in the logging layer so they are stripped automatically.",
    cwe: ["CWE-532"],
    tags: ["logging", "sensitive-data"],
  },
];

interface ConfigCheck {
  readonly rule: string;
  readonly severity: Finding["severity"];
  readonly title: string;
  readonly description: string;
  readonly remediation: string;
  readonly cwe: readonly string[];
  /** Returns true when the condition is a problem worth a finding. */
  readonly triggered: (c: LoggingConfig) => boolean;
  readonly evidence: (c: LoggingConfig) => string;
}

const CONFIG_CHECKS: readonly ConfigCheck[] = [
  {
    rule: "no-audit-log",
    severity: "high",
    title: "No audit log is maintained",
    description:
      "The configuration declares that no audit log exists. Without a tamper-evident record of security-relevant events, an intrusion cannot be detected, scoped, or investigated, and there is no evidence for incident response or compliance.",
    remediation:
      "Stand up an audit log that records authentication, authorization, and administrative events with a timestamp and the acting principal, separate from general application logs.",
    cwe: ["CWE-778"],
    triggered: (c) => c.has_audit_log === false,
    evidence: () => "has_audit_log = false",
  },
  {
    rule: "missing-authentication-logging",
    severity: "high",
    title: "Authentication events are not logged",
    description:
      "Successful and failed authentication attempts are not recorded. Credential-stuffing, brute-force, and account-takeover activity is invisible without an authentication audit trail, and post-incident investigation cannot reconstruct who logged in.",
    remediation:
      "Log every authentication outcome (success and failure) with the principal, source address, and timestamp. Ensure failures are logged at a level that feeds detection.",
    cwe: ["CWE-778"],
    triggered: (c) => c.logs_authentication === false,
    evidence: () => "logs_authentication = false",
  },
  {
    rule: "missing-authorization-logging",
    severity: "high",
    title: "Authorization decisions are not logged",
    description:
      "Access-control decisions, in particular denied or privilege-escalation attempts, are not recorded. This omission hides probing and lateral-movement activity and removes the evidence needed to confirm an authorization breach.",
    remediation:
      "Log authorization failures and grants of sensitive permissions, including the principal, the resource, and the decision.",
    cwe: ["CWE-778"],
    triggered: (c) => c.logs_authorization === false,
    evidence: () => "logs_authorization = false",
  },
  {
    rule: "missing-admin-action-logging",
    severity: "high",
    title: "Administrative actions are not logged",
    description:
      "Privileged and administrative operations are not captured in the audit trail. Admin actions are the highest-impact events; without logging them, an abused admin account or a malicious insider leaves no record.",
    remediation:
      "Log all administrative and configuration-changing actions with the actor, the change made, and a timestamp.",
    cwe: ["CWE-778"],
    triggered: (c) => c.logs_admin_actions === false,
    evidence: () => "logs_admin_actions = false",
  },
  {
    rule: "no-log-injection-protection",
    severity: "high",
    title: "No log-injection neutralization is in place",
    description:
      "The logging pipeline does not neutralize untrusted input. An attacker can inject CR/LF characters to forge log entries, or escape sequences and markup that are interpreted when logs are viewed, undermining the integrity of the audit trail itself.",
    remediation:
      "Sanitize CR/LF and control characters out of logged values and prefer structured logging so untrusted data is always a discrete, escaped field rather than part of the message string.",
    cwe: ["CWE-117"],
    triggered: (c) => c.log_injection_protection === false,
    evidence: () => "log_injection_protection = false",
  },
  {
    rule: "logs-not-centralized",
    severity: "medium",
    title: "Logs are not shipped to a centralized store",
    description:
      "Logs remain on the host that produced them. An attacker who compromises that host can delete or alter the only copy, and responders cannot correlate activity across services during an investigation.",
    remediation:
      "Forward logs in near-real-time to a centralized, append-only store (a SIEM or log aggregation service) so they survive host compromise and can be correlated.",
    cwe: ["CWE-778"],
    triggered: (c) => c.centralized === false,
    evidence: () => "centralized = false",
  },
  {
    rule: "no-tamper-protection",
    severity: "medium",
    title: "Audit logs have no tamper protection",
    description:
      "Logs can be modified or deleted after the fact. An attacker who reaches the logging system can erase evidence of the intrusion, and the audit trail cannot be trusted as forensic evidence.",
    remediation:
      "Make the audit log append-only and integrity-protected — write to a WORM or append-only store, hash-chain entries, or forward to a system the application cannot edit.",
    cwe: ["CWE-778"],
    triggered: (c) => c.tamper_protection === false,
    evidence: () => "tamper_protection = false",
  },
  {
    rule: "logs-sensitive-data-without-redaction",
    severity: "high",
    title: "Sensitive data or PII is logged without redaction",
    description:
      "The configuration declares that sensitive data or PII is written to logs but no redaction is applied. Logs are widely replicated and indexed, so unredacted secrets and personal data become a standing exposure and a compliance violation.",
    remediation:
      "Enable PII/secret redaction in the logging layer: maintain a deny-list of sensitive field names that are masked or dropped before any log line is emitted.",
    cwe: ["CWE-532"],
    triggered: (c) =>
      (c.logs_sensitive_data === true || c.logs_sensitive_data === undefined) &&
      c.pii_redaction === false,
    evidence: (c) =>
      `logs_sensitive_data = ${String(c.logs_sensitive_data ?? "unspecified")}, pii_redaction = false`,
  },
  {
    rule: "retention-too-short",
    severity: "medium",
    title: "Audit-log retention is too short",
    description:
      "Logs are retained for fewer days than is needed to investigate an incident. Many breaches are discovered months after the initial compromise; a short retention window means the relevant evidence has already been deleted.",
    remediation: `Retain security audit logs for at least ${String(MIN_RETENTION_DAYS)} days — most compliance regimes expect closer to a year — in a cost-tiered archive.`,
    cwe: ["CWE-778"],
    triggered: (c) => typeof c.retention_days === "number" && c.retention_days < MIN_RETENTION_DAYS,
    evidence: (c) => `retention_days = ${String(c.retention_days)}`,
  },
  {
    rule: "missing-log-timestamp",
    severity: "medium",
    title: "Audit-log entries do not include a timestamp",
    description:
      "Log entries omit a timestamp. Without an accurate, ideally synchronized, time on every entry, events cannot be ordered or correlated and the audit trail is of little forensic use.",
    remediation:
      "Include a high-precision, timezone-qualified timestamp on every log entry, sourced from an NTP-synchronized clock.",
    cwe: ["CWE-778"],
    triggered: (c) => c.includes_timestamp === false,
    evidence: () => "includes_timestamp = false",
  },
  {
    rule: "missing-log-actor",
    severity: "medium",
    title: "Audit-log entries do not identify the acting principal",
    description:
      "Log entries do not record who performed the action. An audit trail that cannot attribute an event to a principal cannot support accountability or an incident investigation.",
    remediation:
      "Record the acting principal (user or service identity) and source address on every security-relevant log entry.",
    cwe: ["CWE-778"],
    triggered: (c) => c.includes_actor === false,
    evidence: () => "includes_actor = false",
  },
];

export function auditLogging(input: LoggingAuditInput): readonly Finding[] {
  const findings: Finding[] = [];

  if (input.source !== undefined && input.source.trim() !== "") {
    findings.push(...scanWithPatterns(input.source, SOURCE_PATTERNS, REFS, input.filename));
  }

  const config = input.config;
  if (config !== undefined) {
    for (const check of CONFIG_CHECKS) {
      if (check.triggered(config)) {
        findings.push(
          buildIncidentFinding(
            {
              rule: check.rule,
              severity: check.severity,
              title: check.title,
              description: check.description,
              remediation: check.remediation,
              cwe: check.cwe,
              references: REFS,
              evidence: check.evidence(config),
              tags: ["logging", "audit-trail"],
            },
            input.filename,
          ),
        );
      }
    }
  }

  return findings;
}
