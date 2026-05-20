// Canary-token / honeypot coverage auditor (altais_check_canary).
//
// Deception controls — canary tokens and honeypots — give an organization
// a high-signal, low-false-positive tripwire for an in-progress intrusion.
// This auditor assesses, from a declarative configuration, whether such
// controls are deployed, whether their triggers are actually routed to
// someone, and which sensitive areas are still uncovered.

import type { Finding } from "../../core/types.js";
import { buildIncidentFinding } from "./finding.js";

export interface CanaryConfig {
  readonly canary_tokens_deployed?: boolean;
  readonly honeypots_deployed?: boolean;
  readonly coverage_areas?: readonly string[];
  readonly alerting_enabled?: boolean;
  readonly alert_routing?: string;
  readonly monitored_assets?: readonly string[];
}

export interface CanaryAuditInput {
  readonly config: CanaryConfig;
  readonly filename?: string;
}

const REFS = [
  "https://owasp.org/www-community/controls/Intrusion_Detection",
  "https://csrc.nist.gov/pubs/sp/800/61/r3/final",
  "https://cwe.mitre.org/data/definitions/778.html",
];

// Sensitive areas where a deception control is most valuable. A gap here
// is reported as a coverage finding.
const RECOMMENDED_AREAS: readonly { readonly key: string; readonly label: string }[] = [
  { key: "database", label: "production databases" },
  { key: "credentials", label: "credential and secret stores" },
  { key: "filesystem", label: "sensitive file shares and document stores" },
  { key: "cloud", label: "cloud accounts and management consoles" },
  { key: "endpoints", label: "internal API endpoints and admin panels" },
];

function normalize(values: readonly string[] | undefined): Set<string> {
  const out = new Set<string>();
  for (const v of values ?? []) out.add(v.trim().toLowerCase());
  return out;
}

export function checkCanary(input: CanaryAuditInput): readonly Finding[] {
  const config = input.config;
  const findings: Finding[] = [];

  const coverage = normalize(config.coverage_areas);
  const monitored = config.monitored_assets ?? [];

  if (config.canary_tokens_deployed === false) {
    findings.push(
      mk(
        input.filename,
        "no-canary-tokens",
        "medium",
        "No canary tokens are deployed",
        "No canary tokens are in place. A canary token is a decoy credential, file, or URL that should never be touched in normal operation, so any access to it is a near-certain sign of an intruder. Without them, an attacker who has already bypassed perimeter controls can move freely undetected.",
        "Deploy canary tokens across sensitive areas — fake AWS keys, decoy documents, honeypot URLs, and database canary rows — and ensure every trigger raises an alert.",
        ["CWE-778"],
        "canary_tokens_deployed = false",
      ),
    );
  }

  if (config.honeypots_deployed === false) {
    findings.push(
      mk(
        input.filename,
        "no-honeypots",
        "medium",
        "No honeypots are deployed",
        "No honeypot services or hosts are running. A honeypot is a deliberately exposed decoy that has no legitimate users, so any interaction with it indicates reconnaissance or lateral movement. Without one, scanning and lateral-movement activity inside the network produces no high-signal alert.",
        "Deploy at least one honeypot in each network segment — a decoy service or host with no production role — and route all interaction with it to detection.",
        ["CWE-778"],
        "honeypots_deployed = false",
      ),
    );
  }

  const anyDeception = config.canary_tokens_deployed === true || config.honeypots_deployed === true;

  if (anyDeception && config.alerting_enabled === false) {
    findings.push(
      mk(
        input.filename,
        "no-canary-alerting",
        "medium",
        "Deception controls are deployed but do not alert on trigger",
        "Canary tokens or honeypots are in place but a trigger raises no alert. A deception control whose trip is not delivered to a responder is silent — the intrusion is recorded but never acted on, defeating the purpose of the control.",
        "Enable alerting on every canary and honeypot trigger and route it to a channel that is monitored around the clock.",
        ["CWE-778"],
        "alerting_enabled = false",
      ),
    );
  }

  if (
    anyDeception &&
    config.alerting_enabled !== false &&
    (config.alert_routing === undefined || config.alert_routing.trim() === "")
  ) {
    findings.push(
      mk(
        input.filename,
        "no-canary-alert-routing",
        "medium",
        "No alert-routing destination is configured for deception triggers",
        "Deception controls are deployed but no destination is configured for their alerts. An alert with nowhere to go is equivalent to no alert: a triggered canary will not reach a responder.",
        "Configure an explicit alert-routing destination — an on-call rotation, a monitored chat channel, or a SIEM incident queue — for canary and honeypot triggers.",
        ["CWE-778"],
        "alert_routing is not set",
      ),
    );
  }

  if (anyDeception) {
    for (const area of RECOMMENDED_AREAS) {
      if (!coverage.has(area.key)) {
        findings.push(
          mk(
            input.filename,
            "canary-coverage-gap",
            "medium",
            `No deception coverage for ${area.label}`,
            `Deception controls are deployed but ${area.label} are not listed among the covered areas. An attacker operating in an uncovered area triggers nothing, leaving a blind spot in intrusion detection.`,
            `Extend canary tokens or honeypots to cover ${area.label} so an intrusion there is detected as quickly as elsewhere.`,
            ["CWE-778"],
            `coverage_areas does not include "${area.key}"`,
          ),
        );
      }
    }

    if (monitored.length === 0) {
      findings.push(
        mk(
          input.filename,
          "no-monitored-assets",
          "medium",
          "No monitored assets are associated with the deception programme",
          "Deception controls are deployed but no monitored assets are recorded. Without an inventory of what the canaries and honeypots are protecting, coverage cannot be reasoned about and gaps go unnoticed.",
          "Maintain an explicit list of the assets each deception control is protecting, and review it whenever the asset inventory changes.",
          ["CWE-778"],
          "monitored_assets is empty",
        ),
      );
    }
  }

  return findings;
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
  return buildIncidentFinding(
    {
      rule,
      severity,
      title,
      description,
      remediation,
      cwe,
      references: REFS,
      evidence,
      tags: ["canary", "deception", "detection"],
    },
    file,
  );
}
