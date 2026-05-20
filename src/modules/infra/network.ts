// Network segmentation and firewall auditor (altais_audit_network).
//
// Reviews a declarative description of a network: its firewall rules,
// its zones / segments, and whether egress is filtered. It looks for the
// patterns that flatten a network into a single blast radius — any-source
// ingress allows (especially to admin ports), unconstrained `allow any
// any` rules, an absence of segmentation, and unfiltered egress.

import type { Finding, Severity } from "../../core/types.js";
import { buildInfraFinding } from "./finding.js";

export interface FirewallRule {
  readonly direction: "ingress" | "egress";
  readonly source: string;
  readonly destination?: string;
  readonly port?: number | string;
  readonly protocol?: string;
  readonly action: "allow" | "deny";
}

export interface NetworkAuditConfig {
  readonly firewall_rules?: readonly FirewallRule[];
  readonly zones?: readonly string[];
  readonly segments?: readonly string[];
  readonly egress_filtering?: boolean;
}

export interface NetworkAuditInput {
  readonly config: NetworkAuditConfig;
  readonly filename?: string;
}

const REFS = [
  "https://cwe.mitre.org/data/definitions/284.html",
  "https://cwe.mitre.org/data/definitions/668.html",
  "https://cwe.mitre.org/data/definitions/1008.html",
  "https://owasp.org/www-project-top-ten/",
];

// CIDRs that match every host on the internet.
const ANY_SOURCE = new Set(["0.0.0.0/0", "::/0", "0.0.0.0", "*", "any", "all", "internet"]);

// Sensitive service ports that should never be reachable from anywhere.
const ADMIN_PORTS: ReadonlyMap<number, string> = new Map([
  [22, "SSH"],
  [23, "Telnet"],
  [135, "Windows RPC"],
  [445, "SMB"],
  [1433, "Microsoft SQL Server"],
  [1521, "Oracle Database"],
  [3306, "MySQL / MariaDB"],
  [3389, "RDP"],
  [5432, "PostgreSQL"],
  [5601, "Kibana"],
  [5900, "VNC"],
  [5984, "CouchDB"],
  [6379, "Redis"],
  [8086, "InfluxDB"],
  [9042, "Cassandra"],
  [9200, "Elasticsearch"],
  [11211, "Memcached"],
  [27017, "MongoDB"],
]);

function isAnySource(value: string): boolean {
  return ANY_SOURCE.has(value.trim().toLowerCase());
}

/** Normalize a port field to a numeric port, or undefined if not a single port. */
function numericPort(port: number | string | undefined): number | undefined {
  if (port === undefined) return undefined;
  if (typeof port === "number") return Number.isInteger(port) ? port : undefined;
  const trimmed = port.trim();
  if (!/^[0-9]+$/.test(trimmed)) return undefined;
  const n = Number.parseInt(trimmed, 10);
  return Number.isInteger(n) ? n : undefined;
}

/** True when the rule's port field covers every port (`*`, `any`, `0`, `all`). */
function isAnyPort(port: number | string | undefined): boolean {
  if (port === undefined) return true;
  if (typeof port === "number") return port === 0;
  const t = port.trim().toLowerCase();
  return t === "" || t === "*" || t === "any" || t === "all" || t === "0";
}

function ruleEvidence(r: FirewallRule, index: number): string {
  const parts = [`#${String(index + 1)}`, r.direction, `${r.action} from ${r.source}`];
  if (r.destination !== undefined) parts.push(`to ${r.destination}`);
  if (r.port !== undefined) parts.push(`port ${String(r.port)}`);
  if (r.protocol !== undefined) parts.push(`proto ${r.protocol}`);
  return parts.join(" ").slice(0, 200);
}

export function auditNetwork(input: NetworkAuditInput): readonly Finding[] {
  const file = input.filename;
  const cfg = input.config;
  const findings: Finding[] = [];
  const rules = cfg.firewall_rules ?? [];

  let sawDeny = false;

  for (let i = 0; i < rules.length; i++) {
    const rule = rules[i];
    if (rule === undefined) continue;
    if (rule.action === "deny") sawDeny = true;
    if (rule.action !== "allow") continue;

    const anySource = isAnySource(rule.source);
    const anyPort = isAnyPort(rule.port);
    const port = numericPort(rule.port);
    const evidence = ruleEvidence(rule, i);

    if (rule.direction === "ingress" && anySource) {
      const adminService = port !== undefined ? ADMIN_PORTS.get(port) : undefined;
      if (adminService !== undefined) {
        findings.push(
          mk(
            file,
            "network-admin-port-exposed",
            "high",
            `Firewall rule exposes ${adminService} (port ${String(port)}) to any source`,
            `An ingress \`allow\` rule with source \`${rule.source}\` makes the ${adminService} service on port ${String(port)} reachable from the entire internet. Administrative and database ports are continuously scanned and brute-forced; exposing one removes the network as a control layer.`,
            `Restrict the source of this rule to a bastion host, VPN range, or named admin CIDR. ${adminService} should never accept connections from \`0.0.0.0/0\`; place it behind a private subnet and reach it through a jump host or identity-aware proxy.`,
            ["CWE-668", "CWE-284"],
            evidence,
          ),
        );
      } else if (anyPort) {
        findings.push(
          mk(
            file,
            "network-any-any-ingress",
            "high",
            "Firewall rule allows ingress from any source on any port",
            `An ingress \`allow\` rule with source \`${rule.source}\` and no port restriction is an \`allow any any\` rule: every port on the protected hosts is reachable from the entire internet, so the firewall provides no meaningful boundary.`,
            "Replace the broad rule with port-specific rules scoped to the minimum required source ranges. Default to deny and allow only the exact services that must be public.",
            ["CWE-284", "CWE-668"],
            evidence,
          ),
        );
      } else {
        findings.push(
          mk(
            file,
            "network-any-source-ingress",
            "medium",
            `Firewall rule allows ingress from any source on port ${String(rule.port ?? "(unspecified)")}`,
            `An ingress \`allow\` rule with source \`${rule.source}\` exposes the targeted port to every host on the internet. Even for an intentionally public service, an unbounded source range removes the option of geofencing or allow-listing and broadens the attack surface.`,
            "Confirm the port genuinely needs to be public. If so, terminate it behind a WAF or load balancer; otherwise restrict the source to known client CIDRs.",
            ["CWE-284"],
            evidence,
          ),
        );
      }
    } else if (rule.direction === "egress" && anySource && anyPort) {
      const dest = rule.destination;
      if (dest === undefined || isAnySource(dest)) {
        findings.push(
          mk(
            file,
            "network-unrestricted-egress-rule",
            "medium",
            "Firewall rule allows unrestricted egress to any destination",
            "An egress `allow` rule to any destination on any port lets a compromised host exfiltrate data and reach attacker-controlled command-and-control infrastructure without restriction.",
            "Constrain egress to the specific destinations and ports the workload requires (package registries, APIs, telemetry endpoints). Route the rest through an egress proxy that enforces an allow-list.",
            ["CWE-1008"],
            evidence,
          ),
        );
      }
    }
  }

  // ── Segmentation ────────────────────────────────────────────────────────
  const zoneCount = (cfg.zones?.length ?? 0) + (cfg.segments?.length ?? 0);
  if ((cfg.zones !== undefined || cfg.segments !== undefined) && zoneCount <= 1) {
    findings.push(
      mk(
        file,
        "network-flat-topology",
        "medium",
        "Network has no segmentation (flat topology)",
        "The configuration declares zero or one network zone, so all hosts share a single broadcast and trust domain. A flat network gives an attacker who compromises any one host unrestricted lateral movement to every other host.",
        "Segment the network into tiers (for example public / application / data) or workload-scoped microsegments, and place a default-deny firewall policy between them so each tier only reaches what it must.",
        ["CWE-1008", "CWE-668"],
        `zones=${String(cfg.zones?.length ?? 0)} segments=${String(cfg.segments?.length ?? 0)}`,
      ),
    );
  }

  // ── Egress filtering ────────────────────────────────────────────────────
  if (cfg.egress_filtering === false) {
    findings.push(
      mk(
        file,
        "network-no-egress-filtering",
        "medium",
        "Egress filtering is disabled",
        "With egress filtering off, hosts may open outbound connections to any destination. This is the channel malware uses for command-and-control callbacks and for exfiltrating data once a host is compromised.",
        "Enable egress filtering and define an outbound allow-list covering only the destinations the workloads require. Default-deny all other outbound traffic and log denied attempts.",
        ["CWE-1008"],
        "egress_filtering=false",
      ),
    );
  }

  // ── Missing default-deny ────────────────────────────────────────────────
  if (rules.length > 0 && !sawDeny) {
    findings.push(
      mk(
        file,
        "network-no-default-deny",
        "low",
        "Firewall rule set contains no deny rules",
        "Every rule in the set is an `allow` rule and there is no explicit deny. A permissive rule base relies entirely on an implicit default that is easy to misconfigure, and makes it hard to reason about what is actually blocked.",
        "Adopt a default-deny posture: add an explicit catch-all deny rule, then allow only the specific flows that are required.",
        ["CWE-284"],
        `rules=${String(rules.length)} deny=0`,
      ),
    );
  }

  return findings;
}

function mk(
  file: string | undefined,
  rule: string,
  severity: Severity,
  title: string,
  description: string,
  remediation: string,
  cwe: readonly string[],
  evidence: string,
): Finding {
  return buildInfraFinding(
    {
      rule,
      severity,
      title,
      description,
      remediation,
      cwe,
      references: REFS,
      evidence,
      tags: ["network", "firewall"],
    },
    file,
  );
}
