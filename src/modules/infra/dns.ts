// DNS configuration auditor (altais_audit_dns).
//
// Checks a declarative description of a DNS zone for the
// misconfigurations that undermine its integrity and broaden the attack
// surface: DNSSEC disabled, open zone transfers (AXFR), missing CAA
// records, wildcard records, and dangling records that point at
// unclaimed external resources (a subdomain-takeover vector).

import type { Finding, Severity } from "../../core/types.js";
import { buildInfraFinding } from "./finding.js";

export interface DnsRecord {
  readonly name: string;
  readonly type: string;
  readonly value: string;
  readonly points_to_external?: boolean;
}

export interface DnsAuditConfig {
  readonly dnssec_enabled?: boolean;
  readonly zone_transfer_allowed?: boolean;
  readonly allowed_to?: readonly string[];
  readonly caa_records?: readonly string[];
  readonly wildcard_records?: boolean | readonly string[];
  readonly records?: readonly DnsRecord[];
}

export interface DnsAuditInput {
  readonly config: DnsAuditConfig;
  readonly filename?: string;
}

const REFS = [
  "https://cwe.mitre.org/data/definitions/350.html",
  "https://cwe.mitre.org/data/definitions/200.html",
  "https://cwe.mitre.org/data/definitions/295.html",
  "https://owasp.org/www-community/attacks/Subdomain_Takeover",
];

// Record types whose value resolves a name to another name / host —
// these are the records vulnerable to subdomain takeover when dangling.
const ALIAS_TYPES = new Set(["CNAME", "ALIAS", "ANAME", "NS", "MX"]);

export function auditDns(input: DnsAuditInput): readonly Finding[] {
  const file = input.filename;
  const cfg = input.config;
  const findings: Finding[] = [];

  // ── DNSSEC ──────────────────────────────────────────────────────────────
  if (cfg.dnssec_enabled === false) {
    findings.push(
      mk(
        file,
        "dns-dnssec-disabled",
        "high",
        "DNSSEC is not enabled for the zone",
        "Without DNSSEC, DNS responses are unsigned and cannot be cryptographically verified. An attacker positioned to spoof or poison resolver caches can forge answers and redirect traffic to hosts they control.",
        "Enable DNSSEC: sign the zone, publish DS records at the parent registrar, and monitor key rollovers. Validate the chain of trust end to end after enabling.",
        ["CWE-350"],
        "dnssec_enabled=false",
      ),
    );
  }

  // ── Zone transfer / AXFR ────────────────────────────────────────────────
  const allowedTo = cfg.allowed_to;
  const transferOpen =
    cfg.zone_transfer_allowed === true ||
    (allowedTo?.some((h) => {
      const v = h.trim().toLowerCase();
      return v === "any" || v === "*" || v === "0.0.0.0/0" || v === "::/0";
    }) ??
      false);
  if (transferOpen) {
    findings.push(
      mk(
        file,
        "dns-open-zone-transfer",
        "high",
        "Zone transfer (AXFR) is allowed from any host",
        "An open AXFR lets anyone download the entire zone file in one query, enumerating every hostname, internal service, and IP range. This hands an attacker a complete map of the infrastructure for free.",
        "Restrict zone transfers to the secondary name servers' IP addresses only, and authenticate them with TSIG keys. Reject AXFR from every other source.",
        ["CWE-200"],
        cfg.zone_transfer_allowed === true
          ? "zone_transfer_allowed=true"
          : `allowed_to=${(allowedTo ?? []).join(",").slice(0, 180)}`,
      ),
    );
  }

  // ── CAA records ─────────────────────────────────────────────────────────
  if (cfg.caa_records?.length === 0) {
    findings.push(
      mk(
        file,
        "dns-missing-caa",
        "medium",
        "Zone has no CAA records",
        "Without a CAA record, any public certificate authority will issue a certificate for the domain. A single mis-issued or fraudulently obtained certificate then lets an attacker present a trusted TLS identity for the domain.",
        "Publish CAA records naming only the certificate authorities authorized to issue for the domain, and add an `iodef` contact so unauthorized issuance attempts are reported.",
        ["CWE-295"],
        "caa_records=[]",
      ),
    );
  }

  // ── Wildcard records ────────────────────────────────────────────────────
  const wildcard = cfg.wildcard_records;
  const wildcardNames: string[] =
    Array.isArray(wildcard) && wildcard.length > 0
      ? wildcard.map((w) => String(w))
      : wildcard === true
        ? ["*"]
        : [];
  if (wildcardNames.length > 0) {
    findings.push(
      mk(
        file,
        "dns-wildcard-record",
        "low",
        "Zone uses wildcard DNS records",
        "A wildcard record resolves every undefined subdomain to a single target. It masks typos and stale entries, enables phishing on arbitrary look-alike subdomains, and can route attacker-chosen hostnames into the application's virtual-host routing.",
        "Replace wildcard records with explicit records for each hostname actually in use. Where a wildcard is unavoidable, ensure the receiving service strictly validates the Host header it accepts.",
        ["CWE-350"],
        `wildcard_records=${wildcardNames.join(",").slice(0, 180)}`,
      ),
    );
  }

  // ── Dangling records (subdomain takeover) ───────────────────────────────
  for (const rec of cfg.records ?? []) {
    if (rec.points_to_external !== true) continue;
    const type = rec.type.trim().toUpperCase();
    if (!ALIAS_TYPES.has(type)) continue;
    findings.push(
      mk(
        file,
        "dns-dangling-record",
        "high",
        `Record \`${rec.name}\` points to an external resource (subdomain-takeover risk)`,
        `The ${type} record for \`${rec.name}\` resolves to an external target (\`${rec.value}\`). If that external resource — a cloud bucket, a SaaS endpoint, a deprovisioned host — is released, an attacker can re-register it and serve content under the trusted subdomain.`,
        "Verify every external target is still owned and in use. Remove records whose target is no longer claimed, and review external CNAME / ALIAS targets on a regular cadence to catch newly dangling entries.",
        ["CWE-350"],
        `${rec.name} ${type} ${rec.value}`.slice(0, 200),
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
      tags: ["dns"],
    },
    file,
  );
}
