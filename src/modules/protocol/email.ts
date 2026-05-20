// Email authentication auditor (altais_audit_email_security).
//
// Inspects a domain's SPF, DKIM, DMARC, MTA-STS, and DNSSEC posture.
// SPF and DMARC record strings are parsed into mechanisms / tags so the
// auditor can flag a permissive `+all`, a missing `-all`/`~all`, a weak
// `p=none` DMARC policy, and missing aggregate (`rua`) reporting.

import type { Finding } from "../../core/types.js";
import { buildProtocolFinding } from "./finding.js";

export type DmarcPolicy = "none" | "quarantine" | "reject";

export interface EmailSecurityAuditConfig {
  readonly spf_record?: string;
  readonly dkim_enabled?: boolean;
  readonly dkim_selectors?: readonly string[];
  readonly dmarc_record?: string;
  readonly dmarc_policy?: DmarcPolicy;
  readonly mta_sts?: boolean;
  readonly dnssec?: boolean;
}

export interface EmailSecurityAuditInput {
  readonly config: EmailSecurityAuditConfig;
  readonly filename?: string;
}

const REFS = [
  "https://datatracker.ietf.org/doc/html/rfc7208",
  "https://datatracker.ietf.org/doc/html/rfc7489",
  "https://datatracker.ietf.org/doc/html/rfc8461",
];

function mk(
  filename: string | undefined,
  rule: string,
  severity: Finding["severity"],
  title: string,
  description: string,
  remediation: string,
  cwe: readonly string[],
  evidence: string,
  tags: readonly string[],
): Finding {
  return buildProtocolFinding(
    {
      rule,
      severity,
      title,
      description,
      remediation,
      cwe,
      references: REFS,
      evidence,
      tags: ["email", ...tags],
    },
    filename,
  );
}

/** Parse `key=value;` style DMARC / MTA-STS tags into a lookup map. */
function parseTags(record: string): ReadonlyMap<string, string> {
  const map = new Map<string, string>();
  for (const part of record.split(";")) {
    const eq = part.indexOf("=");
    if (eq < 0) continue;
    const key = part.slice(0, eq).trim().toLowerCase();
    const value = part.slice(eq + 1).trim();
    if (key.length > 0) map.set(key, value);
  }
  return map;
}

/** The trailing `all` mechanism qualifier of an SPF record, if present. */
function spfAllQualifier(record: string): string | undefined {
  const m = /([-~?+]?)all\b/i.exec(record);
  return m === null ? undefined : m[1] === "" ? "+" : m[1];
}

function auditSpf(record: string | undefined, file: string | undefined, findings: Finding[]): void {
  if (record === undefined || record.trim() === "") {
    findings.push(
      mk(
        file,
        "email-missing-spf",
        "medium",
        "No SPF record is published",
        "Without a Sender Policy Framework record, receivers have no list of authorized sending hosts. Anyone can send mail claiming to be from the domain (envelope-from spoofing).",
        "Publish a `v=spf1` TXT record listing legitimate senders and ending in `-all` (hard fail) or `~all` (soft fail).",
        ["CWE-290"],
        "spf_record=<absent>",
        ["spf"],
      ),
    );
    return;
  }

  const qualifier = spfAllQualifier(record);
  if (qualifier === undefined) {
    findings.push(
      mk(
        file,
        "email-spf-no-all-mechanism",
        "medium",
        "SPF record has no terminating `all` mechanism",
        "An SPF record without a trailing `all` mechanism leaves the default result `neutral`. Receivers treat unlisted senders the same as if no policy existed, so spoofing is not blocked.",
        "End the SPF record with `-all` (hard fail) or `~all` (soft fail) to define how unlisted senders are treated.",
        ["CWE-290"],
        record.slice(0, 200),
        ["spf"],
      ),
    );
  } else if (qualifier === "+") {
    findings.push(
      mk(
        file,
        "email-spf-permissive-all",
        "high",
        "SPF record ends in `+all` and authorizes every sender",
        "`+all` (pass-all) tells receivers that any host on the internet is an authorized sender for the domain. The SPF record provides no spoofing protection whatsoever.",
        "Replace `+all` with `-all` (hard fail) or `~all` (soft fail) and enumerate only the legitimate sending sources.",
        ["CWE-290"],
        record.slice(0, 200),
        ["spf"],
      ),
    );
  } else if (qualifier === "?") {
    findings.push(
      mk(
        file,
        "email-spf-neutral-all",
        "medium",
        "SPF record ends in `?all` (neutral)",
        "`?all` makes the SPF result explicitly neutral for unlisted senders, so receivers apply no enforcement. Spoofed mail from hosts outside the record is not penalized.",
        "Tighten the terminating mechanism to `-all` (hard fail) or `~all` (soft fail).",
        ["CWE-290"],
        record.slice(0, 200),
        ["spf"],
      ),
    );
  }
}

function auditDkim(
  c: EmailSecurityAuditConfig,
  file: string | undefined,
  findings: Finding[],
): void {
  const hasSelectors = (c.dkim_selectors ?? []).length > 0;
  if (c.dkim_enabled === false || (c.dkim_enabled === undefined && !hasSelectors)) {
    findings.push(
      mk(
        file,
        "email-missing-dkim",
        "medium",
        "DKIM signing is not configured",
        "Without DomainKeys Identified Mail, outbound messages carry no cryptographic signature. Receivers cannot verify the message body and headers were not altered in transit, and DMARC cannot pass via DKIM alignment.",
        "Generate a DKIM key pair, publish the public key under a selector (`<selector>._domainkey`), and sign all outbound mail.",
        ["CWE-345"],
        c.dkim_enabled === false ? "dkim_enabled=false" : "no dkim_selectors",
        ["dkim"],
      ),
    );
  }
}

function auditDmarc(
  c: EmailSecurityAuditConfig,
  file: string | undefined,
  findings: Finding[],
): void {
  const record = c.dmarc_record;
  if ((record === undefined || record.trim() === "") && c.dmarc_policy === undefined) {
    findings.push(
      mk(
        file,
        "email-missing-dmarc",
        "high",
        "No DMARC record is published",
        "Without DMARC, the domain owner gives receivers no policy for handling messages that fail SPF and DKIM, and receives no reporting. SPF/DKIM alone do not protect the visible `From:` header from spoofing.",
        "Publish a `_dmarc` TXT record (`v=DMARC1; p=quarantine; rua=mailto:...`) and progress toward `p=reject`.",
        ["CWE-290"],
        "dmarc_record=<absent>",
        ["dmarc"],
      ),
    );
    return;
  }

  const tags = record !== undefined ? parseTags(record) : new Map<string, string>();
  const policy = (c.dmarc_policy ?? tags.get("p"))?.toLowerCase();

  if (policy === "none") {
    findings.push(
      mk(
        file,
        "email-dmarc-policy-none",
        "medium",
        "DMARC policy is `p=none` (monitor only)",
        "`p=none` tells receivers to take no action on messages that fail authentication. The domain is monitored but spoofed mail is still delivered to recipients.",
        "Once aggregate reports confirm legitimate mail aligns, move the policy to `p=quarantine` and then `p=reject`.",
        ["CWE-290"],
        `p=${policy}`,
        ["dmarc"],
      ),
    );
  }

  if (record !== undefined && record.trim() !== "") {
    const rua = tags.get("rua");
    if (rua === undefined || rua === "") {
      findings.push(
        mk(
          file,
          "email-dmarc-no-aggregate-reporting",
          "low",
          "DMARC record has no `rua` aggregate reporting address",
          "Without an `rua` tag, the domain owner receives no aggregate reports and is blind to authentication failures, spoofing attempts, and misconfigured legitimate senders.",
          "Add `rua=mailto:dmarc-reports@yourdomain` so receivers send daily aggregate XML reports.",
          ["CWE-778"],
          record.slice(0, 200),
          ["dmarc"],
        ),
      );
    }
  }
}

export function auditEmailSecurity(input: EmailSecurityAuditInput): readonly Finding[] {
  const c = input.config;
  const file = input.filename;
  const findings: Finding[] = [];

  auditSpf(c.spf_record, file, findings);
  auditDkim(c, file, findings);
  auditDmarc(c, file, findings);

  if (c.mta_sts === false) {
    findings.push(
      mk(
        file,
        "email-missing-mta-sts",
        "low",
        "MTA-STS is not enabled",
        "Without SMTP MTA Strict Transport Security, inbound SMTP can be downgraded to plaintext by a network attacker (STARTTLS stripping), exposing message content in transit.",
        "Publish an MTA-STS policy (`_mta-sts` TXT record plus an `enforce` policy file) and enable TLS-RPT reporting.",
        ["CWE-319"],
        "mta_sts=false",
        ["mta-sts"],
      ),
    );
  }

  if (c.dnssec === false) {
    findings.push(
      mk(
        file,
        "email-missing-dnssec",
        "low",
        "DNSSEC is not enabled for the domain",
        "Without DNSSEC, the SPF, DKIM, DMARC, and MTA-STS records themselves can be forged by a DNS spoofing or cache-poisoning attacker, undermining every email-authentication control that relies on them.",
        "Sign the zone with DNSSEC and publish a DS record at the registrar.",
        ["CWE-345"],
        "dnssec=false",
        ["dnssec"],
      ),
    );
  }

  return findings;
}
