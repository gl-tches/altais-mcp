// Vulnerability-disclosure / bug-bounty program generator
// (altais_generate_disclosure_program).
//
// Produces a complete coordinated-vulnerability-disclosure (VDP) or
// bug-bounty policy document in markdown, covering scope, safe harbor,
// reporting process, and expectations. The output is a self-contained
// artifact — no Finding objects are pushed.

export interface DisclosureConfig {
  readonly organization: string;
  readonly scope_in?: readonly string[];
  readonly scope_out?: readonly string[];
  readonly safe_harbor?: boolean;
  readonly bounty?: boolean;
  readonly response_sla_days?: number;
  readonly contact: string;
}

export interface DisclosureResult {
  readonly markdown: string;
  readonly references: readonly string[];
}

const DEFAULT_SLA_DAYS = 5;

const REFS: readonly string[] = [
  "https://datatracker.ietf.org/doc/html/rfc9116",
  "https://www.cisa.gov/coordinated-vulnerability-disclosure-process",
  "https://owasp.org/www-project-vulnerability-disclosure/",
];

function bullets(items: readonly string[] | undefined, fallback: string): readonly string[] {
  const cleaned = (items ?? []).map((i) => i.trim()).filter((i) => i !== "");
  return cleaned.length > 0 ? cleaned.map((i) => `- ${i}`) : [`- ${fallback}`];
}

export function generateDisclosureProgram(config: DisclosureConfig): DisclosureResult {
  const org = config.organization.trim();
  const contact = config.contact.trim();
  const sla =
    typeof config.response_sla_days === "number" ? config.response_sla_days : DEFAULT_SLA_DAYS;
  const isBounty = config.bounty === true;
  const safeHarbor = config.safe_harbor !== false;

  const lines: string[] = [];

  lines.push(`# ${org} ${isBounty ? "Bug Bounty Program" : "Vulnerability Disclosure Policy"}`);
  lines.push("");
  lines.push("## Introduction");
  lines.push("");
  lines.push(
    `${org} values the work of security researchers and is committed to resolving ` +
      "security issues responsibly. This policy explains how to report a vulnerability " +
      `to us, what is in scope, and what you can expect in return.`,
  );
  lines.push("");

  lines.push("## Scope");
  lines.push("");
  lines.push("### In scope");
  lines.push("");
  for (const line of bullets(
    config.scope_in,
    "List the systems, domains, and applications covered by this policy.",
  )) {
    lines.push(line);
  }
  lines.push("");
  lines.push("### Out of scope");
  lines.push("");
  for (const line of bullets(config.scope_out, "Third-party services not operated by us.")) {
    lines.push(line);
  }
  lines.push("");
  lines.push(
    "The following finding types are generally **not** accepted: reports from automated " +
      "scanners without a demonstrated impact, denial-of-service testing, social engineering " +
      "of staff or customers, physical attacks, and spam or best-practice suggestions with no " +
      "security impact.",
  );
  lines.push("");

  lines.push("## How to report");
  lines.push("");
  lines.push(`- Send reports to **${contact}**.`);
  lines.push(
    "- Include a clear description, the affected asset, reproduction steps or a proof of " +
      "concept, and the impact you believe the issue has.",
  );
  lines.push("- Submit one issue per report so each can be tracked independently.");
  lines.push("- Encrypt sensitive details where possible; do not include real customer data.");
  lines.push("");

  lines.push("## Our commitment");
  lines.push("");
  lines.push(
    `- We will acknowledge your report within **${String(sla)} business day${sla === 1 ? "" : "s"}**.`,
  );
  lines.push("- We will keep you informed of our progress as we triage and remediate.");
  lines.push("- We will work with you on a coordinated disclosure timeline once a fix is ready.");
  lines.push("- We will credit you for the report unless you ask to remain anonymous.");
  lines.push("");

  lines.push("## Researcher expectations");
  lines.push("");
  lines.push(
    "- Stay within the in-scope assets and avoid any privacy violation or service degradation.",
  );
  lines.push(
    "- Use only your own accounts or test accounts; do not access, modify, or exfiltrate data " +
      "that does not belong to you.",
  );
  lines.push(
    "- Stop testing and report immediately if you encounter sensitive data such as personal " +
      "information or credentials.",
  );
  lines.push(
    "- Give us a reasonable time to remediate before any public disclosure, and coordinate the " +
      "timeline with us.",
  );
  lines.push("");

  lines.push("## Safe harbor");
  lines.push("");
  if (safeHarbor) {
    lines.push(
      `${org} will not pursue or support legal action against researchers who, in good faith, ` +
        "discover and report vulnerabilities in accordance with this policy. We consider such " +
        "research to be authorized conduct under applicable anti-hacking law, and we will help " +
        "make it known that your activity was authorized if a third party raises a concern. " +
        "If legal action is initiated by a third party against you for activity conducted in " +
        "line with this policy, we will make this authorization known.",
    );
  } else {
    lines.push(
      "This policy does not currently include a formal safe-harbor provision. Researchers " +
        "should contact us before testing to obtain explicit authorization for their planned " +
        "activity. We strongly recommend adopting a safe-harbor clause to encourage good-faith " +
        "research.",
    );
  }
  lines.push("");

  lines.push("## Rewards");
  lines.push("");
  if (isBounty) {
    lines.push(
      "Eligible reports may receive a monetary bounty. The amount is determined by the " +
        "severity and quality of the report (CVSS rating, exploitability, and clarity of the " +
        "write-up). Only the first reporter of a unique, in-scope, previously unknown issue is " +
        "eligible. Duplicates, out-of-scope reports, and issues already known to us are not " +
        "eligible for a reward.",
    );
  } else {
    lines.push(
      "This is a vulnerability disclosure program and does not currently offer monetary " +
        "rewards. We recognize valid reports with public acknowledgment, with the reporter's " +
        "consent.",
    );
  }
  lines.push("");

  lines.push("## References");
  lines.push("");
  for (const ref of REFS) {
    lines.push(`- ${ref}`);
  }
  lines.push("");

  return { markdown: `${lines.join("\n")}\n`, references: REFS };
}
