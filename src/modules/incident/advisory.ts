// Security advisory generator (altais_draft_advisory).
//
// Drafts a security advisory in the GitHub Security Advisory (GHSA) style:
// a markdown document with a summary, severity, affected and patched
// versions, impact, remediation, references, and a disclosure timeline.
// The output is a self-contained artifact — no Finding objects are pushed.

export type AdvisorySeverity = "critical" | "high" | "moderate" | "low";

export interface AdvisoryConfig {
  readonly title: string;
  readonly severity: AdvisorySeverity;
  readonly cve?: string;
  readonly cwe?: readonly string[];
  readonly affected_versions?: string;
  readonly patched_version?: string;
  readonly description?: string;
  readonly impact?: string;
  readonly cvss_vector?: string;
  readonly credits?: string;
}

export interface AdvisoryResult {
  readonly markdown: string;
  readonly references: readonly string[];
}

const REFS: readonly string[] = [
  "https://github.com/advisories",
  "https://docs.github.com/code-security/security-advisories",
  "https://cwe.mitre.org/",
];

function cweUrl(id: string): string {
  const num = /(\d+)/.exec(id);
  return num !== null
    ? `https://cwe.mitre.org/data/definitions/${String(num[1])}.html`
    : "https://cwe.mitre.org/";
}

export function draftAdvisory(config: AdvisoryConfig): AdvisoryResult {
  const lines: string[] = [];
  const affected = config.affected_versions?.trim();
  const patched = config.patched_version?.trim();
  const description = config.description?.trim();
  const impact = config.impact?.trim();
  const credits = config.credits?.trim();
  const cve = config.cve?.trim();
  const cwes = (config.cwe ?? []).map((c) => c.trim()).filter((c) => c !== "");

  lines.push(`# ${config.title.trim()}`);
  lines.push("");

  lines.push("## Summary");
  lines.push("");
  lines.push(
    description !== undefined && description !== ""
      ? description
      : "_Provide a concise, plain-language summary of the vulnerability here._",
  );
  lines.push("");

  lines.push("## Severity");
  lines.push("");
  lines.push(`- **Rating:** ${config.severity}`);
  if (config.cvss_vector !== undefined && config.cvss_vector.trim() !== "") {
    lines.push(`- **CVSS vector:** \`${config.cvss_vector.trim()}\``);
  }
  if (cve !== undefined && cve !== "") {
    lines.push(`- **CVE:** ${cve}`);
  }
  if (cwes.length > 0) {
    lines.push(`- **Weakness:** ${cwes.join(", ")}`);
  }
  lines.push("");

  lines.push("## Affected versions");
  lines.push("");
  lines.push(
    affected !== undefined && affected !== ""
      ? affected
      : "_Specify the affected version range, e.g. `>= 2.0.0, < 2.4.1`._",
  );
  lines.push("");

  lines.push("## Patched versions");
  lines.push("");
  lines.push(
    patched !== undefined && patched !== ""
      ? patched
      : "_Specify the first fixed version, or state that no patch is yet available._",
  );
  lines.push("");

  lines.push("## Impact");
  lines.push("");
  lines.push(
    impact !== undefined && impact !== ""
      ? impact
      : "_Describe who is affected and what an attacker can achieve by exploiting this issue._",
  );
  lines.push("");

  lines.push("## Remediation");
  lines.push("");
  if (patched !== undefined && patched !== "") {
    lines.push(`- Upgrade to ${patched} or later, which contains the fix.`);
  } else {
    lines.push("- Upgrade to a fixed release once one is available.");
  }
  lines.push(
    "- If an immediate upgrade is not possible, apply the documented workaround or mitigation to reduce exposure.",
  );
  lines.push("- Audit logs for indicators of exploitation against the affected versions.");
  lines.push("");

  lines.push("## References");
  lines.push("");
  if (cve !== undefined && cve !== "") {
    lines.push(`- https://nvd.nist.gov/vuln/detail/${cve}`);
  }
  for (const c of cwes) {
    lines.push(`- ${cweUrl(c)}`);
  }
  lines.push("- https://github.com/advisories");
  lines.push("");

  lines.push("## Timeline");
  lines.push("");
  lines.push("- **Reported:** _date the issue was reported_");
  lines.push("- **Triaged:** _date the issue was confirmed_");
  lines.push("- **Fixed:** _date the patched release shipped_");
  lines.push("- **Disclosed:** _date this advisory was published_");
  lines.push("");

  lines.push("## Credits");
  lines.push("");
  lines.push(
    credits !== undefined && credits !== ""
      ? credits
      : "_Credit the reporter(s) who discovered and responsibly disclosed this issue._",
  );
  lines.push("");

  return { markdown: `${lines.join("\n")}\n`, references: REFS };
}
