// Data classifier (altais_classify_data).
//
// Takes a list of data fields and assigns each a sensitivity tier
// (restricted / confidential / internal / public) by pattern-matching
// the field name, type, and description. Every field that lands in the
// restricted or confidential tier is emitted as a tracked Finding so it
// is carried into the remediation backlog.

import type { Finding, Severity } from "../../core/types.js";
import { buildDataFinding } from "./finding.js";

export type SensitivityTier = "restricted" | "confidential" | "internal" | "public";

export interface DataField {
  readonly name: string;
  readonly type?: string;
  readonly description?: string;
}

export interface ClassifyDataInput {
  readonly fields: readonly DataField[];
}

const REFS = [
  "https://gdpr.eu/article-9-processing-special-categories-of-personal-data/",
  "https://owasp.org/www-project-top-ten/2021/A02_2021-Cryptographic_Failures",
  "https://cwe.mitre.org/data/definitions/312.html",
  "https://www.nist.gov/privacy-framework",
];

interface TierRule {
  readonly tier: SensitivityTier;
  readonly category: string;
  readonly patterns: readonly RegExp[];
}

// A token separator: word boundary, whitespace, underscore, or hyphen.
const S = "[_\\s-]?";

/** Build a case-insensitive regex matching `name` with flexible separators. */
function p(name: string): RegExp {
  return new RegExp(name.replace(/ /g, S), "i");
}

// Ordered most-sensitive first; the first match wins.
const TIER_RULES: readonly TierRule[] = [
  {
    tier: "restricted",
    category: "secret or credential",
    patterns: [
      /pass(?:word|wd|phrase)/i,
      /secret/i,
      p("api key"),
      p("private key"),
      p("access token"),
      /credential/i,
    ],
  },
  {
    tier: "restricted",
    category: "government or financial identifier",
    patterns: [
      /\bssn\b/i,
      p("social security"),
      p("credit card"),
      p("card number"),
      /\bcvv\b/i,
      /passport/i,
      /drivers?[_\s-]?licen[sc]e/i,
      p("bank account"),
      /\biban\b/i,
      p("tax id"),
    ],
  },
  {
    tier: "restricted",
    category: "health or biometric data",
    patterns: [
      /health/i,
      /medical/i,
      /diagnos(?:is|es)/i,
      /biometric/i,
      /fingerprint/i,
      /genetic/i,
      /disability/i,
    ],
  },
  {
    tier: "confidential",
    category: "direct contact or identity data",
    patterns: [
      /email/i,
      /phone/i,
      /mobile/i,
      p("first name"),
      p("last name"),
      p("full name"),
      p("date of birth"),
      /\bdob\b/i,
      p("birth date"),
    ],
  },
  {
    tier: "confidential",
    category: "location or address data",
    patterns: [
      /address/i,
      p("postal code"),
      p("zip code"),
      /latitude/i,
      /longitude/i,
      p("geo location"),
      p("ip address"),
    ],
  },
  {
    tier: "internal",
    category: "internal operational data",
    patterns: [
      p("user id"),
      p("account id"),
      p("created at"),
      p("updated at"),
      /internal/i,
      /\bis[_\s-]?[a-z]/i,
      /status/i,
    ],
  },
  {
    tier: "public",
    category: "public-facing data",
    patterns: [/slug/i, p("public title"), p("display title"), /permalink/i],
  },
];

export interface FieldClassification {
  readonly field: string;
  readonly tier: SensitivityTier;
  readonly category: string;
}

/** Classify a single field's haystack (name + type + description). */
function classifyField(field: DataField): FieldClassification {
  const haystack = [field.name, field.type ?? "", field.description ?? ""].join(" ");
  for (const rule of TIER_RULES) {
    for (const pattern of rule.patterns) {
      if (pattern.test(haystack)) {
        return { field: field.name, tier: rule.tier, category: rule.category };
      }
    }
  }
  return { field: field.name, tier: "internal", category: "unclassified — default to internal" };
}

const TIER_SEVERITY: Readonly<Record<"restricted" | "confidential", Severity>> = {
  restricted: "high",
  confidential: "medium",
};

export interface ClassifyDataResult {
  readonly classifications: readonly FieldClassification[];
  readonly summary: Readonly<Record<SensitivityTier, number>>;
  readonly findings: readonly Finding[];
}

/**
 * Classify the supplied fields. Returns the per-field tiers, a tier
 * tally, and a Finding for every restricted / confidential field.
 */
export function classifyData(input: ClassifyDataInput): ClassifyDataResult {
  const classifications = input.fields.map(classifyField);
  const summary: Record<SensitivityTier, number> = {
    restricted: 0,
    confidential: 0,
    internal: 0,
    public: 0,
  };
  for (const c of classifications) summary[c.tier] += 1;

  const findings: Finding[] = [];
  for (const c of classifications) {
    if (c.tier !== "restricted" && c.tier !== "confidential") continue;
    const severity = TIER_SEVERITY[c.tier];
    findings.push(
      buildDataFinding(
        {
          rule: `data-classified-${c.tier}`,
          severity,
          title: `Field \`${c.field}\` classified ${c.tier} (${c.category})`,
          description: `The field \`${c.field}\` was classified as ${c.tier} sensitivity because it matches a ${c.category} pattern. ${
            c.tier === "restricted"
              ? "Restricted data (secrets, government / financial identifiers, health, biometric) carries the highest breach impact and the strictest legal obligations."
              : "Confidential data (contact details, names, dates of birth, precise location) is regulated personal data and must not be exposed."
          }`,
          remediation: `Encrypt \`${c.field}\` at rest and in transit, restrict access to the minimum set of roles, and mask or tokenize it in logs and non-production environments.${
            c.tier === "restricted"
              ? " Consider field-level encryption or tokenization and an audited access trail."
              : ""
          }`,
          cwe: ["CWE-312", "CWE-359"],
          references: REFS,
          evidence: `field: ${c.field} -> tier: ${c.tier}`,
          tags: ["classification", "privacy", c.tier],
        },
        undefined,
      ),
    );
  }

  return { classifications, summary, findings };
}

/** Findings-only view, matching the analyzer signature used by the runner. */
export function classifyDataFindings(input: ClassifyDataInput): readonly Finding[] {
  return classifyData(input).findings;
}
