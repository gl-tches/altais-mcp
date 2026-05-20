// PII detector (altais_detect_pii).
//
// Scans source code or sample data text for personally identifiable
// information: contact details, government identifiers, financial
// numbers, network identifiers, and PII-revealing variable / column
// names in code. Detection is pure regex / text scanning — raw matched
// values are never echoed back; every finding masks the evidence.

import type { Finding } from "../../core/types.js";
import { buildDataFinding, lineAt } from "./finding.js";

export interface PiiDetectInput {
  readonly source: string;
  readonly filename?: string;
}

const REFS = [
  "https://gdpr.eu/what-is-gdpr/",
  "https://owasp.org/www-community/vulnerabilities/Information_exposure_through_query_strings_in_url",
  "https://cwe.mitre.org/data/definitions/359.html",
  "https://www.nist.gov/privacy-framework",
];

type PiiSeverity = "high" | "medium" | "low";

interface ValuePattern {
  readonly rule: string;
  readonly category: string;
  readonly regex: RegExp;
  readonly severity: PiiSeverity;
  /** Mask a raw matched value into a non-revealing form. */
  readonly mask: (raw: string) => string;
  /** Optional extra validation (e.g. Luhn) to cut false positives. */
  readonly validate?: (raw: string) => boolean;
}

/** Mask a string keeping only the last `keep` characters. */
function maskTail(raw: string, keep: number): string {
  const cleaned = raw.trim();
  if (cleaned.length <= keep) return "*".repeat(cleaned.length);
  return "*".repeat(cleaned.length - keep) + cleaned.slice(cleaned.length - keep);
}

/** Luhn checksum — true when the digit string is a valid mod-10 number. */
function luhnValid(raw: string): boolean {
  const digits = raw.replace(/[^0-9]/g, "");
  if (digits.length < 13 || digits.length > 19) return false;
  let sum = 0;
  let double = false;
  for (let i = digits.length - 1; i >= 0; i--) {
    const ch = digits.charCodeAt(i) - 48;
    let d = ch;
    if (double) {
      d *= 2;
      if (d > 9) d -= 9;
    }
    sum += d;
    double = !double;
  }
  return sum % 10 === 0;
}

const VALUE_PATTERNS: readonly ValuePattern[] = [
  {
    rule: "pii-email-address",
    category: "email address",
    regex: /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,24}\b/g,
    severity: "medium",
    mask: (raw) => {
      const at = raw.indexOf("@");
      const local = at > 0 ? raw.slice(0, at) : raw;
      const domain = at > 0 ? raw.slice(at) : "";
      const head = local.slice(0, 1);
      return `${head}***${domain}`;
    },
  },
  {
    rule: "pii-us-ssn",
    category: "US Social Security Number",
    regex: /\b\d{3}-\d{2}-\d{4}\b/g,
    severity: "high",
    mask: (raw) => `***-**-${raw.slice(-4)}`,
  },
  {
    rule: "pii-credit-card",
    category: "credit card number",
    regex: /\b(?:\d[ -]?){12,18}\d\b/g,
    severity: "high",
    validate: luhnValid,
    mask: (raw) => {
      const digits = raw.replace(/[^0-9]/g, "");
      return `${"*".repeat(Math.max(0, digits.length - 4))}${digits.slice(-4)}`;
    },
  },
  {
    rule: "pii-phone-number",
    category: "phone number",
    regex: /(?<![\w.])\+?\d{1,3}?[ .-]?\(?\d{2,4}\)?[ .-]?\d{3}[ .-]?\d{3,4}(?![\w.])/g,
    severity: "medium",
    validate: (raw) => raw.replace(/[^0-9]/g, "").length >= 9,
    mask: (raw) => maskTail(raw.replace(/[^0-9+]/g, ""), 2),
  },
  {
    rule: "pii-ipv4-address",
    category: "IPv4 address",
    regex: /\b(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\b/g,
    severity: "low",
    mask: (raw) => {
      const parts = raw.split(".");
      return `${parts[0] ?? "*"}.${parts[1] ?? "*"}.*.*`;
    },
  },
  {
    rule: "pii-iban",
    category: "IBAN bank account number",
    regex: /\b[A-Z]{2}\d{2}[A-Z0-9]{11,30}\b/g,
    severity: "high",
    validate: (raw) => raw.length >= 15 && raw.length <= 34,
    mask: (raw) => `${raw.slice(0, 4)}${"*".repeat(Math.max(0, raw.length - 8))}${raw.slice(-4)}`,
  },
  {
    rule: "pii-date-of-birth",
    category: "date of birth",
    regex:
      /\b(?:(?:0?[1-9]|[12]\d|3[01])[/.-](?:0?[1-9]|1[0-2])|(?:0?[1-9]|1[0-2])[/.-](?:0?[1-9]|[12]\d|3[01]))[/.-](?:19|20)\d\d\b/g,
    severity: "medium",
    mask: () => "**/**/****",
  },
];

// Variable / column names that reveal PII fields in code or schemas.
interface IdentifierRule {
  readonly rule: string;
  readonly category: string;
  readonly severity: PiiSeverity;
  readonly names: readonly string[];
}

const IDENTIFIER_RULES: readonly IdentifierRule[] = [
  {
    rule: "pii-identifier-ssn",
    category: "Social Security Number identifier",
    severity: "high",
    names: ["ssn", "social_security", "social_security_number", "socialsecuritynumber"],
  },
  {
    rule: "pii-identifier-name",
    category: "personal name identifier",
    severity: "medium",
    names: ["first_name", "firstname", "last_name", "lastname", "full_name", "fullname"],
  },
  {
    rule: "pii-identifier-date-of-birth",
    category: "date-of-birth identifier",
    severity: "medium",
    names: ["date_of_birth", "dateofbirth", "dob", "birth_date", "birthdate"],
  },
  {
    rule: "pii-identifier-government-id",
    category: "government identifier",
    severity: "high",
    names: ["passport", "passport_number", "drivers_license", "driver_license", "license_number"],
  },
  {
    rule: "pii-identifier-home-address",
    category: "home address identifier",
    severity: "medium",
    names: ["home_address", "street_address", "mailing_address", "postal_address"],
  },
];

/** Build a word-boundary, case-insensitive global regex for an identifier name. */
function identifierRegex(name: string): RegExp {
  return new RegExp(`\\b${name}\\b`, "gi");
}

export function detectPii(input: PiiDetectInput): readonly Finding[] {
  const source = input.source;
  const file = input.filename;
  const findings: Finding[] = [];

  for (const pat of VALUE_PATTERNS) {
    const regex = new RegExp(pat.regex.source, pat.regex.flags);
    let m: RegExpExecArray | null;
    while ((m = regex.exec(source)) !== null) {
      const raw = m[0];
      if (raw.length === 0) {
        regex.lastIndex += 1;
        continue;
      }
      if (pat.validate !== undefined && !pat.validate(raw)) continue;
      const line = lineAt(source, m.index);
      findings.push(
        buildDataFinding(
          {
            rule: pat.rule,
            severity: pat.severity,
            title: `Detected ${pat.category} in scanned content`,
            description: `A value matching the shape of a ${pat.category} appears in the scanned source. Personal data embedded in code, fixtures, logs, or sample data is a privacy exposure: it can be committed to version control, shipped in artifacts, or leaked through error messages.`,
            remediation: `Remove the real ${pat.category} from source. Use clearly synthetic placeholder data for fixtures and tests, and keep production personal data in an access-controlled, encrypted store — never in code.`,
            cwe: ["CWE-359", "CWE-200"],
            references: REFS,
            evidence: `${pat.category}: ${pat.mask(raw)} (line ${String(line)})`,
            tags: ["pii", "privacy"],
            line,
          },
          file,
        ),
      );
    }
  }

  for (const rule of IDENTIFIER_RULES) {
    for (const name of rule.names) {
      const regex = identifierRegex(name);
      let m: RegExpExecArray | null;
      while ((m = regex.exec(source)) !== null) {
        const line = lineAt(source, m.index);
        findings.push(
          buildDataFinding(
            {
              rule: rule.rule,
              severity: rule.severity,
              title: `PII-revealing identifier \`${name}\` found in code`,
              description: `The identifier \`${name}\` indicates the code or schema handles a ${rule.category}. Code that stores or processes this category of personal data must apply encryption, access control, and minimization, and must be covered by the data-retention and privacy program.`,
              remediation: `Confirm the field holding this ${rule.category} is encrypted at rest, access-controlled, retention-bounded, and documented in the data inventory. Mask or tokenize it in logs and non-production environments.`,
              cwe: ["CWE-359"],
              references: REFS,
              evidence: `identifier: ${name} (line ${String(line)})`,
              tags: ["pii", "privacy", "identifier"],
              line,
            },
            file,
          ),
        );
      }
    }
  }

  return findings;
}
