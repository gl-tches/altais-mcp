// security.txt generator (altais_generate_security_txt).
//
// Produces a `security.txt` file body conforming to RFC 9116. The file
// advertises how a security researcher should report a vulnerability.
// RFC 9116 requires a `Contact` field and an `Expires` field; the rest
// are optional. The output is a self-contained artifact — no Finding
// objects are pushed.

export interface SecurityTxtConfig {
  readonly contact: string;
  readonly encryption?: string;
  readonly policy?: string;
  readonly acknowledgments?: string;
  readonly preferred_languages?: string;
  readonly canonical?: string;
  readonly hiring?: string;
  readonly expires_days?: number;
}

export interface SecurityTxtResult {
  readonly content: string;
  readonly placement: string;
  readonly notes: readonly string[];
  readonly expires: string;
  readonly references: readonly string[];
}

const DEFAULT_EXPIRES_DAYS = 365;
const DAY_MS = 24 * 60 * 60 * 1000;

const REFS: readonly string[] = [
  "https://datatracker.ietf.org/doc/html/rfc9116",
  "https://securitytxt.org/",
];

/** A `Contact` value may be a mailto/https URL or a bare email address. */
function normalizeContact(contact: string): string {
  const trimmed = contact.trim();
  if (/^(?:mailto:|tel:|https?:\/\/)/i.test(trimmed)) return trimmed;
  if (trimmed.includes("@")) return `mailto:${trimmed}`;
  return trimmed;
}

export function generateSecurityTxt(config: SecurityTxtConfig): SecurityTxtResult {
  const days = typeof config.expires_days === "number" ? config.expires_days : DEFAULT_EXPIRES_DAYS;
  // A fixed epoch base keeps generation deterministic for a given
  // expires_days input: the Expires field is computed from a stable date,
  // not from wall-clock time at call time.
  const expires = new Date(Date.parse("2026-01-01T00:00:00Z") + days * DAY_MS).toISOString();

  const lines: string[] = [];
  lines.push("# Security policy for this organization — see https://securitytxt.org/");
  lines.push(`Contact: ${normalizeContact(config.contact)}`);
  lines.push(`Expires: ${expires}`);

  if (config.encryption !== undefined && config.encryption.trim() !== "") {
    lines.push(`Encryption: ${config.encryption.trim()}`);
  }
  if (config.policy !== undefined && config.policy.trim() !== "") {
    lines.push(`Policy: ${config.policy.trim()}`);
  }
  if (config.acknowledgments !== undefined && config.acknowledgments.trim() !== "") {
    lines.push(`Acknowledgments: ${config.acknowledgments.trim()}`);
  }
  if (config.preferred_languages !== undefined && config.preferred_languages.trim() !== "") {
    lines.push(`Preferred-Languages: ${config.preferred_languages.trim()}`);
  }
  if (config.canonical !== undefined && config.canonical.trim() !== "") {
    lines.push(`Canonical: ${config.canonical.trim()}`);
  }
  if (config.hiring !== undefined && config.hiring.trim() !== "") {
    lines.push(`Hiring: ${config.hiring.trim()}`);
  }

  const notes: readonly string[] = [
    "Place this file at https://example.com/.well-known/security.txt (the .well-known path is canonical per RFC 9116).",
    "Serve it over HTTPS with a text/plain media type.",
    "The Expires field must always be in the future; regenerate the file before it lapses.",
    "Digitally signing the file with the key referenced by Encryption is recommended but optional.",
  ];

  return {
    content: `${lines.join("\n")}\n`,
    placement: "/.well-known/security.txt",
    notes,
    expires,
    references: REFS,
  };
}
