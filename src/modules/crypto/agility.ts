// Cryptographic agility assessor (altais_assess_crypto_agility).
//
// Can the system swap a primitive (cipher, hash, KEM) without code
// changes? Agility is what makes the eventual PQC migration — and any
// emergency algorithm break — tractable.

import type { Finding } from "../../core/types.js";
import { buildCryptoFinding, lineAt } from "./finding.js";

export interface CryptoAgilityConfig {
  /** Algorithm choices are pinned to config / negotiated, not hardcoded. */
  readonly algorithm_from_config?: boolean;
  /** Stored ciphertext carries an algorithm/version identifier. */
  readonly versioned_ciphertext?: boolean;
  /** Crypto is accessed through an abstraction / provider layer. */
  readonly abstraction_layer?: boolean;
  /** A cryptographic inventory / CBOM exists. */
  readonly inventory_exists?: boolean;
  /** Keys and algorithms can be rotated without a redeploy. */
  readonly rotation_without_redeploy?: boolean;
}

export interface CryptoAgilityInput {
  readonly source?: string;
  readonly config?: CryptoAgilityConfig;
  readonly filename?: string;
}

const REFS = [
  "https://csrc.nist.gov/pubs/cswp/39/considerations-for-achieving-crypto-agility/final",
  "https://owasp.org/Top10/A02_2021-Cryptographic_Failures/",
];

// Algorithm strings hardcoded as literals throughout the codebase are the
// classic agility blocker.
const HARDCODED_ALGO_RE =
  /["'](?:aes-(?:128|192|256)-(?:cbc|gcm|ctr|ecb)|sha-?(?:1|224|256|384|512)|md5|rsa-?(?:oaep|pkcs1)?|hmac-?sha\d+|chacha20(?:-poly1305)?)["']/gi;
const HARDCODED_THRESHOLD = 3;

export function assessCryptoAgility(input: CryptoAgilityInput): readonly Finding[] {
  const findings: Finding[] = [];

  if (input.source) {
    const src = input.source;
    const re = new RegExp(HARDCODED_ALGO_RE.source, "gi");
    const matches: { text: string; index: number }[] = [];
    let m: RegExpExecArray | null;
    while ((m = re.exec(src)) !== null) {
      matches.push({ text: m[0], index: m.index });
      if (m[0].length === 0) re.lastIndex += 1;
    }
    if (matches.length >= HARDCODED_THRESHOLD) {
      const first = matches[0];
      if (first !== undefined) {
        findings.push(
          buildCryptoFinding(
            {
              rule: "agility-hardcoded-algorithms",
              severity: "medium",
              title: `Algorithm names hardcoded in ${matches.length} place(s)`,
              description:
                "Algorithm identifiers scattered as string literals must each be found and edited to change a primitive — there is no single point of control. This blocks both routine upgrades and emergency replacement of a broken algorithm.",
              remediation:
                "Centralize algorithm selection behind a config value or a single crypto-policy module. Reference that one source everywhere.",
              cwe: ["CWE-327"],
              references: REFS,
              evidence: matches
                .slice(0, 5)
                .map((x) => x.text)
                .join(", "),
              tags: ["agility"],
              line: lineAt(src, first.index),
            },
            input.filename,
          ),
        );
      }
    }
  }

  if (input.config) {
    const c = input.config;

    if (c.versioned_ciphertext === false) {
      findings.push(
        buildCryptoFinding(
          {
            rule: "agility-no-versioned-ciphertext",
            severity: "high",
            title: "Stored ciphertext carries no algorithm/version identifier",
            description:
              "Without a version tag, the system cannot tell which algorithm encrypted a given record, so it can never decrypt-and-re-encrypt existing data under a new primitive. Stored data is effectively frozen on its original algorithm.",
            remediation:
              "Prefix ciphertext with a version/algorithm byte. On read, branch on the version; on write, always use the current algorithm — enabling lazy migration.",
            cwe: ["CWE-327"],
            references: REFS,
            evidence: "versioned_ciphertext=false",
            tags: ["agility"],
          },
          input.filename,
        ),
      );
    }

    if (c.algorithm_from_config === false) {
      findings.push(
        buildCryptoFinding(
          {
            rule: "agility-algorithm-not-configurable",
            severity: "medium",
            title: "Algorithm selection is not driven by configuration",
            description:
              "When the algorithm cannot be changed without editing and redeploying code, responding to a cryptographic break is slow.",
            remediation:
              "Drive algorithm choice from configuration or negotiation so a primitive can be swapped operationally.",
            cwe: ["CWE-327"],
            references: REFS,
            evidence: "algorithm_from_config=false",
            tags: ["agility"],
          },
          input.filename,
        ),
      );
    }

    if (c.abstraction_layer === false) {
      findings.push(
        buildCryptoFinding(
          {
            rule: "agility-no-abstraction-layer",
            severity: "low",
            title: "No cryptographic abstraction layer",
            description:
              "Direct calls to a crypto library from across the codebase couple every call site to a specific primitive and API shape.",
            remediation:
              "Route crypto through a thin internal interface (encrypt / decrypt / sign / verify) so the implementation can change in one place.",
            cwe: ["CWE-327"],
            references: REFS,
            evidence: "abstraction_layer=false",
            tags: ["agility"],
          },
          input.filename,
        ),
      );
    }

    if (c.inventory_exists === false) {
      findings.push(
        buildCryptoFinding(
          {
            rule: "agility-no-crypto-inventory",
            severity: "medium",
            title: "No cryptographic inventory (CBOM)",
            description:
              "Without an inventory of which algorithms, key sizes, and protocols are used where, you cannot scope a migration or know what an algorithm break affects.",
            remediation:
              "Build and maintain a Cryptographic Bill of Materials (CBOM) covering algorithms, key sizes, protocols, and their locations.",
            cwe: ["CWE-1059"],
            references: REFS,
            evidence: "inventory_exists=false",
            tags: ["agility"],
          },
          input.filename,
        ),
      );
    }

    if (c.rotation_without_redeploy === false) {
      findings.push(
        buildCryptoFinding(
          {
            rule: "agility-rotation-requires-redeploy",
            severity: "medium",
            title: "Algorithm/key rotation requires a code redeploy",
            description:
              "If rotation cannot happen operationally, an emergency primitive replacement is gated on a full release cycle.",
            remediation:
              "Support rotation through configuration and key references so it can be executed without shipping code.",
            cwe: ["CWE-320"],
            references: REFS,
            evidence: "rotation_without_redeploy=false",
            tags: ["agility"],
          },
          input.filename,
        ),
      );
    }
  }

  return findings;
}
