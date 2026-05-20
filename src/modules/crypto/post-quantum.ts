// Post-quantum readiness assessor (altais_assess_pq_readiness).
//
// Flags classical asymmetric primitives that a cryptographically relevant
// quantum computer (CRQC) would break via Shor's algorithm, and assesses
// the "harvest now, decrypt later" exposure of long-lived secrets.

import type { Finding } from "../../core/types.js";
import { buildCryptoFinding, lineAt } from "./finding.js";

export interface PqReadinessConfig {
  /** Asymmetric algorithms in use (e.g. ["RSA-2048", "ECDH-P256"]). */
  readonly algorithms?: readonly string[];
  /** Years that data encrypted today must stay confidential. */
  readonly data_retention_years?: number;
  /** Whether a hybrid (classical + PQC) key exchange is deployed. */
  readonly uses_hybrid?: boolean;
}

export interface PqReadinessInput {
  readonly source?: string;
  readonly config?: PqReadinessConfig;
  readonly filename?: string;
}

const REFS = [
  "https://csrc.nist.gov/projects/post-quantum-cryptography",
  "https://csrc.nist.gov/pubs/fips/203/final",
  "https://csrc.nist.gov/pubs/fips/204/final",
];

// Quantum-vulnerable classical asymmetric primitives. The `(?<!ML-)` /
// `(?<!SLH-)` guards stop the bare `DSA` token from matching the PQC
// signature schemes ML-DSA and SLH-DSA.
const QUANTUM_VULNERABLE_RE =
  /(?<!ML-)(?<!SLH-)\b(?:RSA|DSA|ECDSA|ECDH|ECDHE|ECIES|ElGamal|Diffie[- ]?Hellman|DHE?|X25519|X448|Ed25519|Ed448|Curve25519|secp256[rk]1|secp384r1|prime256v1|nistp\d+)\b/i;

// NIST-standardized PQC primitives.
const PQC_RE =
  /\b(?:ML-?KEM|ML-?DSA|SLH-?DSA|Kyber|Dilithium|SPHINCS\+?|FALCON|FIPS-?20[345]|Classic McEliece|FrodoKEM|BIKE|HQC)\b/i;

export function assessPqReadiness(input: PqReadinessInput): readonly Finding[] {
  const findings: Finding[] = [];
  let classicalSeen = false;
  let pqcSeen = false;

  if (input.source) {
    const src = input.source;
    const vulnRe = new RegExp(QUANTUM_VULNERABLE_RE.source, "gi");
    let m: RegExpExecArray | null;
    while ((m = vulnRe.exec(src)) !== null) {
      classicalSeen = true;
      findings.push(
        buildCryptoFinding(
          {
            rule: "pq-quantum-vulnerable-algorithm",
            severity: "medium",
            title: `Quantum-vulnerable algorithm in use: ${m[0]}`,
            description:
              "RSA, finite-field/elliptic-curve Diffie-Hellman, and (EC)DSA are broken by Shor's algorithm on a cryptographically relevant quantum computer. Signatures lose authenticity once a CRQC exists; key exchanges are exposed retroactively.",
            remediation:
              "Plan migration to NIST PQC standards: ML-KEM (FIPS 203) for key establishment, ML-DSA (FIPS 204) / SLH-DSA (FIPS 205) for signatures. Deploy hybrid (classical + PQC) during transition.",
            cwe: ["CWE-327"],
            references: REFS,
            evidence: m[0],
            tags: ["post-quantum"],
            line: lineAt(src, m.index),
          },
          input.filename,
        ),
      );
      if (m[0].length === 0) vulnRe.lastIndex += 1;
    }
    if (PQC_RE.test(src)) pqcSeen = true;
  }

  if (input.config) {
    const c = input.config;
    for (const algo of c.algorithms ?? []) {
      if (QUANTUM_VULNERABLE_RE.test(algo)) {
        classicalSeen = true;
        findings.push(
          buildCryptoFinding(
            {
              rule: "pq-quantum-vulnerable-algorithm",
              severity: "medium",
              title: `Quantum-vulnerable algorithm in inventory: ${algo}`,
              description:
                "This classical asymmetric algorithm is broken by Shor's algorithm once a CRQC is available.",
              remediation:
                "Migrate to ML-KEM / ML-DSA / SLH-DSA; deploy hybrid key exchange during the transition.",
              cwe: ["CWE-327"],
              references: REFS,
              evidence: algo,
              tags: ["post-quantum"],
            },
            input.filename,
          ),
        );
      }
      if (PQC_RE.test(algo)) pqcSeen = true;
    }

    const retention = c.data_retention_years;
    if (classicalSeen && retention !== undefined && retention >= 5 && c.uses_hybrid !== true) {
      findings.push(
        buildCryptoFinding(
          {
            rule: "pq-harvest-now-decrypt-later",
            severity: "high",
            title: `"Harvest now, decrypt later" exposure: ${retention}y retention with classical key exchange`,
            description:
              "Traffic encrypted today with classical key exchange can be recorded now and decrypted once a CRQC exists. Data that must stay confidential beyond the CRQC horizon is already at risk.",
            remediation:
              "Deploy hybrid key exchange (e.g. X25519+ML-KEM) immediately for any data with a multi-year confidentiality requirement.",
            cwe: ["CWE-327"],
            references: REFS,
            evidence: `data_retention_years=${retention}, uses_hybrid=${c.uses_hybrid ?? false}`,
            tags: ["post-quantum"],
          },
          input.filename,
        ),
      );
    }

    if (classicalSeen && c.uses_hybrid === false) {
      findings.push(
        buildCryptoFinding(
          {
            rule: "pq-no-hybrid-key-exchange",
            severity: "medium",
            title: "No hybrid (classical + PQC) key exchange deployed",
            description:
              "Hybrid key exchange combines a classical and a PQC KEM so the connection stays secure if either is broken. It is the recommended transitional posture.",
            remediation:
              "Enable a hybrid group such as X25519MLKEM768 on TLS endpoints and equivalent constructions elsewhere.",
            cwe: ["CWE-327"],
            references: REFS,
            evidence: "uses_hybrid=false",
            tags: ["post-quantum"],
          },
          input.filename,
        ),
      );
    }
  }

  if (classicalSeen && !pqcSeen) {
    findings.push(
      buildCryptoFinding(
        {
          rule: "pq-no-pqc-algorithm-detected",
          severity: "info",
          title: "No post-quantum algorithm detected",
          description:
            "Classical asymmetric crypto is in use but no NIST PQC primitive (ML-KEM / ML-DSA / SLH-DSA) was found. This is informational — track it in a migration roadmap.",
          remediation:
            "Build a cryptographic inventory (CBOM) and a prioritized PQC migration plan; start with long-lived data and root signing keys.",
          cwe: ["CWE-327"],
          references: REFS,
          tags: ["post-quantum"],
        },
        input.filename,
      ),
    );
  }

  return findings;
}
