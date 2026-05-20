// Cryptographic algorithm auditor (altais_audit_crypto).
//
// Accepts:
// - source: code that calls a crypto library — pattern matched for weak
//   ciphers, deprecated hashes, ECB mode, and broken APIs
// - config: a structured inventory of algorithms in use

import type { Finding } from "../../core/types.js";
import { buildCryptoFinding, scanWithPatterns, type SourcePattern } from "./finding.js";

export interface CryptoAlgorithmEntry {
  readonly name: string;
  readonly purpose?: "hashing" | "encryption" | "signing" | "key_exchange" | "mac" | "kdf";
  readonly key_size_bits?: number;
}

export interface CryptoAuditConfig {
  readonly algorithms?: readonly CryptoAlgorithmEntry[];
}

export interface CryptoAuditInput {
  readonly source?: string;
  readonly config?: CryptoAuditConfig;
  readonly filename?: string;
}

const REFS = [
  "https://owasp.org/Top10/A02_2021-Cryptographic_Failures/",
  "https://csrc.nist.gov/pubs/sp/800/131/a/r2/final",
  "https://cwe.mitre.org/data/definitions/327.html",
];

const SOURCE_PATTERNS: readonly SourcePattern[] = [
  {
    rule: "crypto-md5",
    regex: /\b(?:createHash|hashlib\.new|MessageDigest\.getInstance)\s*\(\s*["']md-?5["']/i,
    severity: "high",
    title: "MD5 hash in use",
    description:
      "MD5 is cryptographically broken: practical collisions exist. It must not be used for integrity, signatures, or any security decision.",
    remediation:
      "Use SHA-256 / SHA-3 for integrity. For passwords, use Argon2id / bcrypt / scrypt.",
    cwe: ["CWE-327", "CWE-328"],
    tags: ["hash"],
  },
  {
    rule: "crypto-sha1",
    regex: /\b(?:createHash|hashlib\.new|MessageDigest\.getInstance)\s*\(\s*["']sha-?1["']/i,
    severity: "high",
    title: "SHA-1 hash in use",
    description:
      "SHA-1 is broken — the SHAttered and SHA-1 is a Shambles attacks produced practical collisions. It is unfit for signatures or integrity checks.",
    remediation: "Migrate to SHA-256 or SHA-3.",
    cwe: ["CWE-327", "CWE-328"],
    tags: ["hash"],
  },
  {
    rule: "crypto-md4",
    regex: /\b(?:createHash|hashlib\.new|MessageDigest\.getInstance)\s*\(\s*["']md4["']/i,
    severity: "high",
    title: "MD4 hash in use",
    description: "MD4 is comprehensively broken and far weaker than MD5.",
    remediation: "Migrate to SHA-256 or SHA-3.",
    cwe: ["CWE-327", "CWE-328"],
    tags: ["hash"],
  },
  {
    rule: "crypto-des",
    regex: /\b(?:DES|DESede|TripleDES|3DES|des-ede3|des-cbc)\b/,
    severity: "high",
    title: "DES / 3DES cipher in use",
    description:
      "Single DES has a 56-bit key (brute-forceable). 3DES is deprecated by NIST (disallowed after 2023) and vulnerable to Sweet32 birthday attacks on its 64-bit block.",
    remediation: "Use AES-256-GCM (or ChaCha20-Poly1305) for symmetric encryption.",
    cwe: ["CWE-327"],
    tags: ["cipher"],
  },
  {
    rule: "crypto-rc4",
    regex: /\b(?:RC4|ARCFOUR|rc4-\d+)\b/i,
    severity: "high",
    title: "RC4 stream cipher in use",
    description: "RC4 has known keystream biases and is prohibited by RFC 7465.",
    remediation: "Use an AEAD cipher: AES-256-GCM or ChaCha20-Poly1305.",
    cwe: ["CWE-327"],
    tags: ["cipher"],
  },
  {
    rule: "crypto-blowfish",
    regex: /\bBlowfish\b|\bbf-(?:cbc|ecb)\b/i,
    severity: "medium",
    title: "Blowfish cipher in use",
    description:
      "Blowfish has a 64-bit block and is vulnerable to Sweet32-style birthday attacks on long-lived connections.",
    remediation: "Use AES-256-GCM or ChaCha20-Poly1305.",
    cwe: ["CWE-327"],
    tags: ["cipher"],
  },
  {
    rule: "crypto-ecb-mode",
    regex: /["']?(?:aes|des)-?\d*-?ecb["']?|\bMODE_ECB\b|\bECB\b\s*mode/i,
    severity: "high",
    title: "ECB block-cipher mode in use",
    description:
      "ECB encrypts identical plaintext blocks to identical ciphertext blocks, leaking structure. It provides no semantic security.",
    remediation:
      "Use an authenticated mode: AES-GCM or AES-CBC with HMAC. Prefer AEAD (GCM / ChaCha20-Poly1305).",
    cwe: ["CWE-327", "CWE-1240"],
    tags: ["cipher", "mode"],
  },
  {
    rule: "crypto-deprecated-createcipher",
    regex: /\bcrypto\.createCipher\s*\(/,
    severity: "high",
    title: "Node `crypto.createCipher()` used",
    description:
      "`createCipher` derives the key and IV from a password using a single unsalted MD5 round, and reuses a zero IV. It is deprecated.",
    remediation:
      "Use `crypto.createCipheriv()` with a random IV and a key from a proper KDF (scrypt / HKDF / PBKDF2).",
    cwe: ["CWE-327", "CWE-329"],
    tags: ["cipher"],
  },
  {
    rule: "crypto-static-iv",
    regex: /\b(?:iv|nonce)\s*[:=]\s*(?:Buffer\.alloc\s*\(\s*\d+\s*\)|["'][^"']{2,}["'])/i,
    severity: "high",
    title: "Hardcoded / static IV or nonce",
    description:
      "A static initialization vector or nonce defeats the semantic security of CBC/CTR/GCM. For GCM, nonce reuse is catastrophic — it leaks the authentication key.",
    remediation:
      "Generate a fresh random IV/nonce per message with a CSPRNG and prepend it to the ciphertext.",
    cwe: ["CWE-329", "CWE-323"],
    tags: ["iv"],
  },
  {
    rule: "crypto-static-salt",
    regex: /\bsalt\s*[:=]\s*["'][^"']{2,}["']/i,
    severity: "medium",
    title: "Hardcoded / static salt",
    description:
      "A static salt lets attackers precompute rainbow tables and means identical inputs hash identically across users.",
    remediation: "Generate a unique random salt per hash and store it alongside the digest.",
    cwe: ["CWE-760", "CWE-759"],
    tags: ["salt"],
  },
];

const WEAK_NAMES = /^(md5|md4|sha1|sha-1|des|3des|tripledes|rc4|rc2|blowfish|md2)$/i;

function normalize(name: string): string {
  return name.toLowerCase().replace(/[\s_-]/g, "");
}

export function auditCrypto(input: CryptoAuditInput): readonly Finding[] {
  const findings: Finding[] = [];
  if (input.source) {
    findings.push(...scanWithPatterns(input.source, SOURCE_PATTERNS, REFS, input.filename));
  }
  if (input.config) findings.push(...auditConfig(input.config, input.filename));
  return findings;
}

function auditConfig(c: CryptoAuditConfig, source: string | undefined): readonly Finding[] {
  const findings: Finding[] = [];
  for (const algo of c.algorithms ?? []) {
    const norm = normalize(algo.name);
    if (WEAK_NAMES.test(algo.name.trim())) {
      findings.push(
        buildCryptoFinding(
          {
            rule: "crypto-weak-algorithm",
            severity: "high",
            title: `Weak algorithm in inventory: ${algo.name}`,
            description: `${algo.name} is cryptographically broken or deprecated and must not be used for security purposes.`,
            remediation:
              "Replace with SHA-256/SHA-3 (hashing), AES-256-GCM / ChaCha20-Poly1305 (encryption), or Ed25519 / ECDSA-P256 (signing).",
            cwe: ["CWE-327"],
            references: REFS,
            evidence: `${algo.name}${algo.purpose ? ` (${algo.purpose})` : ""}`,
          },
          source,
        ),
      );
      continue;
    }
    if (norm.startsWith("rsa") && algo.key_size_bits !== undefined && algo.key_size_bits < 2048) {
      findings.push(
        buildCryptoFinding(
          {
            rule: "crypto-rsa-key-too-small",
            severity: "high",
            title: `RSA key size below 2048 bits: ${algo.key_size_bits}`,
            description:
              "NIST disallows RSA keys under 2048 bits. 1024-bit RSA is considered factorable by well-resourced attackers.",
            remediation: "Use RSA-3072 (or RSA-2048 minimum), or migrate to Ed25519 / ECDSA-P256.",
            cwe: ["CWE-326"],
            references: REFS,
            evidence: `${algo.name}=${algo.key_size_bits}b`,
          },
          source,
        ),
      );
    }
    if (
      (norm.startsWith("aes") || algo.purpose === "encryption") &&
      algo.key_size_bits !== undefined &&
      algo.key_size_bits > 0 &&
      algo.key_size_bits < 128
    ) {
      findings.push(
        buildCryptoFinding(
          {
            rule: "crypto-symmetric-key-too-small",
            severity: "high",
            title: `Symmetric key size below 128 bits: ${algo.key_size_bits}`,
            description: "Symmetric keys shorter than 128 bits do not provide adequate strength.",
            remediation: "Use AES-256 (or AES-128 minimum).",
            cwe: ["CWE-326"],
            references: REFS,
            evidence: `${algo.name}=${algo.key_size_bits}b`,
          },
          source,
        ),
      );
    }
  }
  return findings;
}
