// Insecure randomness auditor (altais_audit_randomness).
//
// Pattern-matches source for non-cryptographic PRNGs. Where a weak PRNG
// appears near a security-sensitive keyword (token, password, key, ...),
// the finding is escalated.

import type { Finding } from "../../core/types.js";
import { buildCryptoFinding, lineAt } from "./finding.js";

export interface RandomnessAuditInput {
  readonly source: string;
  readonly filename?: string;
}

const REFS = [
  "https://cwe.mitre.org/data/definitions/338.html",
  "https://owasp.org/www-community/vulnerabilities/Insecure_Randomness",
];

const SECURITY_CONTEXT_RE =
  /\b(?:token|secret|password|passwd|nonce|salt|api[_-]?key|session|csrf|otp|cookie|private[_-]?key|iv|seed|uuid|guid|reset)\b/i;
const CONTEXT_WINDOW = 120;

interface WeakRng {
  readonly rule: string;
  readonly regex: RegExp;
  readonly base: Finding["severity"];
  readonly title: string;
  readonly description: string;
  readonly remediation: string;
}

const WEAK_RNGS: readonly WeakRng[] = [
  {
    rule: "random-math-random",
    regex: /\bMath\.random\s*\(/g,
    base: "low",
    title: "`Math.random()` is not cryptographically secure",
    description:
      "`Math.random()` is a fast, predictable PRNG (typically xorshift128+). Its output can be reconstructed from a few samples.",
    remediation:
      "For security values use `crypto.getRandomValues()` (browser) or `crypto.randomBytes()` / `crypto.randomUUID()` (Node).",
  },
  {
    rule: "random-python-random",
    regex:
      /\brandom\.(?:random|randint|randrange|choice|choices|getrandbits|sample|shuffle|uniform)\s*\(/g,
    base: "low",
    title: "Python `random` module is not cryptographically secure",
    description:
      "The `random` module uses a Mersenne Twister, whose internal state is fully recoverable from 624 outputs.",
    remediation:
      "Use the `secrets` module (`secrets.token_hex`, `secrets.choice`) or `os.urandom()` for security values.",
  },
  {
    rule: "random-java-util-random",
    regex: /\bnew\s+(?:java\.util\.)?Random\s*\(/g,
    base: "low",
    title: "`java.util.Random` is not cryptographically secure",
    description:
      "`java.util.Random` is a 48-bit linear congruential generator; its sequence is trivially predictable.",
    remediation: "Use `java.security.SecureRandom`.",
  },
  {
    rule: "random-go-math-rand",
    regex: /\bmath\/rand\b|\brand\.(?:Intn?|Int31|Int63|Float64|Perm|Read)\s*\(/g,
    base: "low",
    title: "Go `math/rand` is not cryptographically secure",
    description: "`math/rand` is a deterministic PRNG seeded from a single int64.",
    remediation: "Use `crypto/rand` for security-sensitive values.",
  },
  {
    rule: "random-c-rand-srand",
    regex: /\b(?:srand|rand)\s*\(|\bmt19937\b/g,
    base: "low",
    title: "C/C++ `rand()` / `mt19937` is not cryptographically secure",
    description:
      "`rand()` and the Mersenne Twister are predictable PRNGs unsuitable for security values.",
    remediation:
      "Use a CSPRNG: `getrandom(2)` / `/dev/urandom`, or `std::random_device` backed by an OS source.",
  },
  {
    rule: "random-time-seed",
    regex: /\b(?:srand|seed|Random)\s*\(\s*(?:time\s*\(|Date\.now\s*\(|System\.currentTimeMillis)/g,
    base: "medium",
    title: "PRNG seeded from the current time",
    description:
      "Seeding a PRNG with the current time makes its entire output stream predictable to anyone who can estimate the seed time.",
    remediation: "Do not seed a CSPRNG manually; use the OS entropy source directly.",
  },
];

function hasSecurityContext(source: string, start: number, end: number): boolean {
  const before = source.slice(Math.max(0, start - CONTEXT_WINDOW), start);
  const after = source.slice(end, end + CONTEXT_WINDOW);
  return SECURITY_CONTEXT_RE.test(before) || SECURITY_CONTEXT_RE.test(after);
}

export function auditRandomness(input: RandomnessAuditInput): readonly Finding[] {
  const findings: Finding[] = [];
  const source = input.source;
  if (source.length === 0) return findings;

  for (const rng of WEAK_RNGS) {
    const regex = new RegExp(rng.regex.source, "g");
    let m: RegExpExecArray | null;
    while ((m = regex.exec(source)) !== null) {
      const end = m.index + m[0].length;
      const sensitive = hasSecurityContext(source, m.index, end);
      findings.push(
        buildCryptoFinding(
          {
            rule: sensitive ? `${rng.rule}-security-context` : rng.rule,
            severity: sensitive ? "high" : rng.base,
            title: sensitive ? `${rng.title} — used in a security-sensitive context` : rng.title,
            description: sensitive
              ? `${rng.description} A nearby security keyword (token / key / secret / ...) suggests this value protects something — a predictable value here is directly exploitable.`
              : `${rng.description} If this value is only used for non-security purposes (jitter, sampling, UI), it is acceptable.`,
            remediation: rng.remediation,
            cwe: sensitive ? ["CWE-338", "CWE-330"] : ["CWE-330"],
            references: REFS,
            evidence: m[0].slice(0, 200),
            tags: ["randomness"],
            line: lineAt(source, m.index),
          },
          input.filename,
        ),
      );
      if (m[0].length === 0) regex.lastIndex += 1;
    }
  }
  return findings;
}
