// Password-hashing auditor.

import type { Finding } from "../../core/types.js";
import { buildAuthFinding, lineAt } from "./finding.js";

export interface PasswordAuditInput {
  readonly source?: string;
  readonly filename?: string;
}

const REFS = [
  "https://owasp.org/www-project-cheat-sheets/cheatsheets/Password_Storage_Cheat_Sheet.html",
  "https://datatracker.ietf.org/doc/html/rfc9106",
];

const WEAK_HASH_REGEX =
  /\b(?:crypto\.createHash|hashlib\.new|MessageDigest\.getInstance)\s*\(\s*["'](md5|sha-?1|sha\d+)["']/i;

const PASSWORD_KEYWORD_RE = /\b(?:password|passwd|pwd|hash_password|hashPassword|user\.secret)\b/i;
const CONTEXT_WINDOW = 200;

const POSITIVE_PATTERNS: readonly RegExp[] = [
  /\bargon2(?:id?)?\b/i,
  /\bbcrypt(?:js)?\b/i,
  /\bscrypt(?:Sync)?\b/i,
  /from\s+passlib\.hash\s+import\s+(?:argon2|bcrypt|scrypt)/i,
];

function hasPasswordContext(source: string, matchStart: number, matchEnd: number): boolean {
  const before = source.slice(Math.max(0, matchStart - CONTEXT_WINDOW), matchStart);
  const after = source.slice(matchEnd, matchEnd + CONTEXT_WINDOW);
  return PASSWORD_KEYWORD_RE.test(before) || PASSWORD_KEYWORD_RE.test(after);
}

export function auditPasswordHashing(input: PasswordAuditInput): readonly Finding[] {
  const findings: Finding[] = [];
  const source = input.source ?? "";
  if (source.length === 0) return findings;

  let m: RegExpExecArray | null;
  const weakRegex = new RegExp(WEAK_HASH_REGEX.source, "gi");
  while ((m = weakRegex.exec(source)) !== null) {
    const hashAlg = m[1] ?? "";
    const matchEnd = m.index + m[0].length;
    const ctx = hasPasswordContext(source, m.index, matchEnd);
    if (ctx) {
      findings.push(
        buildAuthFinding(
          {
            rule: "password-weak-hash-context",
            severity: "critical",
            title: `Password hashing uses fast hash: ${hashAlg}`,
            description:
              "Fast hashes (MD5 / SHA-*) are designed for integrity, not password storage. They are too cheap to compute to resist brute force.",
            remediation:
              "Use Argon2id (parameters: m=64MiB, t=3, p=4 baseline). Bcrypt and scrypt with strong cost are also acceptable.",
            cwe: ["CWE-327", "CWE-916"],
            references: REFS,
            evidence: m[0].slice(0, 200),
            tags: ["password"],
            line: lineAt(source, m.index),
          },
          input.filename,
        ),
      );
    } else {
      findings.push(
        buildAuthFinding(
          {
            rule: "password-weak-hash-suspect",
            severity: "low",
            title: "Weak hash function in use (verify password context)",
            description:
              "A fast hash (MD5/SHA) appears in source. If it is used for password storage, this is critical; if it is used for non-secret integrity (e.g. ETags), it is fine.",
            remediation:
              "Confirm the context. For passwords, switch to Argon2id / bcrypt / scrypt.",
            cwe: ["CWE-327"],
            references: REFS,
            evidence: m[0].slice(0, 200),
            tags: ["password"],
            line: lineAt(source, m.index),
          },
          input.filename,
        ),
      );
    }
    if (m[0].length === 0) weakRegex.lastIndex += 1;
  }

  const positives = POSITIVE_PATTERNS.some((p) => p.test(source));
  if (!positives) {
    findings.push(
      buildAuthFinding(
        {
          rule: "password-no-strong-kdf-detected",
          severity: "info",
          title: "No call to a strong password KDF detected",
          description:
            "Scan did not find a reference to Argon2 / bcrypt / scrypt. This is informational — passwords may be hashed elsewhere — but worth confirming.",
          remediation:
            "Ensure passwords are hashed with Argon2id / bcrypt / scrypt at registration and on credential change.",
          cwe: ["CWE-916"],
          references: REFS,
          tags: ["password"],
        },
        input.filename,
      ),
    );
  }
  return findings;
}
