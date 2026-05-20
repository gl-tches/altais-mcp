// Webhook signature-verification auditor (altais_check_webhook).
//
// Accepts webhook-handler source code and/or a structured description of
// the webhook verification posture. Checks for the failure modes that let
// an attacker forge or replay inbound webhook deliveries: no signature
// check, timing-unsafe signature comparison, weak hash algorithms, no
// timestamp / replay protection, and hardcoded signing secrets.

import type { Finding } from "../../core/types.js";
import { buildProtocolFinding, scanWithPatterns, type SourcePattern } from "./finding.js";

export interface WebhookAuditConfig {
  readonly signature_verified?: boolean;
  readonly hash_algorithm?: string;
  readonly constant_time_comparison?: boolean;
  readonly timestamp_validation?: boolean;
  readonly replay_protection?: boolean;
  readonly secret_source?: "env" | "secrets_manager" | "config_file" | "hardcoded";
}

export interface WebhookAuditInput {
  readonly source?: string;
  readonly config?: WebhookAuditConfig;
  readonly filename?: string;
}

const REFS = [
  "https://cwe.mitre.org/data/definitions/347.html",
  "https://owasp.org/www-community/Webhook_security",
  "https://datatracker.ietf.org/doc/html/rfc9421",
];

const WEAK_HASH_RE = /\b(?:md5|sha-?1|md4|md2)\b/i;

const SOURCE_PATTERNS: readonly SourcePattern[] = [
  {
    rule: "webhook-non-constant-time-compare",
    regex:
      /(?:signature|sig|hmac|digest|expected[_a-z]*)\s*(?:===?|!==?)\s*(?:[A-Za-z_$][\w$.]*|["'`])/i,
    severity: "high",
    title: "Webhook signature compared with a non-constant-time operator",
    description:
      "Comparing an HMAC signature with `==`, `===`, `!=`, or `!==` short-circuits on the first differing byte. The measurable timing difference lets an attacker recover a valid signature byte-by-byte and forge requests.",
    remediation:
      "Compare signatures with a constant-time function: `crypto.timingSafeEqual` (Node), `hmac.compare_digest` (Python), `subtle.ConstantTimeCompare` (Go).",
    cwe: ["CWE-208", "CWE-347"],
    tags: ["webhook", "timing"],
  },
  {
    rule: "webhook-weak-hash-algorithm",
    regex: /createHmac\s*\(\s*["'`](?:md5|sha1)["'`]|hmac\.new\([^)]*hashlib\.(?:md5|sha1)/i,
    severity: "high",
    title: "Webhook HMAC uses a weak hash algorithm",
    description:
      "An HMAC built on MD5 or SHA-1 inherits those hashes' broken collision and length-extension weaknesses, undermining the signature's integrity guarantee.",
    remediation: "Use HMAC-SHA-256 or stronger for webhook signatures.",
    cwe: ["CWE-328", "CWE-347"],
    tags: ["webhook", "hash"],
  },
  {
    rule: "webhook-hardcoded-secret",
    regex:
      /(?:webhook|signing|hmac)[_a-z]*(?:secret|key|token)\s*[:=]\s*["'`][A-Za-z0-9_\-+/=]{8,}["'`]/i,
    severity: "high",
    title: "Webhook signing secret is hardcoded in source",
    description:
      "A signing secret committed to source code is exposed to anyone with repository access and ends up in version-control history. An attacker with the secret can forge valid webhook deliveries.",
    remediation:
      "Load the webhook secret from an environment variable or a secrets manager; rotate any secret that has been committed.",
    cwe: ["CWE-798"],
    tags: ["webhook", "secret"],
  },
];

function mk(
  filename: string | undefined,
  rule: string,
  severity: Finding["severity"],
  title: string,
  description: string,
  remediation: string,
  cwe: readonly string[],
  evidence: string,
  tags: readonly string[],
): Finding {
  return buildProtocolFinding(
    {
      rule,
      severity,
      title,
      description,
      remediation,
      cwe,
      references: REFS,
      evidence,
      tags: ["webhook", ...tags],
    },
    filename,
  );
}

function auditConfig(c: WebhookAuditConfig, file: string | undefined): readonly Finding[] {
  const findings: Finding[] = [];

  if (c.signature_verified === false) {
    findings.push(
      mk(
        file,
        "webhook-no-signature-verification",
        "critical",
        "Webhook payloads are accepted without signature verification",
        "An endpoint that does not verify the provider's signature accepts any HTTP request that reaches it. An attacker can post forged payloads to trigger arbitrary application logic.",
        "Verify the provider's HMAC signature header on every delivery before processing the payload, and reject requests that fail verification.",
        ["CWE-345", "CWE-347"],
        "signature_verified=false",
        ["signature"],
      ),
    );
  }

  if (c.signature_verified !== false && c.constant_time_comparison === false) {
    findings.push(
      mk(
        file,
        "webhook-non-constant-time-compare",
        "high",
        "Webhook signature is compared in non-constant time",
        "A byte-by-byte signature comparison leaks, through response timing, how many leading bytes matched. An attacker can iteratively recover a valid signature and forge requests.",
        "Use a constant-time comparison (`crypto.timingSafeEqual`, `hmac.compare_digest`, `subtle.ConstantTimeCompare`).",
        ["CWE-208", "CWE-347"],
        "constant_time_comparison=false",
        ["timing"],
      ),
    );
  }

  if (c.hash_algorithm !== undefined && WEAK_HASH_RE.test(c.hash_algorithm)) {
    findings.push(
      mk(
        file,
        "webhook-weak-hash-algorithm",
        "high",
        `Webhook signatures use a weak hash algorithm: ${c.hash_algorithm}`,
        "MD5 and SHA-1 are collision-broken; an HMAC built on them no longer provides a dependable integrity guarantee.",
        "Switch the webhook signature scheme to HMAC-SHA-256 or stronger.",
        ["CWE-328", "CWE-347"],
        `hash_algorithm=${c.hash_algorithm}`,
        ["hash"],
      ),
    );
  }

  if (c.timestamp_validation === false) {
    findings.push(
      mk(
        file,
        "webhook-no-timestamp-validation",
        "medium",
        "Webhook deliveries are not checked against a timestamp",
        "Without validating a signed timestamp header, an old but correctly signed delivery stays valid forever. A captured request can be replayed long after it was issued.",
        "Include the timestamp in the signed payload and reject deliveries whose timestamp is outside a short tolerance window (e.g. 5 minutes).",
        ["CWE-294"],
        "timestamp_validation=false",
        ["replay"],
      ),
    );
  }

  if (c.replay_protection === false) {
    findings.push(
      mk(
        file,
        "webhook-no-replay-protection",
        "medium",
        "Webhook handler has no replay protection",
        "A correctly signed delivery can be re-sent and reprocessed. Without idempotency or delivery-ID de-duplication, replays can double-charge, double-provision, or duplicate side effects.",
        "Track processed delivery IDs (or a nonce) and reject a delivery that has already been handled.",
        ["CWE-294"],
        "replay_protection=false",
        ["replay"],
      ),
    );
  }

  if (c.secret_source === "hardcoded") {
    findings.push(
      mk(
        file,
        "webhook-hardcoded-secret",
        "high",
        "Webhook signing secret is sourced from hardcoded code",
        "A signing secret embedded in source code is readable by anyone with repository access and is preserved in version-control history. Knowledge of the secret allows forging valid deliveries.",
        "Load the secret from an environment variable or a secrets manager and rotate the exposed value.",
        ["CWE-798"],
        "secret_source=hardcoded",
        ["secret"],
      ),
    );
  }

  return findings;
}

export function checkWebhook(input: WebhookAuditInput): readonly Finding[] {
  const findings: Finding[] = [];
  if (input.source !== undefined) {
    findings.push(...scanWithPatterns(input.source, SOURCE_PATTERNS, REFS, input.filename));
  }
  if (input.config !== undefined) {
    findings.push(...auditConfig(input.config, input.filename));
  }
  return findings;
}
