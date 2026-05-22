// altais_audit_db_tls — database-specific TLS / SSL configuration audit.
//
// Reviews whether TLS is enabled, the minimum protocol version, server
// certificate verification, cipher-suite strength, self-signed
// certificates, certificate expiry, and mutual TLS.

import { z } from "zod";
import type { Finding } from "../../core/types.js";
import { type ConfigCheck, runConfigChecks } from "./finding.js";

const REFS = [
  "https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Security_Cheat_Sheet.html",
  "https://cheatsheetseries.owasp.org/cheatsheets/Database_Security_Cheat_Sheet.html",
];

export const dbTlsSchema = z.object({
  config: z.object({
    tls_enabled: z
      .boolean()
      .optional()
      .describe("Whether TLS is enabled for database connections."),
    min_protocol_version: z
      .enum(["1.0", "1.1", "1.2", "1.3"])
      .optional()
      .describe("The minimum negotiated TLS protocol version."),
    certificate_verification: z
      .enum(["full", "required", "none"])
      .optional()
      .describe(
        "Server-certificate verification level (`full` = hostname + chain, `none` = not verified).",
      ),
    weak_cipher_suites_allowed: z
      .boolean()
      .optional()
      .describe("Whether weak or legacy cipher suites are permitted."),
    self_signed_certificate: z
      .boolean()
      .optional()
      .describe("Whether the server presents a self-signed certificate."),
    certificate_expired_or_expiring: z
      .boolean()
      .optional()
      .describe("Whether the server certificate is expired or close to expiry."),
    mutual_tls_enabled: z
      .boolean()
      .optional()
      .describe("Whether mutual TLS (client-certificate authentication) is in use."),
  }),
  filename: z
    .string()
    .min(1)
    .max(512)
    .optional()
    .describe("Optional filename used for the finding location."),
});

export type DbTlsInput = z.infer<typeof dbTlsSchema>;
type DbTlsConfig = DbTlsInput["config"];

const CHECKS: readonly ConfigCheck<DbTlsConfig>[] = [
  {
    rule: "db-tls-disabled",
    when: (c) => c.tls_enabled === false,
    severity: "critical",
    title: "Database TLS is disabled",
    description:
      "With TLS off, the authentication handshake, query text, and result data all cross the network in cleartext, where they can be read or modified by anyone on the path.",
    remediation:
      "Enable TLS on the database server with a trusted certificate and require it for every non-local connection.",
    cwe: ["CWE-319"],
  },
  {
    rule: "db-tls-weak-protocol",
    when: (c) => c.min_protocol_version === "1.0" || c.min_protocol_version === "1.1",
    severity: "high",
    title: "Database permits a deprecated TLS protocol version",
    description:
      "TLS 1.0 and 1.1 are deprecated and have known weaknesses. Allowing them lets a network attacker downgrade the connection to a breakable protocol.",
    remediation:
      "Set the minimum TLS version to 1.2, and prefer 1.3 where both the server and driver support it.",
    cwe: ["CWE-326"],
  },
  {
    rule: "db-tls-no-cert-verification",
    when: (c) => c.certificate_verification === "none",
    severity: "high",
    title: "Database TLS does not verify the server certificate",
    description:
      "Encryption without certificate verification stops passive eavesdropping but not an active attacker: anyone who can intercept the connection can present their own certificate and machine-in-the-middle it.",
    remediation:
      "Verify the server certificate against a trusted CA and check the hostname (`sslmode=verify-full`, `rejectUnauthorized: true`). Never disable verification to silence a certificate error.",
    cwe: ["CWE-295"],
  },
  {
    rule: "db-tls-weak-ciphers",
    when: (c) => c.weak_cipher_suites_allowed === true,
    severity: "medium",
    title: "Database TLS permits weak cipher suites",
    description:
      "Legacy cipher suites (RC4, 3DES, export-grade, non-forward-secret RSA key exchange) are weak. Allowing them gives a downgrade attacker a breakable option.",
    remediation:
      "Restrict the cipher list to strong AEAD suites with forward secrecy (ECDHE + AES-GCM / ChaCha20-Poly1305) and disable legacy ciphers.",
    cwe: ["CWE-327"],
  },
  {
    rule: "db-tls-self-signed-certificate",
    when: (c) => c.self_signed_certificate === true,
    severity: "medium",
    title: "Database server uses a self-signed certificate",
    description:
      "A self-signed certificate cannot be validated against a trusted CA, so clients tend to disable verification entirely — which removes the protection against an active machine-in-the-middle attacker.",
    remediation:
      "Issue the database certificate from an internal or public CA that clients trust, so verification can stay enabled. Distribute the internal CA root to clients rather than turning verification off.",
    cwe: ["CWE-295"],
  },
  {
    rule: "db-tls-certificate-expiring",
    when: (c) => c.certificate_expired_or_expiring === true,
    severity: "medium",
    title: "Database server certificate is expired or expiring",
    description:
      "An expired certificate breaks connections for clients that verify it — and pressures operators to disable verification as a quick fix, which removes machine-in-the-middle protection.",
    remediation:
      "Renew the certificate before expiry and automate renewal (and reload) so it never lapses.",
  },
  {
    rule: "db-tls-no-mutual-tls",
    when: (c) => c.mutual_tls_enabled === false,
    severity: "low",
    title: "Database does not use mutual TLS",
    description:
      "Without mutual TLS the database authenticates to the client but not the reverse, so a stolen password is the only thing standing between an attacker and a connection.",
    remediation:
      "For service-to-service database access, consider client-certificate authentication (mutual TLS) so a connection requires both a valid credential and a provisioned client certificate.",
  },
];

/** Audit a database's TLS / SSL configuration. */
export function auditDbTls(input: DbTlsInput): readonly Finding[] {
  return runConfigChecks(input.config, CHECKS, REFS, input.filename);
}
