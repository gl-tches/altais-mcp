// altais_audit_redis — Redis / Memcached configuration audit.
//
// Reviews authentication, protected mode, network binding, ACLs,
// dangerous-command exposure, transport security, and password strength.

import { z } from "zod";
import type { Finding } from "../../core/types.js";
import { type ConfigCheck, runConfigChecks } from "./finding.js";

const REFS = [
  "https://cheatsheetseries.owasp.org/cheatsheets/Database_Security_Cheat_Sheet.html",
  "https://redis.io/docs/latest/operate/oss_and_stack/management/security/",
];

export const redisSchema = z.object({
  config: z.object({
    requirepass_set: z
      .boolean()
      .optional()
      .describe("Whether a password (requirepass) or ACL credential is configured."),
    protected_mode: z.boolean().optional().describe("Whether protected-mode is enabled."),
    bind: z
      .string()
      .max(256)
      .optional()
      .describe("The bind directive value (e.g. `127.0.0.1`, `0.0.0.0`)."),
    acl_enabled: z
      .boolean()
      .optional()
      .describe("Whether per-user ACL rules are configured (vs a single shared password)."),
    dangerous_commands_disabled: z
      .boolean()
      .optional()
      .describe(
        "Whether dangerous commands (FLUSHALL, CONFIG, DEBUG, KEYS, SHUTDOWN) are renamed or disabled.",
      ),
    tls_enabled: z.boolean().optional().describe("Whether TLS (the tls-port) is enabled."),
    weak_password: z
      .boolean()
      .optional()
      .describe("Whether the configured password is short, default, or low-entropy."),
  }),
  filename: z
    .string()
    .min(1)
    .max(512)
    .optional()
    .describe("Optional filename used for the finding location."),
});

export type RedisInput = z.infer<typeof redisSchema>;
type RedisConfig = RedisInput["config"];

const CHECKS: readonly ConfigCheck<RedisConfig>[] = [
  {
    rule: "redis-no-authentication",
    when: (c) => c.requirepass_set === false,
    severity: "critical",
    title: "Redis has no authentication configured",
    description:
      "With no `requirepass` and no ACL user, any client that reaches the port has full command access — including reading every key and running `FLUSHALL` or `CONFIG`.",
    remediation:
      "Configure a strong `requirepass`, or define per-user ACLs with `requirepass` disabled in favor of named users. Never run Redis unauthenticated.",
    cwe: ["CWE-306"],
  },
  {
    rule: "redis-protected-mode-off",
    when: (c) => c.protected_mode === false,
    severity: "high",
    title: "Redis protected-mode is disabled",
    description:
      "Protected-mode is the safety net that refuses external connections when Redis is unauthenticated and bound broadly. Disabling it removes that backstop.",
    remediation:
      "Set `protected-mode yes`. Disable it only when authentication and a firewall are both verified to be in place.",
    cwe: ["CWE-284"],
  },
  {
    rule: "redis-bind-all-interfaces",
    when: (c) => c.bind === "0.0.0.0" || c.bind === "*" || c.bind === "",
    severity: "high",
    title: "Redis binds to all network interfaces",
    description:
      "Binding Redis to `0.0.0.0` exposes it on every interface. Unauthenticated, internet-exposed Redis instances are routinely scanned and wiped or used for crypto-mining.",
    remediation:
      "Bind to `127.0.0.1` and the specific private address the application uses, and restrict the port with a firewall.",
    cwe: ["CWE-1327"],
  },
  {
    rule: "redis-no-acl",
    when: (c) => c.acl_enabled === false,
    severity: "medium",
    title: "Redis uses a single shared password instead of ACLs",
    description:
      "A single `requirepass` grants every client every command. There is no way to limit an application to the keys and commands it actually needs, and no per-client accountability.",
    remediation:
      "Define per-application ACL users (`ACL SETUSER`) scoped to specific key patterns and command categories, and disable the shared `default` user.",
    cwe: ["CWE-272"],
  },
  {
    rule: "redis-dangerous-commands-exposed",
    when: (c) => c.dangerous_commands_disabled === false,
    severity: "medium",
    title: "Redis dangerous commands are not restricted",
    description:
      "Commands such as `FLUSHALL`, `FLUSHDB`, `CONFIG`, `DEBUG`, `KEYS`, and `SHUTDOWN` allow data destruction, runtime reconfiguration, or denial of service. Leaving them available to the application user widens the blast radius of any compromise.",
    remediation:
      'Disable or rename destructive commands (`rename-command FLUSHALL ""`) or, with ACLs, remove the `@dangerous` and `@admin` categories from the application user.',
    cwe: ["CWE-250"],
  },
  {
    rule: "redis-tls-disabled",
    when: (c) => c.tls_enabled === false,
    severity: "high",
    title: "Redis TLS is disabled",
    description:
      "Without the TLS port, the password and all key data travel in cleartext and can be captured on the network.",
    remediation:
      "Enable `tls-port` with server certificates, disable the plaintext `port` (`port 0`), and connect clients with `rediss://` and certificate verification.",
    cwe: ["CWE-319"],
  },
  {
    rule: "redis-weak-password",
    when: (c) => c.weak_password === true,
    severity: "high",
    title: "Redis password is weak or default",
    description:
      "Redis can process a very high rate of `AUTH` attempts, so a short or low-entropy password is brute-forceable in a practical amount of time.",
    remediation:
      "Use a long, random password (32+ characters from a CSPRNG) supplied from a secret manager, and rotate it on any suspected exposure.",
    cwe: ["CWE-521"],
  },
];

/** Audit a Redis / Memcached configuration. */
export function auditRedis(input: RedisInput): readonly Finding[] {
  return runConfigChecks(input.config, CHECKS, REFS, input.filename);
}
