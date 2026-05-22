// altais_audit_pooling — connection-pool configuration audit.
//
// Reviews pool-size bounds, idle / connection / lifetime timeouts, leak
// detection, TLS enforcement in the pool, and inline credentials.

import { z } from "zod";
import type { Finding } from "../../core/types.js";
import { type ConfigCheck, runConfigChecks } from "./finding.js";

const REFS = [
  "https://cwe.mitre.org/data/definitions/770.html",
  "https://cheatsheetseries.owasp.org/cheatsheets/Database_Security_Cheat_Sheet.html",
];

export const poolingSchema = z.object({
  config: z.object({
    pool_size_limited: z
      .boolean()
      .optional()
      .describe("Whether the pool has an explicit maximum-size limit."),
    max_pool_size: z
      .number()
      .int()
      .min(0)
      .max(100000)
      .optional()
      .describe("The configured maximum pool size, if known."),
    idle_timeout_set: z
      .boolean()
      .optional()
      .describe("Whether an idle-connection timeout is configured."),
    connection_timeout_set: z
      .boolean()
      .optional()
      .describe("Whether an acquire / connection timeout is configured."),
    max_lifetime_set: z
      .boolean()
      .optional()
      .describe("Whether a maximum connection lifetime is configured."),
    leak_detection_enabled: z
      .boolean()
      .optional()
      .describe("Whether connection-leak detection is enabled."),
    ssl_enforced: z
      .boolean()
      .optional()
      .describe("Whether the pool configuration enforces TLS on every connection."),
    credentials_inline: z
      .boolean()
      .optional()
      .describe("Whether database credentials are hard-coded in the pool configuration."),
  }),
  filename: z
    .string()
    .min(1)
    .max(512)
    .optional()
    .describe("Optional filename used for the finding location."),
});

export type PoolingInput = z.infer<typeof poolingSchema>;
type PoolingConfig = PoolingInput["config"];

const CHECKS: readonly ConfigCheck<PoolingConfig>[] = [
  {
    rule: "pool-size-unbounded",
    when: (c) => c.pool_size_limited === false,
    severity: "high",
    title: "Connection pool has no maximum-size limit",
    description:
      "An unbounded pool opens new connections under load until the database hits its own connection limit. The database then refuses connections for every application, turning a traffic spike into an outage.",
    remediation:
      "Set an explicit maximum pool size, sized to the database's connection budget divided across application instances.",
    cwe: ["CWE-770"],
  },
  {
    rule: "pool-size-excessive",
    when: (c) => c.max_pool_size !== undefined && c.max_pool_size > 200,
    severity: "medium",
    title: "Connection pool maximum size is very large",
    description:
      "A very large per-instance pool multiplies across instances and can exhaust the database's global connection limit, and most workloads see no throughput gain past a modest pool size.",
    remediation:
      "Right-size the pool (often 10-30 per instance) against the database's max connections and the number of application instances; measure rather than over-provision.",
    cwe: ["CWE-770"],
  },
  {
    rule: "pool-no-idle-timeout",
    when: (c) => c.idle_timeout_set === false,
    severity: "medium",
    title: "Connection pool has no idle timeout",
    description:
      "Without an idle timeout, connections are never reclaimed once unused, holding database resources and masking connection leaks.",
    remediation:
      "Configure an idle timeout so idle connections are closed and returned to the database after a bounded period.",
    cwe: ["CWE-770"],
  },
  {
    rule: "pool-no-connection-timeout",
    when: (c) => c.connection_timeout_set === false,
    severity: "medium",
    title: "Connection pool has no acquire / connection timeout",
    description:
      "With no acquire timeout, a request that cannot get a connection blocks indefinitely instead of failing fast. Under pool exhaustion this stacks up requests and threads and degrades the whole service.",
    remediation:
      "Set a connection-acquire timeout so a request fails fast (and can shed load or retry) when the pool is exhausted.",
    cwe: ["CWE-400"],
  },
  {
    rule: "pool-no-max-lifetime",
    when: (c) => c.max_lifetime_set === false,
    severity: "low",
    title: "Connection pool has no maximum connection lifetime",
    description:
      "Without a maximum lifetime, pooled connections live indefinitely and can become stale after a database failover, a DNS change, or a credential rotation.",
    remediation:
      "Set a maximum connection lifetime (shorter than any database- or proxy-side idle limit) so connections are recycled regularly.",
  },
  {
    rule: "pool-no-leak-detection",
    when: (c) => c.leak_detection_enabled === false,
    severity: "low",
    title: "Connection pool leak detection is disabled",
    description:
      "Without leak detection, a code path that borrows a connection and never returns it drains the pool silently until it is exhausted.",
    remediation:
      "Enable the pool's leak-detection threshold so connections held longer than expected are logged with a stack trace.",
  },
  {
    rule: "pool-ssl-not-enforced",
    when: (c) => c.ssl_enforced === false,
    severity: "high",
    title: "Connection pool does not enforce TLS",
    description:
      "If the pool configuration does not require TLS, pooled connections may be established unencrypted, exposing credentials and query data on the network.",
    remediation:
      "Set the pool's SSL/TLS options to require verified TLS for every connection it opens (e.g. `ssl: { rejectUnauthorized: true }`, `sslmode=verify-full`).",
    cwe: ["CWE-319"],
  },
  {
    rule: "pool-credentials-inline",
    when: (c) => c.credentials_inline === true,
    severity: "high",
    title: "Database credentials are hard-coded in the pool configuration",
    description:
      "Credentials embedded directly in the pool configuration end up in source control and deployment artifacts, where they are widely exposed and hard to rotate.",
    remediation:
      "Load credentials at startup from environment variables or a secret manager; keep no password literal in the pool configuration.",
    cwe: ["CWE-798"],
  },
];

/** Audit a database connection-pool configuration. */
export function auditPooling(input: PoolingInput): readonly Finding[] {
  return runConfigChecks(input.config, CHECKS, REFS, input.filename);
}
