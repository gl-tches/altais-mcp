// altais_audit_mongodb — MongoDB configuration audit.
//
// Reviews access control, network binding, the authentication mechanism,
// transport security, journaling, the application role, and server-side
// JavaScript.

import { z } from "zod";
import type { Finding } from "../../core/types.js";
import { type ConfigCheck, runConfigChecks } from "./finding.js";

const REFS = [
  "https://cheatsheetseries.owasp.org/cheatsheets/Database_Security_Cheat_Sheet.html",
  "https://www.mongodb.com/docs/manual/administration/security-checklist/",
];

export const mongodbSchema = z.object({
  config: z.object({
    authorization_enabled: z
      .boolean()
      .optional()
      .describe("Whether access control (security.authorization) is enabled."),
    bind_ip: z
      .string()
      .max(256)
      .optional()
      .describe("The net.bindIp value (e.g. `127.0.0.1`, `0.0.0.0`)."),
    auth_mechanism: z
      .enum(["scram-sha-256", "scram-sha-1", "mongodb-cr"])
      .optional()
      .describe("The default authentication mechanism."),
    tls_enabled: z.boolean().optional().describe("Whether TLS is enabled for client connections."),
    journal_enabled: z.boolean().optional().describe("Whether write-ahead journaling is enabled."),
    app_role: z
      .string()
      .max(64)
      .optional()
      .describe("The built-in role granted to the application user (e.g. `readWrite`, `root`)."),
    server_side_javascript_enabled: z
      .boolean()
      .optional()
      .describe("Whether server-side JavaScript ($where, mapReduce) is enabled."),
  }),
  filename: z
    .string()
    .min(1)
    .max(512)
    .optional()
    .describe("Optional filename used for the finding location."),
});

export type MongodbInput = z.infer<typeof mongodbSchema>;
type MongodbConfig = MongodbInput["config"];

const BROAD_ROLES =
  /^(root|dbOwner|dbAdminAnyDatabase|userAdminAnyDatabase|readWriteAnyDatabase|clusterAdmin|__system)$/i;

const CHECKS: readonly ConfigCheck<MongodbConfig>[] = [
  {
    rule: "mongo-authorization-disabled",
    when: (c) => c.authorization_enabled === false,
    severity: "critical",
    title: "MongoDB access control is disabled",
    description:
      "With `security.authorization` disabled, MongoDB authenticates no one: any client that reaches the port has full read/write access to every database. This is the cause of countless ransomed MongoDB deployments.",
    remediation:
      "Enable `security.authorization: enabled`, create an admin user and a least-privilege application user, and restart so authentication is enforced.",
    cwe: ["CWE-306"],
  },
  {
    rule: "mongo-bind-all-interfaces",
    when: (c) => c.bind_ip === "0.0.0.0" || c.bind_ip === "*",
    severity: "medium",
    title: "MongoDB binds to all network interfaces",
    description:
      "`net.bindIp: 0.0.0.0` exposes mongod on every interface. Combined with disabled or weak authentication this makes the database internet-reachable.",
    remediation:
      "Bind to `127.0.0.1` and the specific private address the application uses, and restrict access with a firewall.",
    cwe: ["CWE-1327"],
  },
  {
    rule: "mongo-legacy-auth-mechanism",
    when: (c) => c.auth_mechanism !== undefined && c.auth_mechanism !== "scram-sha-256",
    severity: "high",
    title: "MongoDB uses a legacy authentication mechanism",
    description:
      "MONGODB-CR and SCRAM-SHA-1 are superseded: MONGODB-CR is fundamentally weak, and SHA-1 is no longer collision-resistant. SCRAM-SHA-256 is the current standard.",
    remediation:
      "Set the authentication mechanism to SCRAM-SHA-256 and recreate user credentials so the SHA-256 verifier is stored.",
    cwe: ["CWE-327"],
  },
  {
    rule: "mongo-tls-disabled",
    when: (c) => c.tls_enabled === false,
    severity: "high",
    title: "MongoDB TLS is disabled",
    description:
      "Without TLS, client traffic — the SCRAM handshake, queries, and documents — crosses the network in cleartext and can be intercepted or modified.",
    remediation:
      "Enable `net.tls` with a server certificate, set `net.tls.mode: requireTLS`, and have clients connect with `tls=true` and certificate verification.",
    cwe: ["CWE-319"],
  },
  {
    rule: "mongo-journaling-disabled",
    when: (c) => c.journal_enabled === false,
    severity: "low",
    title: "MongoDB journaling is disabled",
    description:
      "With journaling off, writes acknowledged before the next checkpoint can be lost on an unclean shutdown, risking data loss and an inconsistent recovery state.",
    remediation:
      "Keep journaling enabled (the default on the WiredTiger engine) and use an appropriate write concern for durability-sensitive operations.",
  },
  {
    rule: "mongo-excessive-app-role",
    when: (c) => c.app_role !== undefined && BROAD_ROLES.test(c.app_role.trim()),
    severity: "high",
    title: "MongoDB application user holds an over-broad role",
    description:
      "A built-in cluster- or any-database role (`root`, `dbOwner`, `*AnyDatabase`, `clusterAdmin`) gives the application far more than it needs; an injection flaw or stolen credential then reaches every database.",
    remediation:
      "Grant the application user a role scoped to its own database — `readWrite` on that database, or a custom role with only the required actions.",
    cwe: ["CWE-250"],
  },
  {
    rule: "mongo-server-side-javascript",
    when: (c) => c.server_side_javascript_enabled === true,
    severity: "medium",
    title: "MongoDB server-side JavaScript is enabled",
    description:
      "Server-side JavaScript (`$where`, `mapReduce`, `$function`) executes caller-influenced code on the database server, creating a code-injection sink and an availability risk.",
    remediation:
      "Disable server-side JavaScript (`security.javascriptEnabled: false`) and replace `$where` / `mapReduce` usage with the aggregation pipeline.",
    cwe: ["CWE-94"],
  },
];

/** Audit a MongoDB configuration. */
export function auditMongodb(input: MongodbInput): readonly Finding[] {
  return runConfigChecks(input.config, CHECKS, REFS, input.filename);
}
