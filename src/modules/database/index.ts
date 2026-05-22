// Database module: 16 tools for database-layer security auditing —
// connection-string hygiene, query parameterization across ORMs and raw
// drivers, per-engine configuration audits (PostgreSQL / CockroachDB,
// MySQL / MariaDB, MongoDB, Redis / Memcached, SQLite, SQL Server,
// Elasticsearch, DynamoDB / Supabase / PlanetScale), connection pooling,
// migration safety, backup posture, NoSQL injection, TLS, and audit
// logging.
//
// Every config-auditing tool accepts a `config` object of known
// settings; the three source-scanning tools (queries, migrations,
// nosql_injection) accept `source` text. Findings flow into the shared
// session FindingStore.

import type { z } from "zod";
import type { CallToolResult } from "@modelcontextprotocol/sdk/types.js";

import type { FindingStore } from "../../core/report.js";
import type { Finding, ModuleDefinition, ToolDefinition } from "../../core/types.js";
import { auditConnection, connectionSchema } from "./connection.js";
import { auditQueries, queriesSchema } from "./queries.js";
import { auditPostgres, postgresSchema } from "./postgres.js";
import { auditMysql, mysqlSchema } from "./mysql.js";
import { auditMongodb, mongodbSchema } from "./mongodb.js";
import { auditRedis, redisSchema } from "./redis.js";
import { auditSqlite, sqliteSchema } from "./sqlite.js";
import { auditMssql, mssqlSchema } from "./mssql.js";
import { auditElasticsearch, elasticsearchSchema } from "./elasticsearch.js";
import { auditDynamodb, dynamodbSchema } from "./dynamodb.js";
import { auditPooling, poolingSchema } from "./pooling.js";
import { auditMigrations, migrationsSchema } from "./migrations.js";
import { auditBackup, backupSchema } from "./backup.js";
import { auditNosqlInjection, nosqlInjectionSchema } from "./nosql-injection.js";
import { auditDbTls, dbTlsSchema } from "./tls.js";
import { auditDbLogging, dbLoggingSchema } from "./logging.js";

const MODULE_VERSION = "1.1.1";

const COMMON_ANNOTATIONS = {
  readOnlyHint: true,
  destructiveHint: false,
  idempotentHint: true,
  openWorldHint: false,
} as const;

export interface DatabaseModuleDeps {
  readonly findingStore: FindingStore;
}

function textResult(text: string): CallToolResult {
  return { content: [{ type: "text", text }] };
}

function errorResult(text: string): CallToolResult {
  return { isError: true, content: [{ type: "text", text }] };
}

function jsonText(value: unknown): string {
  return JSON.stringify(value, null, 2);
}

function summarize(findings: readonly Finding[]): {
  total: number;
  by_severity: Record<string, number>;
} {
  const bySeverity: Record<string, number> = {};
  for (const f of findings) bySeverity[f.severity] = (bySeverity[f.severity] ?? 0) + 1;
  return { total: findings.length, by_severity: bySeverity };
}

function zodParser<T>(
  schema: z.ZodType<T>,
): (args: unknown) => { success: true; data: T } | { success: false; message: string } {
  return (args) => {
    const r = schema.safeParse(args);
    if (r.success) return { success: true, data: r.data };
    return {
      success: false,
      message: r.error.issues
        .map((i) => `${i.path.join(".") || "<root>"}: ${i.message}`)
        .join("; "),
    };
  };
}

function makeRunner<TInput>(
  deps: DatabaseModuleDeps,
  parser: (args: unknown) => { success: true; data: TInput } | { success: false; message: string },
  run: (data: TInput) => readonly Finding[],
): (args: unknown) => CallToolResult {
  return (args: unknown) => {
    const parsed = parser(args);
    if (!parsed.success) return errorResult(`Invalid input: ${parsed.message}`);
    const findings = run(parsed.data);
    deps.findingStore.addMany(findings);
    return textResult(jsonText({ summary: summarize(findings), findings }));
  };
}

interface ToolSpec<T> {
  readonly name: string;
  readonly title: string;
  readonly description: string;
  readonly schema: z.ZodType<T>;
  readonly shape: z.ZodRawShape;
  readonly audit: (data: T) => readonly Finding[];
}

function buildTool<T>(deps: DatabaseModuleDeps, spec: ToolSpec<T>): ToolDefinition {
  return {
    name: spec.name,
    title: spec.title,
    description: spec.description,
    inputSchema: spec.shape,
    annotations: COMMON_ANNOTATIONS,
    handler: makeRunner(deps, zodParser(spec.schema), spec.audit),
  };
}

/** Construct the database module with its 16 tools. */
export function createDatabaseModule(deps: DatabaseModuleDeps): ModuleDefinition {
  const tools: readonly ToolDefinition[] = [
    buildTool(deps, {
      name: "altais_audit_connection",
      title: "Audit database connection configuration",
      description:
        "Audit database connection strings / URIs for security weaknesses: credentials embedded in the URI, empty or default/well-known passwords, disabled or unspecified TLS (`sslmode=disable/allow/prefer/require`, `ssl=false`), and plaintext schemes (`redis://`, `http://`). Covers PostgreSQL, MySQL/MariaDB, MongoDB, Redis, Elasticsearch, and cloud-managed databases.",
      schema: connectionSchema,
      shape: connectionSchema.shape,
      audit: auditConnection,
    }),
    buildTool(deps, {
      name: "altais_audit_queries",
      title: "Audit query parameterization",
      description:
        "Detect unsafe, non-parameterized query construction in source code across the supported ORMs and drivers: Prisma ($queryRawUnsafe), Drizzle, TypeORM, Sequelize, Knex, pg, mysql2, better-sqlite3, SQLAlchemy, Django ORM, psycopg, diesel, sqlx, sea-orm, GORM, database/sql, and pgx. Flags string concatenation, template-literal / f-string interpolation, and format!-built SQL.",
      schema: queriesSchema,
      shape: queriesSchema.shape,
      audit: auditQueries,
    }),
    buildTool(deps, {
      name: "altais_audit_postgres",
      title: "Audit PostgreSQL configuration",
      description:
        "Audit a PostgreSQL / CockroachDB configuration: application connecting as superuser, PUBLIC having CREATE on the public schema, row-level security disabled, `trust` authentication in pg_hba.conf, weak password encryption (md5 vs scram-sha-256), TLS disabled, listening on all interfaces, high-risk extensions, and missing connection logging.",
      schema: postgresSchema,
      shape: postgresSchema.shape,
      audit: auditPostgres,
    }),
    buildTool(deps, {
      name: "altais_audit_mysql",
      title: "Audit MySQL / MariaDB configuration",
      description:
        "Audit a MySQL / MariaDB configuration: --skip-grant-tables, binding to all interfaces, legacy password hashing (secure_auth / old_passwords), LOAD DATA LOCAL INFILE, TLS not required, anonymous accounts, an over-privileged application account (ALL / SUPER / FILE), wildcard-host accounts, and non-strict sql_mode.",
      schema: mysqlSchema,
      shape: mysqlSchema.shape,
      audit: auditMysql,
    }),
    buildTool(deps, {
      name: "altais_audit_mongodb",
      title: "Audit MongoDB configuration",
      description:
        "Audit a MongoDB configuration: access control disabled, binding to all interfaces, a legacy authentication mechanism (MONGODB-CR / SCRAM-SHA-1 vs SCRAM-SHA-256), TLS disabled, journaling disabled, an over-broad application role, and server-side JavaScript enabled.",
      schema: mongodbSchema,
      shape: mongodbSchema.shape,
      audit: auditMongodb,
    }),
    buildTool(deps, {
      name: "altais_audit_redis",
      title: "Audit Redis / Memcached configuration",
      description:
        "Audit a Redis / Memcached configuration: no authentication (requirepass), protected-mode disabled, binding to all interfaces, no per-user ACLs, unrestricted dangerous commands (FLUSHALL / CONFIG / DEBUG / KEYS), TLS disabled, and a weak password.",
      schema: redisSchema,
      shape: redisSchema.shape,
      audit: auditRedis,
    }),
    buildTool(deps, {
      name: "altais_audit_sqlite",
      title: "Audit SQLite configuration",
      description:
        "Audit a SQLite configuration: a world-readable database or WAL/journal file, no encryption at rest for sensitive data, runtime extension loading enabled, ATTACH DATABASE from caller-influenced paths, and an insecure temporary-store directory.",
      schema: sqliteSchema,
      shape: sqliteSchema.shape,
      audit: auditSqlite,
    }),
    buildTool(deps, {
      name: "altais_audit_mssql",
      title: "Audit Microsoft SQL Server configuration",
      description:
        "Audit a Microsoft SQL Server configuration: the sa account enabled, xp_cmdshell enabled, CLR integration, OLE Automation procedures, linked servers with saved credentials, Force Encryption disabled, an application login in the sysadmin role, and contained databases.",
      schema: mssqlSchema,
      shape: mssqlSchema.shape,
      audit: auditMssql,
    }),
    buildTool(deps, {
      name: "altais_audit_elasticsearch",
      title: "Audit Elasticsearch configuration",
      description:
        "Audit an Elasticsearch configuration: the security feature disabled, anonymous access, transport- and HTTP-layer TLS disabled, dynamic scripting enabled, binding to all interfaces, audit logging disabled, and an unchanged built-in elastic superuser password.",
      schema: elasticsearchSchema,
      shape: elasticsearchSchema.shape,
      audit: auditElasticsearch,
    }),
    buildTool(deps, {
      name: "altais_audit_dynamodb",
      title: "Audit AWS DynamoDB configuration",
      description:
        "Audit an AWS DynamoDB configuration: encryption at rest disabled or using an AWS-owned key, point-in-time recovery disabled, no VPC endpoint, IAM policies with wildcard actions or resources, deletion protection disabled, and missing fine-grained (item-level) access control.",
      schema: dynamodbSchema,
      shape: dynamodbSchema.shape,
      audit: auditDynamodb,
    }),
    buildTool(deps, {
      name: "altais_audit_pooling",
      title: "Audit connection-pool configuration",
      description:
        "Audit a database connection-pool configuration: an unbounded or excessively large pool, missing idle / acquire / max-lifetime timeouts, disabled leak detection, TLS not enforced in the pool, and hard-coded credentials in the pool configuration.",
      schema: poolingSchema,
      shape: poolingSchema.shape,
      audit: auditPooling,
    }),
    buildTool(deps, {
      name: "altais_audit_migrations",
      title: "Audit database migration safety",
      description:
        "Scan database migration source (raw SQL or a migration-tool script) for destructive and unsafe operations: table / column / database drops, TRUNCATE, unscoped DELETE, NOT NULL column additions, column renames, and column type changes that risk data loss or break a running deployment.",
      schema: migrationsSchema,
      shape: migrationsSchema.shape,
      audit: auditMigrations,
    }),
    buildTool(deps, {
      name: "altais_audit_backup",
      title: "Audit database backup configuration",
      description:
        "Audit a database backup configuration: no automated backups, backups not encrypted at rest, short retention, point-in-time recovery disabled, no off-site copy, restores never tested, backup storage not access-restricted, and hard-coded credentials in the backup configuration.",
      schema: backupSchema,
      shape: backupSchema.shape,
      audit: auditBackup,
    }),
    buildTool(deps, {
      name: "altais_audit_nosql_injection",
      title: "Audit for NoSQL injection",
      description:
        "Scan source code for NoSQL injection sinks: MongoDB operator injection (request data reaching find / update / aggregate, the $where operator, mapReduce), Elasticsearch query_string injection, and Redis Lua-script injection.",
      schema: nosqlInjectionSchema,
      shape: nosqlInjectionSchema.shape,
      audit: auditNosqlInjection,
    }),
    buildTool(deps, {
      name: "altais_audit_db_tls",
      title: "Audit database TLS configuration",
      description:
        "Audit a database's TLS / SSL configuration: TLS disabled, a deprecated minimum protocol version (TLS 1.0 / 1.1), server-certificate verification disabled, weak cipher suites, a self-signed certificate, an expired or expiring certificate, and missing mutual TLS.",
      schema: dbTlsSchema,
      shape: dbTlsSchema.shape,
      audit: auditDbTls,
    }),
    buildTool(deps, {
      name: "altais_audit_db_logging",
      title: "Audit database audit logging",
      description:
        "Audit a database's audit-logging configuration: audit logging, connection logging, failed-login logging, and the slow-query log disabled; an unsecured log destination; sensitive data captured in logs; and inadequate log retention.",
      schema: dbLoggingSchema,
      shape: dbLoggingSchema.shape,
      audit: auditDbLogging,
    }),
  ];

  return {
    name: "database",
    description:
      "Database-layer security auditing: connection-string hygiene, query parameterization across ORMs and drivers, per-engine configuration audits (PostgreSQL, MySQL/MariaDB, MongoDB, Redis, SQLite, SQL Server, Elasticsearch, DynamoDB), connection pooling, migration safety, backup posture, NoSQL injection, TLS, and audit logging.",
    version: MODULE_VERSION,
    tools,
    init() {
      // Detection patterns load lazily from data/database-patterns.json.
    },
  };
}
