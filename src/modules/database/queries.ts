// altais_audit_queries — unsafe query-construction detection.
//
// Scans source for raw, non-parameterized query building across the
// supported ORMs and drivers (Prisma, Drizzle, TypeORM, Sequelize, Knex,
// pg, mysql2, better-sqlite3 / SQLAlchemy, Django ORM, psycopg /
// diesel, sqlx, sea-orm / GORM, database/sql, pgx). The detection
// patterns live in data/database-patterns.json.

import { z } from "zod";
import type { Finding } from "../../core/types.js";
import { loadDatabasePatterns, scanSource } from "./finding.js";

const REFS = [
  "https://cwe.mitre.org/data/definitions/89.html",
  "https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html",
];

export const queriesSchema = z.object({
  source: z
    .string()
    .min(1)
    .max(512 * 1024)
    .describe("Source code to scan for unsafe database query construction."),
  language: z
    .enum(["javascript", "typescript", "python", "rust", "go"])
    .optional()
    .describe("Optional language filter; when omitted, every query pattern is applied."),
  filename: z
    .string()
    .min(1)
    .max(512)
    .optional()
    .describe("Optional filename used for the finding location."),
});

export type QueriesInput = z.infer<typeof queriesSchema>;

/** Detect unsafe query construction in the supplied source. */
export function auditQueries(input: QueriesInput): readonly Finding[] {
  return scanSource(
    input.source,
    loadDatabasePatterns("queries"),
    REFS,
    input.filename,
    input.language,
  );
}
