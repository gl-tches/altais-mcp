// altais_audit_migrations — destructive / unsafe migration detection.
//
// Scans migration source (raw SQL or a migration-tool script) for
// operations that destroy data or break a running deployment: table /
// column / database drops, TRUNCATE, unscoped DELETE, NOT NULL column
// additions, column renames, and column type changes. The detection
// patterns live in data/database-patterns.json.

import { z } from "zod";
import type { Finding } from "../../core/types.js";
import { loadDatabasePatterns, scanSource } from "./finding.js";

const REFS = [
  "https://cheatsheetseries.owasp.org/cheatsheets/Database_Security_Cheat_Sheet.html",
  "https://martinfowler.com/articles/evodb.html",
];

export const migrationsSchema = z.object({
  source: z
    .string()
    .min(1)
    .max(512 * 1024)
    .describe(
      "Migration source — raw SQL or a migration-tool script — to scan for unsafe operations.",
    ),
  filename: z
    .string()
    .min(1)
    .max(512)
    .optional()
    .describe("Optional filename used for the finding location."),
});

export type MigrationsInput = z.infer<typeof migrationsSchema>;

/** Detect destructive or risky operations in a database migration. */
export function auditMigrations(input: MigrationsInput): readonly Finding[] {
  return scanSource(input.source, loadDatabasePatterns("migrations"), REFS, input.filename);
}
