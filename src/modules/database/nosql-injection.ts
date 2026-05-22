// altais_audit_nosql_injection — NoSQL injection detection.
//
// Scans source for NoSQL-specific injection sinks: MongoDB operator
// injection ($gt / $ne / $where / mapReduce reachable from request
// data), Elasticsearch query_string injection, and Redis Lua-script
// injection. The detection patterns live in data/database-patterns.json.

import { z } from "zod";
import type { Finding } from "../../core/types.js";
import { loadDatabasePatterns, scanSource } from "./finding.js";

const REFS = [
  "https://cwe.mitre.org/data/definitions/943.html",
  "https://owasp.org/www-community/Injection_Flaws",
];

export const nosqlInjectionSchema = z.object({
  source: z
    .string()
    .min(1)
    .max(512 * 1024)
    .describe("Source code to scan for NoSQL injection sinks."),
  language: z
    .enum(["javascript", "typescript", "python"])
    .optional()
    .describe("Optional language filter; when omitted, every NoSQL pattern is applied."),
  filename: z
    .string()
    .min(1)
    .max(512)
    .optional()
    .describe("Optional filename used for the finding location."),
});

export type NosqlInjectionInput = z.infer<typeof nosqlInjectionSchema>;

/** Detect NoSQL injection sinks in the supplied source. */
export function auditNosqlInjection(input: NosqlInjectionInput): readonly Finding[] {
  return scanSource(
    input.source,
    loadDatabasePatterns("nosql_injection"),
    REFS,
    input.filename,
    input.language,
  );
}
