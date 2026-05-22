import { readFile } from "node:fs/promises";
import { parse as parseToml } from "smol-toml";
import { z } from "zod";

const transportSchema = z.enum(["stdio", "http"]);
export type Transport = z.infer<typeof transportSchema>;

const logLevelSchema = z.enum(["debug", "info", "warn", "error"]);
export type LogLevel = z.infer<typeof logLevelSchema>;

const sbomFormatSchema = z.enum(["cyclonedx", "spdx"]);
const podSecurityLevelSchema = z.enum(["baseline", "restricted", "privileged"]);

const serverSchema = z
  .object({
    name: z.string().min(1).max(128).default("altais-mcp"),
    transport: transportSchema.default("stdio"),
    port: z.number().int().min(1).max(65535).default(3100),
    log_level: logLevelSchema.default("info"),
  })
  .prefault({});

const modulesSchema = z
  .object({
    scan: z.boolean().default(true),
    threat_model: z.boolean().default(true),
    owasp: z.boolean().default(true),
    secrets: z.boolean().default(true),
    headers: z.boolean().default(true),
    supply_chain: z.boolean().default(true),
    auth: z.boolean().default(true),
    crypto: z.boolean().default(false),
    container: z.boolean().default(false),
    code: z.boolean().default(false),
    data: z.boolean().default(false),
    compliance: z.boolean().default(false),
    infra: z.boolean().default(false),
    protocol: z.boolean().default(false),
    incident: z.boolean().default(false),
    testing: z.boolean().default(false),
    vuln_db: z.boolean().default(false),
    ml_security: z.boolean().default(false),
    sdlc: z.boolean().default(false),
    iac: z.boolean().default(false),
    agentic: z.boolean().default(false),
    api: z.boolean().default(false),
    runtime: z.boolean().default(false),
    database: z.boolean().default(false),
  })
  .prefault({});

const scanSchema = z
  .object({
    max_file_size_kb: z.number().int().positive().max(16384).default(512),
    exclude_patterns: z
      .array(z.string().max(256))
      .max(128)
      .default(["node_modules", "dist", ".git", "vendor"]),
    languages: z
      .array(z.string().max(32))
      .max(32)
      .default(["typescript", "javascript", "python", "rust", "go"]),
    /**
     * Root directory `altais_scan_file` may read from. Empty (the default)
     * means the server's working directory at startup. Absolute paths are
     * required; paths outside this root are rejected.
     */
    scan_root: z.string().max(512).default(""),
    /**
     * Maximum length of source passed to `altais_scan_code` / `altais_scan_diff`
     * in bytes. Caps total parsing work to prevent denial-of-service.
     */
    max_source_bytes: z
      .number()
      .int()
      .positive()
      .max(64 * 1024 * 1024)
      .default(2 * 1024 * 1024),
  })
  .prefault({});

const supplyChainSchema = z
  .object({
    check_licenses: z.boolean().default(true),
    cvss_threshold: z.number().min(0).max(10).default(7.0),
    sbom_format: sbomFormatSchema.default("cyclonedx"),
    slsa_level: z.number().int().min(1).max(3).default(2),
    verify_signatures: z.boolean().default(true),
    max_dependency_age_days: z.number().int().min(0).max(3650).default(30),
  })
  .prefault({});

const complianceSchema = z
  .object({
    frameworks: z
      .array(z.string().max(64))
      .max(32)
      .default(["owasp-asvs", "nist-800-53", "nist-ssdf", "cisa-sbd", "nis2"]),
  })
  .prefault({});

const severitySchema = z
  .object({
    critical_cvss_min: z.number().min(0).max(10).default(9.0),
    high_cvss_min: z.number().min(0).max(10).default(7.0),
    medium_cvss_min: z.number().min(0).max(10).default(4.0),
  })
  .prefault({});

const iacSchema = z
  .object({
    providers: z
      .array(z.string().max(64))
      .max(16)
      .default(["terraform", "kubernetes", "docker-compose"]),
    k8s_pod_security_level: podSecurityLevelSchema.default("restricted"),
  })
  .prefault({});

const secretsSchema = z
  .object({
    /** Minimum bits-per-character entropy for hex-charset tokens to be flagged. */
    entropy_min_hex: z.number().min(0).max(8).default(4.5),
    /** Minimum bits-per-character entropy for base64-charset tokens to be flagged. */
    entropy_min_base64: z.number().min(0).max(8).default(5.0),
    /** Minimum token length (chars) to consider for entropy scoring. */
    min_token_length: z.number().int().min(8).max(256).default(20),
  })
  .prefault({});

const agenticSchema = z
  .object({
    check_goal_hijack: z.boolean().default(true),
    check_tool_misuse: z.boolean().default(true),
    check_identity_abuse: z.boolean().default(true),
    check_supply_chain: z.boolean().default(true),
    check_code_execution: z.boolean().default(true),
    check_memory_poisoning: z.boolean().default(true),
    check_inter_agent: z.boolean().default(true),
    check_cascading: z.boolean().default(true),
    check_trust_exploitation: z.boolean().default(true),
    check_rogue_agents: z.boolean().default(true),
  })
  .prefault({});

const databaseSchema = z
  .object({
    drivers: z
      .array(z.string().max(64))
      .max(32)
      .default([
        "postgres",
        "mysql",
        "mongodb",
        "redis",
        "sqlite",
        "mssql",
        "elasticsearch",
        "dynamodb",
      ]),
    check_connection_strings: z.boolean().default(true),
    check_parameterization: z.boolean().default(true),
    check_migrations: z.boolean().default(true),
    check_backup: z.boolean().default(true),
    check_nosql_injection: z.boolean().default(true),
  })
  .prefault({});

export const configSchema = z
  .object({
    server: serverSchema,
    modules: modulesSchema,
    scan: scanSchema,
    secrets: secretsSchema,
    supply_chain: supplyChainSchema,
    compliance: complianceSchema,
    severity: severitySchema,
    iac: iacSchema,
    agentic: agenticSchema,
    database: databaseSchema,
  })
  .prefault({});

export type Config = z.infer<typeof configSchema>;
export type ModulesConfig = Config["modules"];
export type ServerConfig = Config["server"];

export class ConfigError extends Error {
  override readonly name = "ConfigError";
}

/**
 * Load the altais config from a TOML file. If the file is missing, the
 * defaults defined in the schema are returned so the server can run with
 * no configuration present.
 */
export async function loadConfig(path?: string): Promise<Config> {
  let raw: unknown = {};
  if (path !== undefined) {
    try {
      const contents = await readFile(path, "utf8");
      raw = parseToml(contents);
    } catch (err) {
      const code = (err as NodeJS.ErrnoException).code;
      if (code !== "ENOENT") {
        throw new ConfigError(`Failed to read config at ${path}: ${(err as Error).message}`);
      }
    }
  }

  const parsed = configSchema.safeParse(raw);
  if (!parsed.success) {
    throw new ConfigError(
      `Invalid config: ${parsed.error.issues
        .map((i) => `${i.path.join(".") || "<root>"}: ${i.message}`)
        .join("; ")}`,
    );
  }
  return parsed.data;
}

/**
 * Return the list of module names that the user has enabled.
 */
export function enabledModules(config: Config): readonly string[] {
  return Object.entries(config.modules)
    .filter(([, enabled]) => enabled)
    .map(([name]) => name);
}
