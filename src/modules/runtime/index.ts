  // Runtime module: 3 tools for runtime application protection —
  // a WAF rule generator, a RASP configuration recommender, and an
  // application-monitoring auditor.
  //
  // The two generators (`altais_generate_waf_rules`,
  // `altais_recommend_rasp`) return ready-to-use artifacts as JSON text and
  // do not push Finding objects. The auditor (`altais_audit_monitoring`)
  // flags security-monitoring gaps and pushes Finding objects into the
  // shared FindingStore.

  import { z } from "zod";
  import type { CallToolResult } from "@modelcontextprotocol/sdk/types.js";

  import type { FindingStore } from "../../core/report.js";
  import type { Finding, ModuleDefinition, ToolDefinition } from "../../core/types.js";
  import { auditMonitoring } from "./monitoring.js";
  import { recommendRasp } from "./rasp.js";
  import { generateWafRules } from "./waf.js";

  const MODULE_VERSION = "0.5.0";

  const COMMON_ANNOTATIONS = {
    readOnlyHint: true,
    destructiveHint: false,
    idempotentHint: true,
    openWorldHint: false,
  } as const;

  export interface RuntimeModuleDeps {
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

  function withSummary(findings: readonly Finding[]): unknown {
    return { summary: summarize(findings), findings };
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
    deps: RuntimeModuleDeps,
    parser: (args: unknown) => { success: true; data: TInput } | { success: false; message: string },
    run: (data: TInput) => readonly Finding[],
  ): (args: unknown) => CallToolResult {
    return (args: unknown) => {
      const parsed = parser(args);
      if (!parsed.success) return errorResult(`Invalid input: ${parsed.message}`);
      const findings = run(parsed.data);
      deps.findingStore.addMany(findings);
      return textResult(jsonText(withSummary(findings)));
    };
  }

  // ─── altais_generate_waf_rules ─────────────────────────────────────────────

  const wafSchema = z.object({
    config: z.object({
      platform: z
        .enum(["modsecurity", "cloudflare", "aws-waf", "nginx-naxsi"])
        .describe("Target WAF platform whose native rule syntax should be generated."),
      protect_against: z
        .array(
          z.enum(["sql-injection", "xss", "path-traversal", "rce", "ssrf", "scanner", "rate-abuse"]),
        )
        .min(1)
        .max(7)
        .describe("Attack classes the generated rule set should block."),
      paths_to_protect: z
        .array(z.string().min(1).max(512))
        .max(64)
        .optional()
        .describe(
          "Optional URL path globs to scope the rules to (e.g. `/api/*`). Defaults to all paths.",
        ),
    }),
  });

  function buildWafTool(): ToolDefinition {
    const parse = zodParser(wafSchema);
    return {
      name: "altais_generate_waf_rules",
      title: "Generate WAF rules",
      description:
        "Generate a ready-to-use Web Application Firewall rule set for a chosen platform (ModSecurity SecRules, a
  Cloudflare ruleset expression, an AWS WAFv2 rule JSON document, or NGINX/NAXSI directives) covering the requested
  attack classes — SQL injection, XSS, path traversal, RCE / command injection, SSRF, scanner traffic, and
  request-rate abuse. Returns the rule definitions, an optional path scope, a platform-specific deployment note, and
  a recommendation to run in detection mode before enforcing.",
      inputSchema: wafSchema.shape,
      annotations: COMMON_ANNOTATIONS,
      handler: (args) => {
        const parsed = parse(args);
        if (!parsed.success) return errorResult(`Invalid input: ${parsed.message}`);
        const result = generateWafRules({
          platform: parsed.data.config.platform,
          protect_against: parsed.data.config.protect_against,
          ...(parsed.data.config.paths_to_protect !== undefined
            ? { paths_to_protect: parsed.data.config.paths_to_protect }
            : {}),
        });
        return textResult(jsonText(result));
      },
    };
  }

  // ─── altais_recommend_rasp ─────────────────────────────────────────────────

  const raspSchema = z.object({
    config: z.object({
      language: z
        .enum(["java", "dotnet", "node", "python", "ruby", "go"])
        .describe("Primary application language — drives the instrumentation mechanism."),
      framework: z
        .string()
        .min(1)
        .max(128)
        .describe("Application framework, e.g. `spring-boot`, `express`, `django`."),
      deployment: z
        .enum(["container", "vm", "serverless"])
        .describe("Deployment model — drives agent packaging and performance guidance."),
      risk_tolerance: z
        .enum(["low", "medium", "high"])
        .describe(
          "Team risk tolerance — `low` favors aggressive blocking, `high` favors monitor-first.",
        ),
    }),
  });

  function buildRaspTool(): ToolDefinition {
    const parse = zodParser(raspSchema);
    return {
      name: "altais_recommend_rasp",
      title: "Recommend a RASP configuration",
      description:
        "Recommend a Runtime Application Self-Protection configuration for an application's language, framework,
  deployment model, and risk tolerance. Returns the RASP product category to evaluate, the protections to enable
  (unsafe deserialization, OS command injection, SQL injection, path traversal, SSRF) each with a block-vs-monitor
  recommendation, stack-specific instrumentation and agent setup steps, blocking-vs-monitoring guidance keyed to risk
   tolerance, and deployment-specific performance considerations.",
      inputSchema: raspSchema.shape,
      annotations: COMMON_ANNOTATIONS,
      handler: (args) => {
        const parsed = parse(args);
        if (!parsed.success) return errorResult(`Invalid input: ${parsed.message}`);
        const result = recommendRasp({
          language: parsed.data.config.language,
          framework: parsed.data.config.framework,
          deployment: parsed.data.config.deployment,
          risk_tolerance: parsed.data.config.risk_tolerance,
        });
        return textResult(jsonText(result));
      },
    };
  }

  // ─── altais_audit_monitoring ───────────────────────────────────────────────

  const monitoringSchema = z.object({
    config: z.object({
      logs_authentication: z
        .boolean()
        .describe("Whether authentication events (login success / failure) are logged."),
      logs_authorization_failures: z
        .boolean()
        .describe("Whether authorization / access-denied failures are logged."),
      logs_input_validation_failures: z
        .boolean()
        .describe("Whether input-validation failures are logged."),
      logs_admin_actions: z
        .boolean()
        .describe("Whether administrative / privileged actions are logged."),
      alerting_enabled: z.boolean().describe("Whether alerts fire on security events."),
      alert_routing: z
        .boolean()
        .describe("Whether alerts are routed to a responder or on-call destination."),
      siem_integrated: z.boolean().describe("Whether logs are forwarded to a SIEM."),
      metrics_collected: z.boolean().describe("Whether application metrics are collected."),
      anomaly_detection: z.boolean().describe("Whether behavioral / anomaly detection is in place."),
      dashboards: z.boolean().describe("Whether security / operations dashboards exist."),
      on_call: z.boolean().describe("Whether an on-call rotation owns security alerts."),
      mean_time_to_detect_minutes: z
        .number()
        .int()
        .min(0)
        .max(525600)
        .describe("Mean time to detect a security incident, in minutes."),
    }),
    filename: z
      .string()
      .min(1)
      .max(512)
      .optional()
      .describe("Optional filename used for the finding location."),
  });

  function buildMonitoringTool(deps: RuntimeModuleDeps): ToolDefinition {
    const parse = zodParser(monitoringSchema);
    const run = makeRunner(deps, parse, (d) => {
      const result = auditMonitoring({
        logs_authentication: d.config.logs_authentication,
        logs_authorization_failures: d.config.logs_authorization_failures,
        logs_input_validation_failures: d.config.logs_input_validation_failures,
        logs_admin_actions: d.config.logs_admin_actions,
        alerting_enabled: d.config.alerting_enabled,
        alert_routing: d.config.alert_routing,
        siem_integrated: d.config.siem_integrated,
        metrics_collected: d.config.metrics_collected,
      return result.findings;
    });
    return {
      name: "altais_audit_monitoring",
      title: "Audit application monitoring coverage",
      description:
        "Audit an application's monitoring and observability posture for security-event coverage. Flags missing
  security-event logging (authentication, authorization failures, input-validation failures, administrative actions),
   no alerting, unrouted alerts, no SIEM integration, no anomaly detection, missing metrics or dashboards, no on-call
   rotation, and a slow mean time to detect. Emits one finding per gap with real CWE references and actionable
  remediation.",
      inputSchema: monitoringSchema.shape,
      annotations: COMMON_ANNOTATIONS,
      handler: run,
    };
  }

  export function createRuntimeModule(deps: RuntimeModuleDeps): ModuleDefinition {
    const tools: readonly ToolDefinition[] = [
      buildWafTool(),
      buildRaspTool(),
      buildMonitoringTool(deps),
    ];
    return {
      name: "runtime",
      description:
        "Runtime application protection: a WAF rule generator (ModSecurity / Cloudflare / AWS WAF / NGINX-NAXSI), a
  RASP configuration recommender, and an application-monitoring auditor for security-event logging, alerting, SIEM
  integration, and detection coverage.",
      version: MODULE_VERSION,
      tools,
      init() {
        // No async resources to load.
      },
    };
  }