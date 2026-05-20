// WAF rule generator (altais_generate_waf_rules).
//
// Given a target WAF platform and the attack classes the team wants to
// block, this generator emits a ready-to-use rule set in that platform's
// native syntax — ModSecurity SecRules, a Cloudflare ruleset expression,
// an AWS WAF rule JSON document, or NGINX/NAXSI directives. It is a pure
// function: it returns an artifact, it does not push Finding objects.

export type WafPlatform = "modsecurity" | "cloudflare" | "aws-waf" | "nginx-naxsi";

export type AttackClass =
  | "sql-injection"
  | "xss"
  | "path-traversal"
  | "rce"
  | "ssrf"
  | "scanner"
  | "rate-abuse";

export interface WafGeneratorInput {
  readonly platform: WafPlatform;
  readonly protect_against: readonly AttackClass[];
  readonly paths_to_protect?: readonly string[];
}

export interface WafRule {
  readonly attack_class: AttackClass;
  /** The rule body in the target platform's native syntax. */
  readonly definition: string;
}

export interface WafGeneratorResult {
  readonly platform: WafPlatform;
  readonly attack_classes: readonly AttackClass[];
  readonly paths_protected: readonly string[];
  readonly rules: readonly WafRule[];
  readonly deployment_note: string;
  readonly recommendation: string;
  readonly references: readonly string[];
}

const REFERENCES: readonly string[] = [
  "https://owasp.org/www-project-modsecurity-core-rule-set/",
  "https://coreruleset.org/docs/",
  "https://docs.aws.amazon.com/waf/latest/developerguide/waf-rules.html",
  "https://owasp.org/Top10/A03_2021-Injection/",
];

interface AttackMeta {
  /** Human-readable label used in comments and messages. */
  readonly label: string;
  /** ModSecurity attack-type macro used in the @rx anchor / msg. */
  readonly modsecVariable: string;
  /** A ModSecurity-flavoured regex covering the attack class. */
  readonly modsecRegex: string;
  /** A Cloudflare ruleset-language sub-expression. */
  readonly cloudflareExpr: string;
  /** AWS WAF managed rule group name that covers this class. */
  readonly awsManagedGroup: string;
}

// Curated, conservative signatures. These are detection anchors; the
// recommendation below tells operators to run in detection mode first
// and tune before enforcing.
const ATTACK_META: Readonly<Record<AttackClass, AttackMeta>> = {
  "sql-injection": {
    label: "SQL injection",
    modsecVariable: "ARGS|ARGS_NAMES|REQUEST_COOKIES|REQUEST_HEADERS:Referer",
    modsecRegex:
      "(?i)(?:union(?:\\s|/\\*.*?\\*/)+select|\\bselect\\b.+\\bfrom\\b|\\binsert\\b.+\\binto\\b|\\bor\\b\\s+1\\s*=\\s*1|sleep\\s*\\(|benchmark\\s*\\()",
    cloudflareExpr:
      'lower(http.request.uri.query) contains "union select" or lower(http.request.body.raw) contains "or 1=1"',
    awsManagedGroup: "AWSManagedRulesSQLiRuleSet",
  },
  xss: {
    label: "cross-site scripting",
    modsecVariable: "ARGS|ARGS_NAMES|REQUEST_HEADERS:User-Agent",
    modsecRegex:
      "(?i)(?:<script[\\s>]|javascript:|onerror\\s*=|onload\\s*=|<svg[\\s/]|document\\.cookie)",
    cloudflareExpr:
      'lower(http.request.uri.query) contains "<script" or lower(http.request.uri.query) contains "onerror="',
    awsManagedGroup: "AWSManagedRulesCommonRuleSet",
  },
  "path-traversal": {
    label: "path traversal",
    modsecVariable: "REQUEST_URI|ARGS",
    modsecRegex: "(?:\\.\\./|\\.\\.\\\\|%2e%2e[/\\\\]|/etc/passwd|c:\\\\windows)",
    cloudflareExpr:
      'http.request.uri.path contains "../" or lower(http.request.uri.path) contains "/etc/passwd"',
    awsManagedGroup: "AWSManagedRulesCommonRuleSet",
  },
  rce: {
    label: "remote code execution / command injection",
    modsecVariable: "ARGS|REQUEST_BODY",
    modsecRegex:
      "(?i)(?:;\\s*(?:cat|wget|curl|bash|sh|nc)\\b|\\$\\(.*\\)|`.*`|\\|\\s*(?:bash|sh)\\b|/bin/(?:bash|sh))",
    cloudflareExpr:
      'lower(http.request.body.raw) contains "/bin/bash" or lower(http.request.uri.query) contains "$(.)"',
    awsManagedGroup: "AWSManagedRulesKnownBadInputsRuleSet",
  },
  ssrf: {
    label: "server-side request forgery",
    modsecVariable: "ARGS",
    modsecRegex:
      "(?i)(?:https?://(?:127\\.0\\.0\\.1|localhost|169\\.254\\.169\\.254|\\[::1\\])|file://|gopher://|dict://)",
    cloudflareExpr:
      'lower(http.request.uri.query) contains "169.254.169.254" or lower(http.request.uri.query) contains "localhost"',
    awsManagedGroup: "AWSManagedRulesKnownBadInputsRuleSet",
  },
  scanner: {
    label: "automated scanner / vulnerability tooling",
    modsecVariable: "REQUEST_HEADERS:User-Agent",
    modsecRegex:
      "(?i)(?:sqlmap|nikto|nmap|masscan|acunetix|nessus|dirbuster|gobuster|wpscan|zaproxy|burp)",
    cloudflareExpr:
      '(http.user_agent contains "sqlmap" or http.user_agent contains "nikto" or http.user_agent contains "nmap")',
    awsManagedGroup: "AWSManagedRulesBotControlRuleSet",
  },
  "rate-abuse": {
    label: "request-rate abuse / brute force",
    modsecVariable: "REMOTE_ADDR",
    modsecRegex: "",
    cloudflareExpr: '(http.request.method eq "POST")',
    awsManagedGroup: "AWSManagedRulesAmazonIpReputationList",
  },
};

/** Default path glob used when the caller does not scope protection. */
const DEFAULT_PATH = "/*";

function effectivePaths(paths: readonly string[] | undefined): readonly string[] {
  if (paths === undefined || paths.length === 0) return [DEFAULT_PATH];
  return paths;
}

// ─── ModSecurity ─────────────────────────────────────────────────────────────

function modsecRule(attack: AttackClass, ruleId: number, paths: readonly string[]): string {
  const meta = ATTACK_META[attack];
  const lines: string[] = [`# ${meta.label} (${attack})`];

  if (attack === "rate-abuse") {
    lines.push(
      `SecAction "id:${String(ruleId)},phase:1,pass,nolog,initcol:ip=%{REMOTE_ADDR}"`,
      `SecRule IP:REQUEST_COUNT "@gt 100" \\`,
      `  "id:${String(ruleId + 1)},phase:1,deny,status:429,\\`,
      `   msg:'Request-rate abuse: more than 100 requests/60s from one IP',\\`,
      `   tag:'attack-rate-abuse',expirevar:ip.request_count=60"`,
      `SecRule REQUEST_LINE "@unconditionalMatch" \\`,
      `  "id:${String(ruleId + 2)},phase:1,pass,nolog,setvar:ip.request_count=+1"`,
    );
    return lines.join("\n");
  }

  const pathAnchor =
    paths.length === 1 && paths[0] === DEFAULT_PATH
      ? ""
      : `SecRule REQUEST_URI "@rx ^(?:${paths
          .map((p) => p.replace(/\*/g, ".*"))
          .join("|")})" "id:${String(ruleId)},phase:2,pass,nolog,chain"\n`;

  lines.push(
    `${pathAnchor}SecRule ${meta.modsecVariable} "@rx ${meta.modsecRegex}" \\`,
    `  "id:${String(pathAnchor === "" ? ruleId : ruleId + 1)},phase:2,deny,status:403,log,\\`,
    `   msg:'${meta.label} detected',\\`,
    `   tag:'attack-${attack}',tag:'OWASP_CRS',severity:'CRITICAL'"`,
  );
  return lines.join("\n");
}

function generateModsecurity(input: WafGeneratorInput): readonly WafRule[] {
  const paths = effectivePaths(input.paths_to_protect);
  let ruleId = 900100;
  return input.protect_against.map((attack) => {
    const definition = modsecRule(attack, ruleId, paths);
    ruleId += 10;
    return { attack_class: attack, definition };
  });
}

// ─── Cloudflare ──────────────────────────────────────────────────────────────

function generateCloudflare(input: WafGeneratorInput): readonly WafRule[] {
  const paths = effectivePaths(input.paths_to_protect);
  const pathClause =
    paths.length === 1 && paths[0] === DEFAULT_PATH
      ? ""
      : `(${paths.map((p) => `http.request.uri.path wildcard "${p}"`).join(" or ")}) and `;

  return input.protect_against.map((attack) => {
    const meta = ATTACK_META[attack];
    const expression = `${pathClause}(${meta.cloudflareExpr})`;
    const action = attack === "rate-abuse" ? "block (via Rate Limiting rule)" : "block";
    const definition = JSON.stringify(
      {
        description: `altais-mcp: block ${meta.label}`,
        expression,
        action,
        ...(attack === "rate-abuse"
          ? {
              ratelimit: {
                characteristics: ["ip.src"],
                period: 60,
                requests_per_period: 100,
                mitigation_timeout: 600,
              },
            }
          : {}),
      },
      null,
      2,
    );
    return { attack_class: attack, definition };
  });
}

// ─── AWS WAF ─────────────────────────────────────────────────────────────────

function generateAwsWaf(input: WafGeneratorInput): readonly WafRule[] {
  const paths = effectivePaths(input.paths_to_protect);
  const scopedToRoot = paths.length === 1 && paths[0] === DEFAULT_PATH;

  return input.protect_against.map((attack, idx) => {
    const meta = ATTACK_META[attack];
    const priority = 10 + idx;

    const baseRule =
      attack === "rate-abuse"
        ? {
            Name: "altais-rate-abuse",
            Priority: priority,
            Action: { Block: {} },
            VisibilityConfig: {
              SampledRequestsEnabled: true,
              CloudWatchMetricsEnabled: true,
              MetricName: "altaisRateAbuse",
            },
            Statement: {
              RateBasedStatement: {
                Limit: 1000,
                AggregateKeyType: "IP",
              },
            },
          }
        : {
            Name: `altais-${attack}`,
            Priority: priority,
            OverrideAction: { None: {} },
            VisibilityConfig: {
              SampledRequestsEnabled: true,
              CloudWatchMetricsEnabled: true,
              MetricName: `altais${attack.replace(/-/g, "")}`,
            },
            Statement: {
              ManagedRuleGroupStatement: {
                VendorName: "AWS",
                Name: meta.awsManagedGroup,
                ...(scopedToRoot
                  ? {}
                  : {
                      ScopeDownStatement: {
                        OrStatement: {
                          Statements: paths.map((p) => ({
                            ByteMatchStatement: {
                              SearchString: p.replace(/\*/g, ""),
                              FieldToMatch: { UriPath: {} },
                              TextTransformations: [{ Priority: 0, Type: "LOWERCASE" }],
                              PositionalConstraint: "STARTS_WITH",
                            },
                          })),
                        },
                      },
                    }),
              },
            },
          };
    return { attack_class: attack, definition: JSON.stringify(baseRule, null, 2) };
  });
}

// ─── NGINX / NAXSI ───────────────────────────────────────────────────────────

function generateNginxNaxsi(input: WafGeneratorInput): readonly WafRule[] {
  const paths = effectivePaths(input.paths_to_protect);
  let ruleId = 1500;

  return input.protect_against.map((attack) => {
    const meta = ATTACK_META[attack];
    const lines: string[] = [`# ${meta.label} (${attack})`];

    if (attack === "rate-abuse") {
      lines.push(
        "# In the http {} block:",
        "limit_req_zone $binary_remote_addr zone=altais_rate:10m rate=10r/s;",
        "# In each protected location {} block:",
        ...paths.map(
          (p) =>
            `location ${p === DEFAULT_PATH ? "/" : p} { limit_req zone=altais_rate burst=20 nodelay; }`,
        ),
      );
      return { attack_class: attack, definition: lines.join("\n") };
    }

    lines.push(
      "# naxsi_core.rules — custom MainRule:",
      `MainRule "rx:${meta.modsecRegex}" "msg:altais ${meta.label}" "mz:ARGS|BODY|URL|$HEADERS_VAR:Cookie" "s:$ATTACK:8" id:${String(ruleId)};`,
      "# Apply inside protected location blocks:",
      ...paths.map(
        (p) =>
          `location ${p === DEFAULT_PATH ? "/" : p} { SecRulesEnabled; CheckRule "$ATTACK >= 8" BLOCK; }`,
      ),
    );
    ruleId += 1;
    return { attack_class: attack, definition: lines.join("\n") };
  });
}

const DEPLOYMENT_NOTES: Readonly<Record<WafPlatform, string>> = {
  modsecurity:
    "Place these SecRules in a custom file loaded after the OWASP Core Rule Set (e.g. `REQUEST-950-CUSTOM.conf`). Reload the web server to apply. Custom rule IDs start at 900100 to avoid colliding with the CRS reserved ranges.",
  cloudflare:
    "Add each rule via the Cloudflare dashboard (Security > WAF > Custom rules) or the Rulesets API. Rate-abuse rules belong under Security > WAF > Rate limiting rules.",
  "aws-waf":
    "Add these rules to a Web ACL via the AWS WAFv2 API, console, or CloudFormation (`AWS::WAFv2::WebACL`). Managed rule groups must keep distinct Priority values; associate the Web ACL with your ALB, API Gateway, or CloudFront distribution.",
  "nginx-naxsi":
    "Load the MainRule lines from `naxsi_core.rules` via an `include` in the `http {}` block, then enable per-location enforcement with `SecRulesEnabled` and a `CheckRule` directive. Reload NGINX (`nginx -s reload`) to apply.",
};

export function generateWafRules(input: WafGeneratorInput): WafGeneratorResult {
  let rules: readonly WafRule[];
  switch (input.platform) {
    case "modsecurity":
      rules = generateModsecurity(input);
      break;
    case "cloudflare":
      rules = generateCloudflare(input);
      break;
    case "aws-waf":
      rules = generateAwsWaf(input);
      break;
    case "nginx-naxsi":
      rules = generateNginxNaxsi(input);
      break;
  }

  return {
    platform: input.platform,
    attack_classes: input.protect_against,
    paths_protected: effectivePaths(input.paths_to_protect),
    rules,
    deployment_note: DEPLOYMENT_NOTES[input.platform],
    recommendation:
      "Deploy these rules in detection / count mode first (ModSecurity `SecRuleEngine DetectionOnly`, Cloudflare `log` action, AWS WAF `Count` override, NAXSI `LearningMode`). Review the logs against real traffic for false positives, tune the signatures, and only then switch to a blocking action. A WAF is a compensating control — fix the underlying vulnerabilities in code as well.",
    references: REFERENCES,
  };
}
