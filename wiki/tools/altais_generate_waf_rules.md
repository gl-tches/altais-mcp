# `altais_generate_waf_rules`

Generates a ready-to-use Web Application Firewall rule set for a chosen platform.

| Property | Value |
|----------|-------|
| Module | [`runtime`](../modules/runtime.md) |
| Tool type | Generator (returns an artifact) |
| Annotations | `readOnlyHint: true` · `destructiveHint: false` · `idempotentHint: true` · `openWorldHint: false` |

## Description

Produces a Web Application Firewall rule set in the native syntax of a chosen platform — ModSecurity SecRules, a Cloudflare ruleset expression, an AWS WAFv2 rule JSON document, or NGINX/NAXSI directives — covering the requested attack classes. It returns the rule definitions, an optional path scope, a platform-specific deployment note, and a recommendation to run in detection mode before enforcing. An agent calls this when standing up or hardening edge protections.

## Input parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `config` | `object` | Yes | The WAF rule configuration. |
| `config.platform` | `enum` | Yes | The target WAF platform: `modsecurity`, `cloudflare`, `aws-waf`, or `nginx-naxsi`. |
| `config.protect_against` | `array` of `enum` (1–7 items) | Yes | Attack classes the rules should block: `sql-injection`, `xss`, `path-traversal`, `rce`, `ssrf`, `scanner`, and/or `rate-abuse`. |
| `config.paths_to_protect` | `array` of `string` (1–512 chars, max 64 items) | No | URL path globs to scope the rules to, e.g. `/api/*`. Defaults to all paths. |

## Output

Returns a generated artifact as JSON. It includes the target `platform`, a `rules` array of platform-native rule definitions, a `deployment_note` specific to the platform, and a `recommendation` to run in detection mode before enforcing. When `paths_to_protect` is supplied, the rules are scoped to those path globs. No findings are emitted.

## Example

**Request**

```json
{ "config": { "platform": "modsecurity", "protect_against": ["sql-injection", "xss"] } }
```

**Response (excerpt)**

```json
{
  "platform": "modsecurity",
  "rules": ["SecRule ARGS \"@detectSQLi\" \"id:1001,deny,status:403\""],
  "deployment_note": "Load the rules after the OWASP CRS.",
  "recommendation": "Run in detection mode before enforcing."
}
```

## Detections

This is a generator. The artifact is a platform-native WAF rule set (ModSecurity SecRules, a Cloudflare ruleset expression, an AWS WAFv2 rule JSON document, or NGINX/NAXSI directives) covering SQL injection, XSS, path traversal, RCE / command injection, SSRF, scanner traffic, and request-rate abuse — plus an optional path scope, a deployment note, and a detection-mode-first recommendation.

## Related tools

- [`altais_recommend_rasp`](altais_recommend_rasp.md) — recommends in-process runtime protection
- [`altais_audit_monitoring`](altais_audit_monitoring.md) — audits monitoring and alerting coverage
- [`altais_audit_api_gateway`](altais_audit_api_gateway.md) — reviews API gateway WAF and TLS configuration

## See also

- [`runtime` module](../modules/runtime.md)
- [Wiki home](../Home.md) · [Contributing](../Contributing.md) · [Deployment](../Deployment.md)
