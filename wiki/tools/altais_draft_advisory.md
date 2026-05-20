# `altais_draft_advisory`

Drafts a security advisory in the GitHub Security Advisory (GHSA) markdown format.

| Property | Value |
|----------|-------|
| Module | [`incident`](../modules/incident.md) |
| Tool type | Generator (returns an artifact) |
| Annotations | `readOnlyHint: true` · `destructiveHint: false` · `idempotentHint: true` · `openWorldHint: false` |

## Description

Produces a security advisory in the GitHub Security Advisory (GHSA) format as markdown: a summary, a severity rating with optional CVSS vector and CVE, affected and patched versions, impact, remediation guidance, references (NVD and CWE links), a disclosure timeline, and credits. An agent calls this when a vulnerability has been confirmed and a publishable advisory is needed.

## Input parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `config` | `object` | Yes | The advisory content (strict — no unknown keys). |
| `config.title` | `string` (1–256 chars) | Yes | Advisory title / vulnerability name. |
| `config.severity` | `enum` | Yes | GHSA-style severity: `critical`, `high`, `moderate`, or `low`. |
| `config.cve` | `string` (1–32 chars) | No | A CVE identifier, e.g. `CVE-2024-12345`. |
| `config.cwe` | `array` of `string` (1–32 chars, max 20) | No | List of CWE identifiers. |
| `config.affected_versions` | `string` (1–256 chars) | No | Affected version range, e.g. `>= 2.0.0, < 2.4.1`. |
| `config.patched_version` | `string` (1–128 chars) | No | First fixed version. |
| `config.description` | `string` (1–8192 chars) | No | Plain-language description of the vulnerability. |
| `config.impact` | `string` (1–4096 chars) | No | Who is affected and what an attacker can achieve. |
| `config.cvss_vector` | `string` (1–512 chars) | No | A CVSS vector string. |
| `config.credits` | `string` (1–512 chars) | No | Credit for the reporter(s). |

## Output

Returns a generated artifact as JSON containing a `markdown` field — the full advisory in GHSA format with a summary, severity rating (and optional CVSS vector / CVE), affected and patched versions, impact, remediation guidance, references with NVD and CWE links, a disclosure timeline, and credits. No findings are emitted.

## Example

**Request**

```json
{ "config": { "title": "SSRF in image proxy", "severity": "high", "affected_versions": "< 2.4.1" } }
```

**Response (excerpt)**

```json
{
  "markdown": "## SSRF in image proxy\n\n**Severity:** High\n\n### Affected versions\n< 2.4.1\n"
}
```

## Detections

This is a generator. The artifact is a GHSA-format markdown advisory containing a summary, severity rating with optional CVSS vector and CVE, affected and patched versions, impact, remediation guidance, references (NVD and CWE links), a disclosure timeline, and credits.

## Related tools

- [`altais_generate_playbook`](altais_generate_playbook.md) — generates the response playbook for the underlying incident
- [`altais_generate_security_txt`](altais_generate_security_txt.md) — generates the security-contact file
- [`altais_calculate_cvss`](altais_calculate_cvss.md) — scores the CVSS vector cited in the advisory

## See also

- [`incident` module](../modules/incident.md)
- [Wiki home](../Home.md) · [Contributing](../Contributing.md) · [Deployment](../Deployment.md)
