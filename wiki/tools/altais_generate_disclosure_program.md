# `altais_generate_disclosure_program`

Generates a coordinated-vulnerability-disclosure or bug-bounty policy document.

| Property | Value |
|----------|-------|
| Module | [`incident`](../modules/incident.md) |
| Tool type | Generator (returns an artifact) |
| Annotations | `readOnlyHint: true` · `destructiveHint: false` · `idempotentHint: true` · `openWorldHint: false` |

## Description

Produces a complete coordinated-vulnerability-disclosure (VDP) or bug-bounty policy document in markdown: an introduction, in-scope and out-of-scope definitions, reporting instructions, the organization's commitments and acknowledgment SLA, researcher expectations, a safe-harbor clause, a rewards section, and references. An agent calls this when an organization needs a published policy for receiving external vulnerability reports.

## Input parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `config` | `object` | Yes | The disclosure-program configuration (strict — no unknown keys). |
| `config.organization` | `string` (1–256 chars) | Yes | The organization the policy is for. |
| `config.contact` | `string` (1–512 chars) | Yes | The reporting contact — an email address or URL. |
| `config.scope_in` | `array` of `string` (1–256 chars, max 100) | No | In-scope systems, domains, and applications. |
| `config.scope_out` | `array` of `string` (1–256 chars, max 100) | No | Out-of-scope systems and services. |
| `config.safe_harbor` | `boolean` | No | Whether to include a safe-harbor clause. Defaults to `true`. |
| `config.bounty` | `boolean` | No | Whether this is a paid bug-bounty program. Defaults to a no-reward VDP. |
| `config.response_sla_days` | `integer` (1–90) | No | Acknowledgment SLA in business days. Defaults to `5`. |

## Output

Returns a generated artifact as JSON containing a `markdown` field — the full VDP or bug-bounty policy document with an introduction, in-scope and out-of-scope sections, reporting instructions, organizational commitments and acknowledgment SLA, researcher expectations, a safe-harbor clause, a rewards section, and references. No findings are emitted.

## Example

**Request**

```json
{ "config": { "organization": "Acme", "contact": "security@acme.example" } }
```

**Response (excerpt)**

```json
{
  "markdown": "# Acme Vulnerability Disclosure Policy\n\n## Reporting\nSend reports to security@acme.example.\n"
}
```

## Detections

This is a generator. The artifact is a coordinated-vulnerability-disclosure (VDP) or bug-bounty policy document covering introduction, in-scope and out-of-scope definitions, reporting instructions, organizational commitments and acknowledgment SLA, researcher expectations, a safe-harbor clause, a rewards section, and references.

## Related tools

- [`altais_generate_security_txt`](altais_generate_security_txt.md) — generates the `security.txt` that points to this policy
- [`altais_draft_advisory`](altais_draft_advisory.md) — drafts advisories for reports received under the program
- [`altais_generate_playbook`](altais_generate_playbook.md) — generates incident-response playbooks

## See also

- [`incident` module](../modules/incident.md)
- [Wiki home](../Home.md) · [Contributing](../Contributing.md) · [Deployment](../Deployment.md)
