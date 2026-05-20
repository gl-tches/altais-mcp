# `altais_generate_security_txt`

Generates an RFC 9116 `security.txt` file body.

| Property | Value |
|----------|-------|
| Module | [`incident`](../modules/incident.md) |
| Tool type | Generator (returns an artifact) |
| Annotations | `readOnlyHint: true` · `destructiveHint: false` · `idempotentHint: true` · `openWorldHint: false` |

## Description

Produces a `security.txt` file body conforming to RFC 9116. It emits valid field syntax with a required `Contact` field and a future-dated `Expires` field, plus optional `Encryption`, `Policy`, `Acknowledgments`, `Preferred-Languages`, `Canonical`, and `Hiring` fields, and a placement note for `/.well-known/security.txt`. An agent calls this when an organization wants a standards-compliant security-contact disclosure file.

## Input parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `config` | `object` | Yes | The `security.txt` field set (strict — no unknown keys). |
| `config.contact` | `string` (1–512 chars) | Yes | The contact — an email address or a `mailto:` / `https:` URL. |
| `config.encryption` | `string` (1–512 chars) | No | URL of a public key for encrypted reports. |
| `config.policy` | `string` (1–512 chars) | No | URL of the security / disclosure policy. |
| `config.acknowledgments` | `string` (1–512 chars) | No | URL of a security acknowledgments / hall-of-fame page. |
| `config.preferred_languages` | `string` (1–256 chars) | No | Comma-separated language tags, e.g. `en, fr`. |
| `config.canonical` | `string` (1–512 chars) | No | The canonical URL where this `security.txt` is located. |
| `config.hiring` | `string` (1–512 chars) | No | URL of security-related job openings. |
| `config.expires_days` | `integer` (1–3650) | No | Days until the file expires. Defaults to `365`. |

## Output

Returns a generated artifact as JSON. It includes the `content` — the full `security.txt` file body with a `Contact` field, a future-dated `Expires` field, and any optional fields supplied — and a `placement` note indicating the file belongs at `/.well-known/security.txt`. No findings are emitted.

## Example

**Request**

```json
{ "config": { "contact": "mailto:security@example.com" } }
```

**Response (excerpt)**

```json
{
  "content": "Contact: mailto:security@example.com\nExpires: 2027-05-20T00:00:00Z\n",
  "placement": "/.well-known/security.txt"
}
```

## Detections

This is a generator. The artifact is an RFC 9116 `security.txt` body with a required `Contact` field, a future-dated `Expires` field, optional `Encryption`, `Policy`, `Acknowledgments`, `Preferred-Languages`, `Canonical`, and `Hiring` fields, and a placement note for `/.well-known/security.txt`.

## Related tools

- [`altais_generate_disclosure_program`](altais_generate_disclosure_program.md) — generates the disclosure policy that `security.txt` can point to
- [`altais_draft_advisory`](altais_draft_advisory.md) — drafts advisories for reported vulnerabilities
- [`altais_generate_playbook`](altais_generate_playbook.md) — generates incident-response playbooks

## See also

- [`incident` module](../modules/incident.md)
- [Wiki home](../Home.md) · [Contributing](../Contributing.md) · [Deployment](../Deployment.md)
