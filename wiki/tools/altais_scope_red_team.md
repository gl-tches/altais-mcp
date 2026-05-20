# `altais_scope_red_team`

Generates a red-team / adversary-simulation engagement scope.

| Property | Value |
|----------|-------|
| Module | [`testing`](../modules/testing.md) |
| Tool type | Generator (returns an artifact) |
| Annotations | `readOnlyHint: true` · `destructiveHint: false` · `idempotentHint: true` · `openWorldHint: false` |

## Description

Produces a red-team / adversary-simulation engagement scope: objectives and capture flags, MITRE ATT&CK-mapped TTPs to emulate selected by threat-actor profile, rules of engagement, deconfliction procedures, and success criteria. It adapts to assumed-breach versus full-scope starting positions. An agent calls this when planning an adversary-emulation engagement.

## Input parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `config` | `object` | Yes | The red-team engagement configuration. |
| `config.objectives` | `array` of `string` (1–512 chars, 1–40 items) | Yes | Engagement objectives the adversary simulation pursues. |
| `config.threat_actor_profile` | `enum` | Yes | The threat actor whose tradecraft is emulated: `opportunistic`, `organized-crime`, `nation-state`, or `insider`. |
| `config.duration_weeks` | `integer` (1–52) | Yes | Engagement duration in weeks. |
| `config.constraints` | `array` of `string` (1–512 chars, max 40 items) | No | Client constraints folded into the rules of engagement. Defaults to an empty array. |
| `config.assumed_breach` | `boolean` | Yes | Whether the engagement starts from an assumed-breach foothold. |

## Output

Returns a generated artifact as JSON. It includes the `objectives`, a `ttps` array of MITRE ATT&CK-mapped techniques (each with an `attack_id` and `name`) selected by threat-actor profile, a `rules_of_engagement` list including deconfliction procedures, and a `success_criteria` list. The scope adapts to assumed-breach versus full-scope starting positions. No findings are emitted.

## Example

**Request**

```json
{ "config": { "objectives": ["exfiltrate crown-jewel data"], "threat_actor_profile": "nation-state", "duration_weeks": 6, "constraints": [], "assumed_breach": true } }
```

**Response (excerpt)**

```json
{
  "objectives": ["exfiltrate crown-jewel data"],
  "ttps": [{ "attack_id": "T1078", "name": "Valid Accounts" }],
  "rules_of_engagement": ["Deconflict suspected detections with the blue team lead."],
  "success_criteria": ["Reach the crown-jewel data store undetected."]
}
```

## Detections

This is a generator. The artifact is a red-team engagement scope: objectives and capture flags, MITRE ATT&CK-mapped TTPs selected by threat-actor profile (opportunistic, organized crime, nation-state, or insider), rules of engagement, deconfliction procedures, and success criteria — adapted to assumed-breach versus full-scope starting positions.

## Related tools

- [`altais_generate_pentest_scope`](altais_generate_pentest_scope.md) — scopes a narrower penetration test
- [`altais_map_attack`](altais_map_attack.md) — maps weaknesses to MITRE ATT&CK techniques
- [`altais_generate_chaos_config`](altais_generate_chaos_config.md) — generates chaos-engineering experiments

## See also

- [`testing` module](../modules/testing.md)
- [Wiki home](../Home.md) · [Contributing](../Contributing.md) · [Deployment](../Deployment.md)
