# `altais_attack_tree`

Match an attacker goal to a built-in attack-tree template.

| Property | Value |
|----------|-------|
| Module | [`threat_model`](../modules/threat_model.md) |
| Tool type | Generator (returns an artifact) |
| Annotations | `readOnlyHint: true` · `destructiveHint: false` · `idempotentHint: true` · `openWorldHint: false` |

## Description

Matches a plain-text attacker goal against a set of built-in attack-tree templates (account takeover, data exfiltration, RCE, privilege escalation, DoS, supply chain) and returns a structured tree of attack paths with mitigations and CWE references. When no template matches it falls back to a generic STRIDE-shaped tree. An agent calls this to enumerate how an attacker might reach a goal.

## Input parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `goal` | `string` (1–256 chars) | Yes | The attacker's goal in plain text. Keywords are matched to a known template or a generic tree. |
| `asset` | `string` (1–256 chars) | No | Target asset, e.g. `customer database`. |
| `context` | `string` (1–2048 chars) | No | Additional context about the system. |

## Output

A generated artifact: `{ goal, tree }`, where `tree` is a structured node graph. Each node has a `node` label and a `children` array; leaf nodes carry a `difficulty`, `cwe` references, and `mitigations`. This tool does not emit session findings.

## Example

**Request**

```json
{ "goal": "account takeover", "asset": "customer accounts" }
```

**Response (excerpt)**

```json
{
  "goal": "account takeover",
  "tree": {
    "node": "...",
    "children": [
      { "node": "...", "difficulty": "...", "cwe": ["..."], "mitigations": ["..."] }
    ]
  }
}
```

## Detections

The generated artifact contains:

- A root node representing the attacker's goal.
- Child nodes representing attack paths toward the goal.
- A difficulty estimate, CWE references, and mitigations on the leaf nodes.

Goal keywords map to templates for account takeover, data exfiltration, RCE, privilege escalation, DoS, and supply-chain attacks; unmatched goals fall back to a generic STRIDE-shaped tree.

## Related tools

- [`altais_stride`](altais_stride.md) — component-level STRIDE breakdown
- [`altais_dread`](altais_dread.md) — scores the severity of a threat the tree exposes

## See also

- [`threat_model` module](../modules/threat_model.md)
- [Wiki home](../Home.md) · [Contributing](../Contributing.md) · [Deployment](../Deployment.md)
