# `threat_model` module

The `threat_model` module provides structured threat modeling: a STRIDE breakdown per component, DREAD scoring of individual threats, attack-tree generation from an attacker goal, and trust-boundary analysis of data flows. It works from a structured architecture description rather than from source code, helping agents reason about a system design.

| Property | Value |
|----------|-------|
| Module name | `threat_model` |
| Status | Default-enabled |
| Config key | `[modules] threat_model` in `altais.config.toml` |
| Tools | 4 |

## Tools

| Tool | Description |
|------|-------------|
| [`altais_stride`](../tools/altais_stride.md) | Emit a STRIDE threat breakdown per component from a structured architecture. |
| [`altais_dread`](../tools/altais_dread.md) | Compute a DREAD risk score from five subjective 1–10 ratings. |
| [`altais_attack_tree`](../tools/altais_attack_tree.md) | Match an attacker goal to a built-in attack-tree template. |
| [`altais_trust_boundaries`](../tools/altais_trust_boundaries.md) | Identify data flows that cross trust zones and emit findings for risky crossings. |

## Enabling this module

The `threat_model` module is one of the seven default-enabled modules, so it is active out of the box. To disable it, set `threat_model = false` under `[modules]` in `altais.config.toml`. The default-enabled set is `scan`, `threat_model`, `owasp`, `secrets`, `headers`, `supply_chain`, and `auth`; `core` is always loaded; all other modules are opt-in.

## See also

- [Wiki home](../Home.md)
