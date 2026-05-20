# `agentic` module

AI-agent and MCP-server security audits. The module implements the **OWASP Agentic Applications Security Top 10 (2026), categories ASI01–ASI10**, with one auditor per category: goal hijacking (ASI01), tool misuse (ASI02), identity and privilege abuse (ASI03), agentic supply chain (ASI04), unexpected code execution (ASI05), memory and context poisoning (ASI06), insecure inter-agent communication (ASI07), cascading agent failures (ASI08), human-agent trust exploitation (ASI09), and rogue agents (ASI10). An agent enables this module to review the security posture of an agentic or multi-agent system.

| Property | Value |
|----------|-------|
| Module name | `agentic` |
| Status | Opt-in (disabled by default) |
| Config key | `[modules] agentic` in `altais.config.toml` |
| Tools | 10 |

## Tools

| Tool | ASI | Description |
|------|-----|-------------|
| [`altais_audit_goal_hijack`](../tools/altais_audit_goal_hijack.md) | ASI01 | Audits against Agent Goal Hijacking. |
| [`altais_audit_tool_misuse`](../tools/altais_audit_tool_misuse.md) | ASI02 | Audits against Tool Misuse & Exploitation. |
| [`altais_audit_agent_identity`](../tools/altais_audit_agent_identity.md) | ASI03 | Audits against Identity & Privilege Abuse. |
| [`altais_audit_agentic_supply_chain`](../tools/altais_audit_agentic_supply_chain.md) | ASI04 | Audits against Agentic Supply Chain Vulnerabilities. |
| [`altais_audit_code_execution`](../tools/altais_audit_code_execution.md) | ASI05 | Audits against Unexpected Code Execution. |
| [`altais_audit_memory_poisoning`](../tools/altais_audit_memory_poisoning.md) | ASI06 | Audits against Memory & Context Poisoning. |
| [`altais_audit_inter_agent_comms`](../tools/altais_audit_inter_agent_comms.md) | ASI07 | Audits against Insecure Inter-Agent Communication. |
| [`altais_audit_cascading_failures`](../tools/altais_audit_cascading_failures.md) | ASI08 | Audits against Cascading Agent Failures. |
| [`altais_audit_trust_exploitation`](../tools/altais_audit_trust_exploitation.md) | ASI09 | Audits against Human-Agent Trust Exploitation. |
| [`altais_audit_rogue_agents`](../tools/altais_audit_rogue_agents.md) | ASI10 | Audits against Rogue Agents. |

## Enabling this module

All three of these modules are opt-in. Enable one by setting its key to `true` under `[modules]` in `altais.config.toml`. Note `agentic` also has an `[agentic]` config section.

```toml
[modules]
agentic = true

[agentic]
# agentic-module-specific settings
```

## See also

- [Wiki home](../Home.md)
