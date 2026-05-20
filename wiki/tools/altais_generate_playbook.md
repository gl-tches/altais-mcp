# `altais_generate_playbook`

Generates a scenario-specific incident-response playbook organized along the NIST SP 800-61 lifecycle.

| Property | Value |
|----------|-------|
| Module | [`incident`](../modules/incident.md) |
| Tool type | Generator (returns an artifact) |
| Annotations | `readOnlyHint: true` · `destructiveHint: false` · `idempotentHint: true` · `openWorldHint: false` |

## Description

Produces a structured incident-response playbook tailored to a chosen incident scenario and organized along the NIST SP 800-61 lifecycle phases — preparation, detection & analysis, containment, eradication, recovery, and post-incident activity. Each phase carries concrete steps, response roles, and communication guidance. An agent calls this when an organization needs a ready-to-adopt runbook for a specific class of incident.

## Input parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `scenario` | `enum` | Yes | The incident scenario: `ransomware`, `data-breach`, `account-takeover`, `ddos`, `supply-chain-compromise`, `insider-threat`, `credential-leak`, `malware`, or `phishing`. |
| `context` | `string` (1–4096 chars) | No | Free-text context about the environment or the specific incident. |

## Output

Returns a generated playbook artifact as JSON. It includes the `scenario`, a `phases` object keyed by the NIST SP 800-61 lifecycle phases (`preparation`, `detection_and_analysis`, `containment`, `eradication`, `recovery`, `post_incident`) — each an ordered list of concrete steps — and a `roles` list describing the response roles and communication guidance. No findings are emitted.

## Example

**Request**

```json
{ "scenario": "ransomware" }
```

**Response (excerpt)**

```json
{
  "scenario": "ransomware",
  "phases": {
    "preparation": ["Maintain tested, offline backups."],
    "containment": ["Isolate affected hosts from the network."]
  },
  "roles": ["Incident commander", "Communications lead"]
}
```

## Detections

This is a generator. The artifact is a scenario-specific incident-response playbook covering the six NIST SP 800-61 lifecycle phases (preparation; detection & analysis; containment; eradication; recovery; post-incident activity), with concrete steps, response roles, and communication guidance for the chosen scenario.

## Related tools

- [`altais_draft_advisory`](altais_draft_advisory.md) — drafts a security advisory for post-incident disclosure
- [`altais_recommend_siem`](altais_recommend_siem.md) — recommends detection coverage that feeds the detection phase
- [`altais_check_canary`](altais_check_canary.md) — assesses deception controls that aid early detection

## See also

- [`incident` module](../modules/incident.md)
- [Wiki home](../Home.md) · [Contributing](../Contributing.md) · [Deployment](../Deployment.md)
