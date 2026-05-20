// Incident-response playbook generator (altais_generate_playbook).
//
// Produces a structured, scenario-specific incident-response playbook
// organized along the NIST SP 800-61 lifecycle phases (preparation;
// detection & analysis; containment; eradication; recovery;
// post-incident activity). The output is a self-contained artifact —
// no Finding objects are pushed.

export type PlaybookScenario =
  | "ransomware"
  | "data-breach"
  | "account-takeover"
  | "ddos"
  | "supply-chain-compromise"
  | "insider-threat"
  | "credential-leak"
  | "malware"
  | "phishing";

export interface PlaybookInput {
  readonly scenario: PlaybookScenario;
  readonly context?: string;
}

export interface PlaybookPhase {
  readonly name: string;
  readonly steps: readonly string[];
}

export interface IncidentRole {
  readonly role: string;
  readonly responsibility: string;
}

export interface Playbook {
  readonly scenario: PlaybookScenario;
  readonly title: string;
  readonly framework: string;
  readonly summary: string;
  readonly context?: string;
  readonly roles: readonly IncidentRole[];
  readonly phases: readonly PlaybookPhase[];
  readonly communication: readonly string[];
  readonly references: readonly string[];
}

const FRAMEWORK = "NIST SP 800-61 Rev. 3 incident-response lifecycle";

const REFS: readonly string[] = [
  "https://csrc.nist.gov/pubs/sp/800/61/r3/final",
  "https://www.cisa.gov/resources-tools/services/cisa-incident-response-playbooks",
  "https://owasp.org/www-project-incident-response/",
];

const DEFAULT_ROLES: readonly IncidentRole[] = [
  {
    role: "Incident Commander",
    responsibility:
      "Owns the response, declares severity, makes containment decisions, and is the single point of coordination.",
  },
  {
    role: "Technical Lead",
    responsibility:
      "Drives investigation and remediation: analyzes evidence, scopes the blast radius, and executes containment and eradication.",
  },
  {
    role: "Communications Lead",
    responsibility:
      "Owns internal and external messaging, status updates, and coordination with legal and regulators.",
  },
  {
    role: "Scribe",
    responsibility:
      "Maintains the incident timeline — every action, decision, and finding with a timestamp — for the post-incident review.",
  },
];

interface ScenarioSpec {
  readonly title: string;
  readonly summary: string;
  readonly detection: readonly string[];
  readonly containment: readonly string[];
  readonly eradication: readonly string[];
  readonly recovery: readonly string[];
  readonly communication: readonly string[];
  readonly extraRoles?: readonly IncidentRole[];
}

const COMMON_PREPARATION: readonly string[] = [
  "Confirm the incident-response plan, on-call rotation, and escalation contacts are current and reachable.",
  "Ensure access to logging, EDR, and backup systems via a documented break-glass path that does not depend on possibly-compromised infrastructure.",
  "Keep an out-of-band communication channel (phone bridge, separate chat workspace) ready in case primary systems are unavailable.",
];

const COMMON_POST_INCIDENT: readonly string[] = [
  "Hold a blameless post-incident review within two weeks; reconstruct the timeline from the scribe's notes.",
  "Identify the root cause and every contributing factor; file tracked remediation items with owners and due dates.",
  "Update detections, playbooks, and runbooks with what was learned; close gaps that delayed detection or response.",
  "Record metrics — time to detect, contain, and recover — and report the incident to stakeholders and, where required, regulators.",
];

const SCENARIOS: Readonly<Record<PlaybookScenario, ScenarioSpec>> = {
  ransomware: {
    title: "Ransomware Incident Response Playbook",
    summary:
      "Responding to encryption or extortion malware that has rendered systems or data unavailable.",
    detection: [
      "Confirm the indicators: mass file renames or extension changes, ransom notes, EDR alerts, and a spike in file-write activity.",
      "Identify patient zero and the encryption start time; pull EDR and file-access logs to scope affected hosts and shares.",
      "Determine whether data was exfiltrated before encryption (double-extortion) by reviewing egress and DLP logs.",
    ],
    containment: [
      "Isolate affected hosts from the network immediately — disable switch ports or apply EDR network containment; do not power them off (memory evidence is lost).",
      "Disable the compromised accounts and the file-share permissions the ransomware used to spread.",
      "Protect backups: take backup systems offline or read-only so they cannot be encrypted, and verify a known-good restore point exists.",
    ],
    eradication: [
      "Remove the ransomware binary and persistence mechanisms; identify and close the initial access vector (phishing, exposed RDP, unpatched service).",
      "Rotate all credentials that the affected hosts could have exposed, including service and domain-admin accounts.",
      "Rebuild compromised hosts from clean images rather than cleaning in place.",
    ],
    recovery: [
      "Restore data from verified clean backups; do not pay the ransom without legal, executive, and law-enforcement consultation.",
      "Bring systems back in a controlled order, monitoring closely for re-infection before reconnecting to the wider network.",
      "Validate data integrity and application functionality before declaring recovery complete.",
    ],
    communication: [
      "Notify executive leadership and legal counsel immediately; engage cyber-insurance per the policy's reporting clause.",
      "Report to law enforcement; do not negotiate or pay without legal and law-enforcement guidance.",
      "Prepare customer and regulator notifications if exfiltration of personal data is confirmed.",
    ],
  },
  "data-breach": {
    title: "Data Breach Incident Response Playbook",
    summary:
      "Responding to confirmed or suspected unauthorized access to, or exfiltration of, sensitive data.",
    detection: [
      "Confirm the breach: identify the data accessed, the volume, the time window, and the access path from logs and DLP alerts.",
      "Classify the affected data (PII, PHI, payment data, secrets) to determine regulatory and notification obligations.",
      "Preserve evidence — logs, disk and memory images — before any remediation that could overwrite it.",
    ],
    containment: [
      "Revoke the access used for the breach: disable accounts, rotate keys, and close the exposed endpoint or misconfiguration.",
      "Block the exfiltration channel and the attacker's known infrastructure at the network edge.",
      "Restrict further access to the affected data set while the investigation proceeds.",
    ],
    eradication: [
      "Remove attacker access, persistence, and tooling; close the root-cause vulnerability or misconfiguration.",
      "Rotate every credential and key that was exposed or could have been accessed.",
      "Verify no backdoors or additional compromised accounts remain.",
    ],
    recovery: [
      "Restore normal access controls and confirm the affected systems are clean.",
      "Increase monitoring on the affected data and accounts for a defined heightened-alert period.",
      "Validate that the data exposure has stopped before closing the incident.",
    ],
    communication: [
      "Engage legal counsel to determine breach-notification obligations and deadlines per applicable law (GDPR 72-hour rule, US state laws).",
      "Notify affected individuals and regulators within the required windows; prepare a clear, factual disclosure.",
      "Coordinate a single approved external statement; route all press and customer inquiries through the Communications Lead.",
    ],
  },
  "account-takeover": {
    title: "Account Takeover Incident Response Playbook",
    summary:
      "Responding to an attacker gaining control of one or more legitimate user or service accounts.",
    detection: [
      "Confirm the takeover: review authentication logs for impossible-travel, new devices, MFA changes, and anomalous actions.",
      "Scope the activity performed by the account while compromised — data accessed, changes made, messages sent.",
      "Determine the takeover method: credential stuffing, phishing, session hijack, or MFA bypass.",
    ],
    containment: [
      "Force a session revocation and password reset on the affected account(s); invalidate all active tokens and API keys.",
      "Suspend the account if active malicious use is ongoing; lock down any privileges it was granted during the takeover.",
      "Block the attacker's source addresses and infrastructure.",
    ],
    eradication: [
      "Remove attacker-created artifacts: forwarding rules, OAuth grants, API keys, new accounts, and MFA devices.",
      "Identify and fix the takeover vector — enforce MFA, fix a session-fixation flaw, or harden the credential-reset flow.",
      "Check for lateral movement to other accounts or systems from the compromised account.",
    ],
    recovery: [
      "Restore the account to the legitimate owner after verifying their identity out of band.",
      "Re-enable access with a fresh credential and re-enrolled MFA; monitor the account closely afterwards.",
      "Reverse any unauthorized changes the account made.",
    ],
    communication: [
      "Notify the affected account owner through a verified out-of-band channel.",
      "If the account could reach customer or employee data, engage legal on notification obligations.",
      "Brief support teams in case the compromised account contacted customers.",
    ],
  },
  ddos: {
    title: "Distributed Denial-of-Service Incident Response Playbook",
    summary:
      "Responding to a volumetric, protocol, or application-layer attack degrading service availability.",
    detection: [
      "Confirm the attack: distinguish a DDoS from an organic traffic spike or an outage using traffic graphs and error rates.",
      "Characterize the attack — layer (3/4 volumetric vs. 7 application), vectors, source distribution, and targeted endpoints.",
      "Identify which services are degraded and the customer-facing impact.",
    ],
    containment: [
      "Engage the DDoS-mitigation provider or CDN scrubbing; enable always-on or on-demand mitigation.",
      "Apply rate limiting, geo-blocking, and WAF rules tuned to the observed attack signature.",
      "Scale capacity where it helps absorb the load and shed non-critical traffic.",
    ],
    eradication: [
      "Tune mitigation rules to drop attack traffic while preserving legitimate users; iterate as the attacker adapts.",
      "Identify and harden the resource bottleneck the attack targeted (an expensive endpoint, an unbounded query).",
      "Confirm the attack traffic has subsided before relaxing mitigations.",
    ],
    recovery: [
      "Gradually return to normal capacity and mitigation posture, watching for the attack resuming.",
      "Validate that legitimate traffic is fully served and latency has returned to baseline.",
      "Keep elevated monitoring for a defined window after the attack ends.",
    ],
    communication: [
      "Post a status-page update; keep customers informed of degraded availability and recovery progress.",
      "Coordinate with the upstream ISP and mitigation provider throughout.",
      "Report extortion-linked DDoS to law enforcement.",
    ],
  },
  "supply-chain-compromise": {
    title: "Supply-Chain Compromise Incident Response Playbook",
    summary:
      "Responding to a compromise introduced through a third-party dependency, build system, or vendor.",
    detection: [
      "Confirm the compromised component — a malicious package version, a tampered build artifact, or a breached vendor.",
      "Identify every system, build, and release that consumed the compromised component, and the time window.",
      "Assess what the malicious component could do: credential theft, backdoor, data exfiltration.",
    ],
    containment: [
      "Pin or remove the compromised dependency version; block it in the package registry and build pipeline.",
      "Isolate build systems that may have been compromised; freeze releases until the pipeline is verified clean.",
      "Rotate any secrets the build pipeline or affected systems exposed.",
    ],
    eradication: [
      "Rebuild affected artifacts from a verified-clean dependency set and a trusted build environment.",
      "Remove any backdoor or persistence the malicious component installed in downstream systems.",
      "Verify build-pipeline integrity — signing keys, runners, and dependency sources.",
    ],
    recovery: [
      "Release clean, re-built artifacts to production and to any customers who consumed the compromised version.",
      "Restore normal build and release operations with added integrity checks (SLSA provenance, dependency pinning).",
      "Monitor downstream systems for residual attacker activity.",
    ],
    communication: [
      "Notify the upstream maintainer or vendor and coordinate disclosure.",
      "Inform downstream customers who consumed the compromised artifact; provide a clean version and guidance.",
      "Engage legal on contractual and notification obligations with the affected vendor and customers.",
    ],
  },
  "insider-threat": {
    title: "Insider Threat Incident Response Playbook",
    summary:
      "Responding to malicious or negligent actions by an employee, contractor, or other trusted insider.",
    detection: [
      "Confirm the insider activity discreetly — review DLP, access, and audit logs without tipping off the subject.",
      "Scope what the insider accessed, copied, modified, or destroyed, and over what period.",
      "Engage HR and legal early; preserve evidence in a defensible, chain-of-custody manner.",
    ],
    containment: [
      "Coordinate with HR and legal before acting; revoke the insider's access in step with any HR action to avoid alerting them prematurely.",
      "Disable accounts, badges, VPN, and remote access; collect company devices.",
      "Restrict access to the data and systems the insider targeted.",
    ],
    eradication: [
      "Remove any backdoors, forwarding rules, or extra accounts the insider created.",
      "Revoke credentials and keys the insider held or could have copied.",
      "Verify no automated jobs or scripts the insider left behind remain active.",
    ],
    recovery: [
      "Restore any data the insider deleted or altered from backups.",
      "Reassign the insider's responsibilities and review access for their team.",
      "Monitor the affected systems for delayed or pre-planted actions.",
    ],
    communication: [
      "Keep the investigation strictly need-to-know; coordinate all communication with HR and legal.",
      "Prepare for law-enforcement referral if the activity is criminal.",
      "Brief affected stakeholders only after legal clearance.",
    ],
    extraRoles: [
      {
        role: "HR Partner",
        responsibility:
          "Coordinates employment actions, ensures process is followed, and is the bridge to the insider's management chain.",
      },
      {
        role: "Legal Counsel",
        responsibility:
          "Advises on evidence handling, employment law, and any law-enforcement referral.",
      },
    ],
  },
  "credential-leak": {
    title: "Credential Leak Incident Response Playbook",
    summary:
      "Responding to credentials, API keys, or secrets exposed in code, logs, or a public location.",
    detection: [
      "Confirm the leak: identify the exact secret, where it was exposed (repo, log, paste site), and for how long.",
      "Determine the secret's scope and privileges — what it can access — to assess blast radius.",
      "Check access logs for any use of the secret by an unexpected source after the exposure.",
    ],
    containment: [
      "Revoke or rotate the exposed secret immediately; this is the single highest-priority action.",
      "Invalidate any sessions or tokens derived from the secret.",
      "If the secret cannot be rotated instantly, restrict what it can access while rotation proceeds.",
    ],
    eradication: [
      "Remove the secret from the source — purge it from git history, redact logs, request removal from third-party sites.",
      "Identify how it leaked (hardcoded secret, verbose logging, misconfigured store) and fix that root cause.",
      "Add secret-scanning to CI and pre-commit hooks to prevent recurrence.",
    ],
    recovery: [
      "Distribute the rotated secret to legitimate consumers through a secrets manager, not by copy-paste.",
      "Confirm all dependent systems work with the new secret.",
      "Monitor for use of the old secret, which now indicates an attacker still holds it.",
    ],
    communication: [
      "Notify the owners of every system that consumes the secret so they can pick up the rotation.",
      "If the secret could grant access to customer data, engage legal on notification obligations.",
      "Document the exposure window for the post-incident review.",
    ],
  },
  malware: {
    title: "Malware Incident Response Playbook",
    summary:
      "Responding to non-ransomware malware — trojans, backdoors, cryptominers, or loaders — on company systems.",
    detection: [
      "Confirm the infection from EDR alerts, anomalous processes, network beacons, or unexpected resource use.",
      "Identify the malware family and capabilities; scope every infected host and the infection timeline.",
      "Determine the initial access vector and whether the malware has spread or established C2.",
    ],
    containment: [
      "Isolate infected hosts with EDR network containment; preserve memory before any reboot.",
      "Block the malware's C2 domains and IPs at the network edge.",
      "Disable accounts the malware may have harvested credentials for.",
    ],
    eradication: [
      "Remove the malware and all persistence mechanisms; prefer rebuilding from a clean image over in-place cleaning.",
      "Close the initial access vector — patch the exploited service or fix the delivery channel.",
      "Rotate credentials exposed on the infected hosts.",
    ],
    recovery: [
      "Restore clean hosts to service and monitor closely for re-infection or beaconing.",
      "Confirm endpoint protection and detections cover the observed malware indicators.",
      "Validate normal operation before reconnecting hosts to the production network.",
    ],
    communication: [
      "Notify affected system and data owners.",
      "If the malware accessed sensitive data, engage legal on notification obligations.",
      "Share indicators of compromise with the broader security team and trusted communities.",
    ],
  },
  phishing: {
    title: "Phishing Incident Response Playbook",
    summary:
      "Responding to a phishing campaign targeting employees, including credential-harvesting and malware-delivery lures.",
    detection: [
      "Confirm the campaign from user reports, email-gateway alerts, and reported lure URLs or attachments.",
      "Scope delivery: search the mail system for all copies of the message and identify every recipient.",
      "Determine who interacted — clicked the link, entered credentials, or opened an attachment.",
    ],
    containment: [
      "Purge the phishing message from all mailboxes; block the sender, URLs, and attachment hashes at the gateway.",
      "Reset credentials and revoke sessions for any user who entered them into the phishing page.",
      "Isolate any host where a malicious attachment was opened.",
    ],
    eradication: [
      "Remove any malware delivered by the campaign and close access for any credentials harvested.",
      "Take down or report the phishing infrastructure; submit URLs to blocklists.",
      "Verify no mailbox rules or OAuth grants were created off the compromised accounts.",
    ],
    recovery: [
      "Restore affected accounts and hosts to normal operation after verification.",
      "Confirm gateway rules block the campaign's indicators going forward.",
      "Monitor affected accounts for follow-on activity.",
    ],
    communication: [
      "Warn all employees about the active campaign with the specific lure details and what to do.",
      "Provide targeted follow-up and refresher training to users who interacted with the lure.",
      "If credentials reaching customer data were harvested, engage legal on notification.",
    ],
  },
};

export function generatePlaybook(input: PlaybookInput): Playbook {
  const spec = SCENARIOS[input.scenario];
  const roles: readonly IncidentRole[] =
    spec.extraRoles !== undefined ? [...DEFAULT_ROLES, ...spec.extraRoles] : DEFAULT_ROLES;

  const phases: readonly PlaybookPhase[] = [
    { name: "Preparation", steps: COMMON_PREPARATION },
    { name: "Detection & Analysis", steps: spec.detection },
    { name: "Containment", steps: spec.containment },
    { name: "Eradication", steps: spec.eradication },
    { name: "Recovery", steps: spec.recovery },
    { name: "Post-Incident Activity", steps: COMMON_POST_INCIDENT },
  ];

  const context = input.context?.trim();

  return {
    scenario: input.scenario,
    title: spec.title,
    framework: FRAMEWORK,
    summary: spec.summary,
    ...(context !== undefined && context !== "" ? { context } : {}),
    roles,
    phases,
    communication: spec.communication,
    references: REFS,
  };
}
