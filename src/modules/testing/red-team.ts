// Red-team / adversary-simulation scope generator
// (altais_scope_red_team).
//
// Produces an engagement scope: objectives and flags, ATT&CK-mapped TTPs
// to emulate based on the chosen threat-actor profile, rules of engagement,
// deconfliction, and success criteria. Static text generation only.

export type ThreatActorProfile = "opportunistic" | "organized-crime" | "nation-state" | "insider";

export interface RedTeamScopeInput {
  readonly objectives: readonly string[];
  readonly threat_actor_profile: ThreatActorProfile;
  readonly duration_weeks: number;
  readonly constraints: readonly string[];
  readonly assumed_breach: boolean;
}

export interface AttackTtp {
  readonly tactic: string;
  readonly technique_id: string;
  readonly technique: string;
}

export interface RedTeamScopeResult {
  readonly threat_actor_profile: ThreatActorProfile;
  readonly profile_summary: string;
  readonly duration_weeks: number;
  readonly assumed_breach: boolean;
  readonly objectives: readonly string[];
  readonly flags: readonly string[];
  readonly ttps: readonly AttackTtp[];
  readonly rules_of_engagement: readonly string[];
  readonly deconfliction: readonly string[];
  readonly success_criteria: readonly string[];
  readonly references: readonly string[];
}

const REFERENCES: readonly string[] = [
  "https://attack.mitre.org/",
  "https://redteam.guide/",
  "https://www.crest-approved.org/",
];

const PROFILE_SUMMARY: Readonly<Record<ThreatActorProfile, string>> = {
  opportunistic:
    "A low-sophistication actor exploiting known, unpatched weaknesses and exposed credentials with off-the-shelf tooling. Emulates commodity attacks and broad scanning.",
  "organized-crime":
    "A financially motivated, moderately resourced group running phishing, ransomware, and data theft. Emulates established intrusion-set playbooks and hands-on-keyboard operators.",
  "nation-state":
    "A well-resourced, patient actor pursuing strategic objectives with custom tooling, supply-chain access, and strong operational security. Emulates a long-dwell APT.",
  insider:
    "A trusted user with legitimate access abusing it for theft or sabotage. Emulates privilege misuse and detection evasion from inside the perimeter.",
};

// ATT&CK-mapped TTPs, tiered by actor sophistication.
const BASE_TTPS: readonly AttackTtp[] = [
  { tactic: "Reconnaissance", technique_id: "T1595", technique: "Active Scanning" },
  {
    tactic: "Initial Access",
    technique_id: "T1190",
    technique: "Exploit Public-Facing Application",
  },
  { tactic: "Credential Access", technique_id: "T1110", technique: "Brute Force" },
  { tactic: "Discovery", technique_id: "T1087", technique: "Account Discovery" },
];

const CRIME_TTPS: readonly AttackTtp[] = [
  { tactic: "Initial Access", technique_id: "T1566", technique: "Phishing" },
  { tactic: "Execution", technique_id: "T1059", technique: "Command and Scripting Interpreter" },
  {
    tactic: "Privilege Escalation",
    technique_id: "T1068",
    technique: "Exploitation for Privilege Escalation",
  },
  { tactic: "Lateral Movement", technique_id: "T1021", technique: "Remote Services" },
  { tactic: "Impact", technique_id: "T1486", technique: "Data Encrypted for Impact" },
];

const NATION_TTPS: readonly AttackTtp[] = [
  { tactic: "Initial Access", technique_id: "T1195", technique: "Supply Chain Compromise" },
  { tactic: "Persistence", technique_id: "T1098", technique: "Account Manipulation" },
  { tactic: "Defense Evasion", technique_id: "T1070", technique: "Indicator Removal" },
  { tactic: "Command and Control", technique_id: "T1071", technique: "Application Layer Protocol" },
  { tactic: "Exfiltration", technique_id: "T1041", technique: "Exfiltration Over C2 Channel" },
  { tactic: "Collection", technique_id: "T1213", technique: "Data from Information Repositories" },
];

const INSIDER_TTPS: readonly AttackTtp[] = [
  { tactic: "Collection", technique_id: "T1213", technique: "Data from Information Repositories" },
  { tactic: "Exfiltration", technique_id: "T1052", technique: "Exfiltration Over Physical Medium" },
  { tactic: "Defense Evasion", technique_id: "T1078", technique: "Valid Accounts" },
  { tactic: "Impact", technique_id: "T1485", technique: "Data Destruction" },
];

function ttpsFor(profile: ThreatActorProfile): readonly AttackTtp[] {
  switch (profile) {
    case "opportunistic":
      return BASE_TTPS;
    case "organized-crime":
      return [...BASE_TTPS, ...CRIME_TTPS];
    case "nation-state":
      return [...BASE_TTPS, ...CRIME_TTPS, ...NATION_TTPS];
    case "insider":
      return [
        { tactic: "Initial Access", technique_id: "T1078", technique: "Valid Accounts" },
        ...INSIDER_TTPS,
      ];
  }
}

const DEFAULT_FLAGS: readonly string[] = [
  "Domain Admin (or cloud root / organization-owner) privileges.",
  "Read access to the designated crown-jewel data store.",
  "Code-execution on a production host without triggering a detection.",
  "Exfiltration of a marked canary file to an external collector.",
];

const COMMON_ROE: readonly string[] = [
  "The engagement emulates the agreed threat actor — TTP realism takes priority over breadth of coverage.",
  "No data destruction, ransomware detonation, or denial-of-service against production systems.",
  "Discovered third-party or out-of-scope systems are reported, never accessed.",
  "Critical-severity findings are reported immediately, out of band, even mid-engagement.",
  "The red team retains logs of every action with timestamps for the post-engagement replay.",
];

const DECONFLICTION: readonly string[] = [
  "A named white-cell contact is reachable 24/7 for the full engagement window.",
  "Each red-team operator uses pre-shared source IPs / user-agents so the blue team can confirm activity is authorized.",
  "A pre-agreed safe-word pauses the engagement immediately if a real incident is suspected.",
  "A shared deconfliction log records who did what and when, reconciled daily with the blue team.",
];

function successCriteria(assumedBreach: boolean): readonly string[] {
  const base = [
    "Each objective flag is either captured or demonstrably blocked by a control.",
    "Every emulated TTP is mapped to whether it was prevented, detected, or missed.",
    "Detection and response gaps are documented with the specific control that should have fired.",
    "A purple-team replay session walks the blue team through each step for tuning.",
  ];
  return assumedBreach
    ? [
        "Engagement starts from an assumed-breach foothold — measure post-compromise detection and containment, not perimeter strength.",
        ...base,
      ]
    : [
        "Engagement starts with no access — initial-access success and time-to-detect are both measured.",
        ...base,
      ];
}

const MAX_WEEKS = 52;
const MAX_ITEM = 512;

export class RedTeamScopeError extends Error {
  override readonly name = "RedTeamScopeError";
}

export function generateRedTeamScope(input: RedTeamScopeInput): RedTeamScopeResult {
  if (input.objectives.length === 0) {
    throw new RedTeamScopeError("`objectives` must list at least one engagement objective.");
  }
  if (
    !Number.isInteger(input.duration_weeks) ||
    input.duration_weeks < 1 ||
    input.duration_weeks > MAX_WEEKS
  ) {
    throw new RedTeamScopeError(
      `\`duration_weeks\` must be an integer between 1 and ${String(MAX_WEEKS)}.`,
    );
  }
  return {
    threat_actor_profile: input.threat_actor_profile,
    profile_summary: PROFILE_SUMMARY[input.threat_actor_profile],
    duration_weeks: input.duration_weeks,
    assumed_breach: input.assumed_breach,
    objectives: input.objectives.map((o) => o.trim().slice(0, MAX_ITEM)),
    flags: DEFAULT_FLAGS,
    ttps: ttpsFor(input.threat_actor_profile),
    rules_of_engagement: [
      ...COMMON_ROE,
      ...input.constraints.map((c) => `Client constraint: ${c.trim().slice(0, MAX_ITEM)}`),
    ],
    deconfliction: DECONFLICTION,
    success_criteria: successCriteria(input.assumed_breach),
    references: REFERENCES,
  };
}
