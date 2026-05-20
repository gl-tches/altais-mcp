// Security chaos-engineering configuration generator
// (altais_generate_chaos_config).
//
// Produces fault-injection experiment definitions with steady-state
// hypotheses, blast-radius limits, and rollback guidance. The output is
// shaped after Chaos Mesh, LitmusChaos, and AWS FIS; pure text generation.

export type ChaosPlatform = "kubernetes" | "aws" | "linux-host" | "application";

export type ChaosExperimentKind =
  | "network-latency"
  | "dependency-failure"
  | "credential-expiry"
  | "pod-kill"
  | "iam-revocation";

export interface ChaosConfigInput {
  readonly platform: ChaosPlatform;
  readonly experiments: readonly ChaosExperimentKind[];
}

export interface ChaosExperiment {
  readonly kind: ChaosExperimentKind;
  readonly name: string;
  readonly steady_state_hypothesis: string;
  readonly blast_radius: string;
  readonly rollback: string;
  readonly spec: { readonly filename: string; readonly content: string };
}

export interface ChaosConfigResult {
  readonly platform: ChaosPlatform;
  readonly tooling: string;
  readonly principles: readonly string[];
  readonly experiments: readonly ChaosExperiment[];
  readonly references: readonly string[];
}

const REFERENCES: readonly string[] = [
  "https://principlesofchaos.org/",
  "https://chaos-mesh.org/docs/",
  "https://litmuschaos.io/",
  "https://docs.aws.amazon.com/fis/",
];

const PRINCIPLES: readonly string[] = [
  "Define a measurable steady state before injecting any fault — if you cannot measure normal, you cannot detect abnormal.",
  "Form a hypothesis that the steady state holds through the fault; an experiment that disproves it is a finding.",
  "Start in a non-production environment, then graduate to production with a minimized blast radius.",
  "Always have an automated abort condition and rollback so an experiment can be stopped immediately.",
];

const TOOLING: Readonly<Record<ChaosPlatform, string>> = {
  kubernetes: "Chaos Mesh / LitmusChaos",
  aws: "AWS Fault Injection Service (FIS)",
  "linux-host": "Pumba / tc / iptables fault scripts",
  application: "Application-level fault hooks (Toxiproxy / Gremlin SDK)",
};

interface ExperimentMeta {
  readonly hypothesis: string;
  readonly blast_radius: string;
  readonly rollback: string;
}

const EXPERIMENT_META: Readonly<Record<ChaosExperimentKind, ExperimentMeta>> = {
  "network-latency": {
    hypothesis:
      "p99 request latency stays under the SLO and no requests fail when 200ms of latency is injected on a dependency call.",
    blast_radius: "One non-critical service replica; 10% of traffic; a 5-minute window.",
    rollback:
      "Remove the latency injector; latency returns to baseline within one health-check interval.",
  },
  "dependency-failure": {
    hypothesis:
      "The service degrades gracefully (cache / fallback / clear error) and does not cascade when a downstream dependency returns errors.",
    blast_radius: "A single downstream dependency; one service; a 5-minute window.",
    rollback: "Restore the dependency connection; circuit breakers close once health checks pass.",
  },
  "credential-expiry": {
    hypothesis:
      "The service auto-renews or fails closed (no silent fallback to anonymous access) when a credential or token expires mid-flight.",
    blast_radius: "One service instance using a short-lived test credential.",
    rollback: "Reissue a valid credential; the instance recovers without a manual restart.",
  },
  "pod-kill": {
    hypothesis:
      "Killing a pod causes no user-visible errors: the replica set reschedules and load balancers drain connections cleanly.",
    blast_radius: "One pod of a multi-replica deployment; a single namespace.",
    rollback:
      "The deployment controller recreates the pod automatically; experiment self-terminates.",
  },
  "iam-revocation": {
    hypothesis:
      "Revoking an IAM permission produces an explicit access-denied error and an alert — the workload never silently continues with stale access.",
    blast_radius: "One non-production role; one workload; a 10-minute window.",
    rollback: "Re-attach the IAM policy; access is restored and the alert clears.",
  },
};

function k8sSpec(kind: ChaosExperimentKind): { filename: string; content: string } {
  switch (kind) {
    case "network-latency":
      return {
        filename: "chaos/network-latency.yaml",
        content: [
          "apiVersion: chaos-mesh.org/v1alpha1",
          "kind: NetworkChaos",
          "metadata: { name: network-latency, namespace: chaos-testing }",
          "spec:",
          "  action: delay",
          "  mode: one",
          "  selector: { namespaces: [staging], labelSelectors: { app: target } }",
          "  delay: { latency: 200ms, jitter: 20ms }",
          "  duration: 5m",
        ].join("\n"),
      };
    case "pod-kill":
      return {
        filename: "chaos/pod-kill.yaml",
        content: [
          "apiVersion: chaos-mesh.org/v1alpha1",
          "kind: PodChaos",
          "metadata: { name: pod-kill, namespace: chaos-testing }",
          "spec:",
          "  action: pod-kill",
          "  mode: one",
          "  selector: { namespaces: [staging], labelSelectors: { app: target } }",
          "  duration: 1m",
        ].join("\n"),
      };
    case "dependency-failure":
      return {
        filename: "chaos/dependency-failure.yaml",
        content: [
          "apiVersion: chaos-mesh.org/v1alpha1",
          "kind: NetworkChaos",
          "metadata: { name: dependency-failure, namespace: chaos-testing }",
          "spec:",
          "  action: partition",
          "  mode: all",
          "  selector: { namespaces: [staging], labelSelectors: { app: target } }",
          "  direction: to",
          "  target: { selector: { labelSelectors: { app: downstream } }, mode: all }",
          "  duration: 5m",
        ].join("\n"),
      };
    case "credential-expiry":
      return {
        filename: "chaos/credential-expiry.yaml",
        content: [
          "# Schedule a short-lived Secret so the mounted credential expires mid-run.",
          "apiVersion: chaos-mesh.org/v1alpha1",
          "kind: Schedule",
          "metadata: { name: credential-expiry, namespace: chaos-testing }",
          "spec:",
          "  schedule: '@every 10m'",
          "  type: PodChaos",
          "  podChaos:",
          "    action: pod-kill",
          "    mode: one",
          "    selector: { namespaces: [staging], labelSelectors: { app: token-refresher } }",
        ].join("\n"),
      };
    case "iam-revocation":
      return {
        filename: "chaos/iam-revocation.yaml",
        content: [
          "# Kubernetes RBAC revocation experiment driven by a chaos workflow step.",
          "apiVersion: chaos-mesh.org/v1alpha1",
          "kind: Workflow",
          "metadata: { name: rbac-revocation, namespace: chaos-testing }",
          "spec:",
          "  entry: revoke",
          "  templates:",
          "    - name: revoke",
          "      type: Suspend",
          "      deadline: 10m   # detach the RoleBinding for this window, then restore",
        ].join("\n"),
      };
  }
}

function awsSpec(kind: ChaosExperimentKind): { filename: string; content: string } {
  const base = (action: string, params: readonly string[]): string =>
    [
      "{",
      `  "description": "${kind} experiment (AWS FIS)",`,
      '  "stopConditions": [{ "source": "aws:cloudwatch:alarm", "value": "ABORT_ALARM_ARN" }],',
      '  "targets": { "selected": { "resourceType": "aws:ec2:instance", "selectionMode": "COUNT(1)" } },',
      '  "actions": {',
      '    "fault": {',
      `      "actionId": "${action}",`,
      '      "parameters": {',
      params.map((p) => `        ${p}`).join(",\n"),
      "      }",
      "    }",
      "  },",
      '  "roleArn": "FIS_EXECUTION_ROLE_ARN"',
      "}",
    ].join("\n");
  switch (kind) {
    case "network-latency":
      return {
        filename: "chaos/fis-network-latency.json",
        content: base("aws:ssm:send-command/AWSFIS-Run-Network-Latency", [
          '"duration": "PT5M"',
          '"delayMilliseconds": "200"',
        ]),
      };
    case "pod-kill":
      return {
        filename: "chaos/fis-pod-kill.json",
        content: base("aws:eks:pod-delete", ['"kubernetesServiceAccount": "fis-experiment"']),
      };
    case "dependency-failure":
      return {
        filename: "chaos/fis-dependency-failure.json",
        content: base("aws:ssm:send-command/AWSFIS-Run-Network-Blackhole-Port", [
          '"duration": "PT5M"',
          '"port": "443"',
          '"protocol": "tcp"',
        ]),
      };
    case "credential-expiry":
      return {
        filename: "chaos/fis-credential-expiry.json",
        content: base("aws:ssm:send-command/AWSFIS-Run-Kill-Process", [
          '"duration": "PT10M"',
          '"processName": "credential-agent"',
        ]),
      };
    case "iam-revocation":
      return {
        filename: "chaos/fis-iam-revocation.json",
        content: base("aws:iam:revoke-security-credentials", [
          '"rolePolicyArn": "TARGET_ROLE_POLICY_ARN"',
        ]),
      };
  }
}

function genericSpec(
  platform: ChaosPlatform,
  kind: ChaosExperimentKind,
): {
  filename: string;
  content: string;
} {
  const ext = platform === "linux-host" ? "sh" : "yaml";
  if (platform === "linux-host") {
    return {
      filename: `chaos/${kind}.sh`,
      content: [
        "#!/usr/bin/env bash",
        `# ${kind} fault injection on a Linux host. Run with care.`,
        "set -euo pipefail",
        kind === "network-latency"
          ? "tc qdisc add dev eth0 root netem delay 200ms 20ms\nsleep 300\ntc qdisc del dev eth0 root netem"
          : kind === "dependency-failure"
            ? "iptables -A OUTPUT -p tcp --dport 443 -j REJECT\nsleep 300\niptables -D OUTPUT -p tcp --dport 443 -j REJECT"
            : "echo 'Inject the fault here, then restore in a trap handler.'",
      ].join("\n"),
    };
  }
  return {
    filename: `chaos/${kind}.${ext}`,
    content: [
      `# ${kind} application-level fault hook`,
      "experiment:",
      `  name: ${kind}`,
      "  inject: true",
      "  duration_seconds: 300",
      "  abort_on_alarm: true",
    ].join("\n"),
  };
}

function specFor(
  platform: ChaosPlatform,
  kind: ChaosExperimentKind,
): {
  filename: string;
  content: string;
} {
  switch (platform) {
    case "kubernetes":
      return k8sSpec(kind);
    case "aws":
      return awsSpec(kind);
    case "linux-host":
    case "application":
      return genericSpec(platform, kind);
  }
}

export class ChaosConfigError extends Error {
  override readonly name = "ChaosConfigError";
}

export function generateChaosConfig(input: ChaosConfigInput): ChaosConfigResult {
  if (input.experiments.length === 0) {
    throw new ChaosConfigError("`experiments` must list at least one experiment to generate.");
  }
  const seen = new Set<ChaosExperimentKind>();
  const experiments: ChaosExperiment[] = [];
  for (const kind of input.experiments) {
    if (seen.has(kind)) continue;
    seen.add(kind);
    const meta = EXPERIMENT_META[kind];
    experiments.push({
      kind,
      name: `${input.platform}-${kind}`,
      steady_state_hypothesis: meta.hypothesis,
      blast_radius: meta.blast_radius,
      rollback: meta.rollback,
      spec: specFor(input.platform, kind),
    });
  }
  return {
    platform: input.platform,
    tooling: TOOLING[input.platform],
    principles: PRINCIPLES,
    experiments,
    references: REFERENCES,
  };
}
