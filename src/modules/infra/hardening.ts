// CIS Benchmark hardening checker (altais_check_hardening).
//
// Checks a system's settings against a curated set of high-value,
// CIS-Benchmark-style controls for a chosen platform. Each control names
// one or more setting keys; the analyzer reads those keys from the
// supplied `settings` map and flags the control when the value shows it
// is non-compliant, or when the key is absent (unknown / unverified).

import type { Finding, Severity } from "../../core/types.js";
import { buildInfraFinding } from "./finding.js";

export type HardeningPlatform =
  | "linux"
  | "windows"
  | "docker"
  | "kubernetes"
  | "aws"
  | "gcp"
  | "azure";

export interface HardeningInput {
  readonly platform: HardeningPlatform;
  readonly settings: Readonly<Record<string, unknown>>;
}

const REFS = [
  "https://www.cisecurity.org/cis-benchmarks",
  "https://csrc.nist.gov/pubs/sp/800/123/final",
  "https://owasp.org/www-project-top-ten/",
];

/** How a control's setting value should be interpreted. */
type Expectation = "true" | "false";

interface Control {
  /** Setting key(s) to look up; the first present key is used. */
  readonly keys: readonly string[];
  /** Value expected for the system to be compliant. */
  readonly expect: Expectation;
  readonly rule: string;
  readonly severity: Severity;
  readonly title: string;
  readonly description: string;
  readonly remediation: string;
  readonly cwe: readonly string[];
}

const CONTROLS: Readonly<Record<HardeningPlatform, readonly Control[]>> = {
  linux: [
    {
      keys: ["ssh_root_login_disabled", "permit_root_login"],
      expect: "true",
      rule: "cis-linux-ssh-root-login",
      severity: "high",
      title: "SSH root login is not disabled",
      description:
        "Allowing direct SSH login as root means brute-force and credential attacks target a single, well-known, all-powerful account, and remove per-administrator accountability.",
      remediation:
        "Set `PermitRootLogin no` in `sshd_config`. Administrators log in as named users and elevate with `sudo`.",
      cwe: ["CWE-250", "CWE-284"],
    },
    {
      keys: ["ssh_password_auth_disabled", "password_authentication"],
      expect: "true",
      rule: "cis-linux-ssh-password-auth",
      severity: "high",
      title: "SSH password authentication is enabled",
      description:
        "Password-based SSH is exposed to online brute-force and credential-stuffing. Key-based authentication is not guessable and is the CIS-recommended posture.",
      remediation:
        "Set `PasswordAuthentication no` in `sshd_config` and require SSH public-key (or certificate) authentication.",
      cwe: ["CWE-308", "CWE-287"],
    },
    {
      keys: ["automatic_updates_enabled", "unattended_upgrades"],
      expect: "true",
      rule: "cis-linux-automatic-updates",
      severity: "medium",
      title: "Automatic security updates are not enabled",
      description:
        "Without automated patching, disclosed vulnerabilities stay exploitable until an operator manually intervenes, widening the window of exposure.",
      remediation:
        "Enable unattended security updates (for example `unattended-upgrades` on Debian/Ubuntu or `dnf-automatic` on RHEL).",
      cwe: ["CWE-1104"],
    },
    {
      keys: ["audit_daemon_enabled", "auditd_enabled"],
      expect: "true",
      rule: "cis-linux-audit-daemon",
      severity: "medium",
      title: "The audit daemon (auditd) is not enabled",
      description:
        "Without auditd, security-relevant events are not recorded, so an intrusion cannot be detected or reconstructed after the fact.",
      remediation:
        "Install and enable `auditd`, and configure CIS-recommended audit rules covering authentication, privilege use, and sensitive file access.",
      cwe: ["CWE-778"],
    },
    {
      keys: ["firewall_enabled", "host_firewall"],
      expect: "true",
      rule: "cis-linux-firewall",
      severity: "high",
      title: "Host firewall is not enabled",
      description:
        "With no host firewall, every listening service is reachable by anything that can route to the host, regardless of whether it was meant to be exposed.",
      remediation:
        "Enable a host firewall (`nftables` / `ufw` / `firewalld`) with a default-deny inbound policy, allowing only required ports.",
      cwe: ["CWE-1008", "CWE-284"],
    },
    {
      keys: ["world_writable_files_present", "world_writable_files"],
      expect: "false",
      rule: "cis-linux-world-writable-files",
      severity: "medium",
      title: "World-writable files are present on the system",
      description:
        "World-writable files can be modified by any local user. If such a file is a script, config, or library used by a privileged process, it becomes a local privilege-escalation path.",
      remediation:
        "Locate world-writable files (`find / -xdev -type f -perm -0002`) and remove the world-write bit unless a directory explicitly requires it (and then add the sticky bit).",
      cwe: ["CWE-732"],
    },
  ],
  windows: [
    {
      keys: ["smbv1_disabled"],
      expect: "true",
      rule: "cis-windows-smbv1",
      severity: "high",
      title: "SMBv1 is not disabled",
      description:
        "SMBv1 is an obsolete, unauthenticated-attack-prone protocol (the EternalBlue family). CIS requires it to be removed.",
      remediation:
        "Uninstall the SMB 1.0/CIFS feature on every Windows host; modern clients negotiate SMBv2/3.",
      cwe: ["CWE-1104"],
    },
    {
      keys: ["bitlocker_enabled", "disk_encryption_enabled"],
      expect: "true",
      rule: "cis-windows-disk-encryption",
      severity: "high",
      title: "BitLocker full-disk encryption is not enabled",
      description:
        "Without full-disk encryption, data on a lost or stolen device — or a decommissioned disk — is readable by anyone who obtains the hardware.",
      remediation:
        "Enable BitLocker on all fixed and removable drives, backed by the TPM, and escrow recovery keys centrally.",
      cwe: ["CWE-311"],
    },
    {
      keys: ["windows_firewall_enabled"],
      expect: "true",
      rule: "cis-windows-firewall",
      severity: "high",
      title: "Windows Defender Firewall is not enabled",
      description:
        "With Windows Firewall off, every listening service is reachable across all network profiles, removing the host-level network boundary.",
      remediation:
        "Enable Windows Defender Firewall for the Domain, Private, and Public profiles with a default inbound-block policy.",
      cwe: ["CWE-1008", "CWE-284"],
    },
    {
      keys: ["automatic_updates_enabled"],
      expect: "true",
      rule: "cis-windows-automatic-updates",
      severity: "medium",
      title: "Automatic updates are not enabled",
      description:
        "Without automatic updates, disclosed Windows vulnerabilities remain exploitable until an operator manually patches each host.",
      remediation:
        "Configure automatic updates via Windows Update for Business or WSUS so security updates install on a defined cadence.",
      cwe: ["CWE-1104"],
    },
    {
      keys: ["uac_enabled"],
      expect: "true",
      rule: "cis-windows-uac",
      severity: "medium",
      title: "User Account Control (UAC) is not enabled",
      description:
        "UAC enforces the prompt and consent boundary for privilege elevation. Disabling it lets any process run with full administrative rights silently.",
      remediation:
        "Enable UAC and keep it at the default or higher prompt level so elevation requires explicit consent.",
      cwe: ["CWE-250"],
    },
  ],
  docker: [
    {
      keys: ["privileged_containers_present", "privileged"],
      expect: "false",
      rule: "cis-docker-privileged",
      severity: "high",
      title: "Containers run with the --privileged flag",
      description:
        "`--privileged` disables nearly all container isolation: the container gets every capability and host device access, so a process escape leads straight to host compromise.",
      remediation:
        "Never run containers with `--privileged`. Grant only the specific capabilities and devices each workload needs.",
      cwe: ["CWE-250", "CWE-269"],
    },
    {
      keys: ["userns_remap_enabled", "user_namespace_remap"],
      expect: "true",
      rule: "cis-docker-userns-remap",
      severity: "medium",
      title: "User-namespace remapping is not enabled",
      description:
        "Without userns-remap, root inside a container maps to root on the host, so a container breakout retains root privileges.",
      remediation:
        "Enable the daemon's `userns-remap` so container root maps to an unprivileged host UID range.",
      cwe: ["CWE-250", "CWE-269"],
    },
    {
      keys: ["host_mounts_present", "host_path_mounts"],
      expect: "false",
      rule: "cis-docker-host-mounts",
      severity: "high",
      title: "Containers mount sensitive host paths",
      description:
        "Bind-mounting host paths (especially `/`, `/etc`, `/var/run/docker.sock`) lets a container read or tamper with the host filesystem and, via the Docker socket, take over the daemon.",
      remediation:
        "Avoid host bind mounts; use named volumes. Never mount the Docker socket into a container.",
      cwe: ["CWE-668"],
    },
    {
      keys: ["content_trust_enabled", "docker_content_trust"],
      expect: "true",
      rule: "cis-docker-content-trust",
      severity: "medium",
      title: "Docker Content Trust is not enabled",
      description:
        "With Content Trust off, the daemon will pull and run unsigned images, so a tampered or substituted image is accepted without verification.",
      remediation:
        "Set `DOCKER_CONTENT_TRUST=1` (or an equivalent admission policy) so only signed images are pulled and run.",
      cwe: ["CWE-494"],
    },
    {
      keys: ["live_restore_enabled"],
      expect: "true",
      rule: "cis-docker-live-restore",
      severity: "low",
      title: "Daemon live-restore is not enabled",
      description:
        "Without `live-restore`, restarting or upgrading the Docker daemon kills all running containers, which can cause unplanned outages during routine patching.",
      remediation:
        "Enable `live-restore` in the daemon configuration so containers keep running across daemon restarts.",
      cwe: ["CWE-1188"],
    },
  ],
  kubernetes: [
    {
      keys: ["anonymous_auth_disabled", "anonymous_auth"],
      expect: "true",
      rule: "cis-k8s-anonymous-auth",
      severity: "high",
      title: "API server anonymous authentication is enabled",
      description:
        "With `--anonymous-auth` on, unauthenticated requests reach the API server as the `system:anonymous` user, and any RBAC binding to that user becomes an unauthenticated entry point.",
      remediation:
        "Start the kube-apiserver with `--anonymous-auth=false` so every request must present credentials.",
      cwe: ["CWE-306", "CWE-287"],
    },
    {
      keys: ["rbac_enabled", "rbac_authorization"],
      expect: "true",
      rule: "cis-k8s-rbac",
      severity: "high",
      title: "RBAC authorization is not enabled",
      description:
        "Without RBAC, the API server falls back to permissive authorization modes (such as `AlwaysAllow`), so any authenticated principal can perform any action cluster-wide.",
      remediation:
        "Include `RBAC` in the API server `--authorization-mode` and remove `AlwaysAllow`. Grant least-privilege Roles and RoleBindings.",
      cwe: ["CWE-284", "CWE-285"],
    },
    {
      keys: ["audit_logging_enabled", "api_audit_logging"],
      expect: "true",
      rule: "cis-k8s-audit-logging",
      severity: "medium",
      title: "API server audit logging is not enabled",
      description:
        "Without an audit policy and log backend, API server actions are not recorded, so cluster intrusions cannot be detected or investigated.",
      remediation:
        "Configure the kube-apiserver with `--audit-policy-file` and an audit log or webhook backend, capturing metadata for sensitive resources.",
      cwe: ["CWE-778"],
    },
    {
      keys: ["privileged_pods_present", "privileged_pods_allowed"],
      expect: "false",
      rule: "cis-k8s-privileged-pods",
      severity: "high",
      title: "Privileged pods are allowed in the cluster",
      description:
        "A privileged pod (or one with `hostPID`, `hostNetwork`, or dangerous capabilities) can break out to the node and from there pivot across the cluster.",
      remediation:
        "Enforce the restricted Pod Security Standard via Pod Security Admission, or an admission controller, to reject privileged and host-namespace pods.",
      cwe: ["CWE-250", "CWE-269"],
    },
    {
      keys: ["network_policies_enabled", "default_deny_network_policy"],
      expect: "true",
      rule: "cis-k8s-network-policy",
      severity: "medium",
      title: "No default-deny NetworkPolicy is in place",
      description:
        "By default every pod can reach every other pod. Without a default-deny NetworkPolicy a compromised pod has unrestricted lateral reach across all namespaces.",
      remediation:
        "Apply a default-deny NetworkPolicy per namespace and explicitly allow only the pod-to-pod flows each workload requires.",
      cwe: ["CWE-1008", "CWE-668"],
    },
  ],
  aws: [
    {
      keys: ["root_mfa_enabled", "root_account_mfa"],
      expect: "true",
      rule: "cis-aws-root-mfa",
      severity: "high",
      title: "MFA is not enabled on the AWS root account",
      description:
        "The root account has unrestricted control of the AWS account. Without MFA, a single leaked root credential gives an attacker total, unrecoverable control.",
      remediation:
        "Enable a hardware MFA device on the root account, store the credentials offline, and use IAM roles for all routine work.",
      cwe: ["CWE-308", "CWE-287"],
    },
    {
      keys: ["cloudtrail_multi_region_enabled", "cloudtrail_enabled"],
      expect: "true",
      rule: "cis-aws-cloudtrail",
      severity: "high",
      title: "CloudTrail is not enabled for all regions",
      description:
        "Without a multi-region CloudTrail, API activity in unmonitored regions is unrecorded, so attacker actions there leave no audit trail.",
      remediation:
        "Create a multi-region CloudTrail with log file validation, delivering to a dedicated, access-restricted S3 bucket.",
      cwe: ["CWE-778"],
    },
    {
      keys: ["s3_public_access_block_enabled", "s3_block_public_access"],
      expect: "true",
      rule: "cis-aws-s3-public-access",
      severity: "high",
      title: "S3 account-level public access block is not enabled",
      description:
        "Without the account-level Block Public Access setting, a single misconfigured bucket policy or ACL can expose stored data to the entire internet.",
      remediation:
        "Enable S3 Block Public Access at the account level so no bucket can be made public regardless of its individual policy.",
      cwe: ["CWE-284", "CWE-668"],
    },
    {
      keys: ["default_vpc_unused", "default_vpc_in_use"],
      expect: "true",
      rule: "cis-aws-default-vpc",
      severity: "low",
      title: "The default VPC is in use",
      description:
        "The default VPC ships with permissive defaults and an internet-routable layout. CIS recommends not deploying workloads into it.",
      remediation:
        "Deploy workloads into purpose-built VPCs with reviewed routing and security groups; leave the default VPC empty.",
      cwe: ["CWE-1008"],
    },
    {
      keys: ["iam_password_policy_strong", "password_policy_configured"],
      expect: "true",
      rule: "cis-aws-password-policy",
      severity: "medium",
      title: "A strong IAM password policy is not configured",
      description:
        "Without an enforced password policy, IAM users can set short, simple, never-expiring passwords, weakening every console login.",
      remediation:
        "Configure an IAM password policy with minimum length, complexity, reuse prevention, and rotation in line with CIS guidance.",
      cwe: ["CWE-521"],
    },
  ],
  gcp: [
    {
      keys: ["audit_logging_enabled", "cloud_audit_logs_enabled"],
      expect: "true",
      rule: "cis-gcp-audit-logging",
      severity: "high",
      title: "Cloud Audit Logs are not fully enabled",
      description:
        "Without Data Access and Admin Activity audit logs, actions in the GCP project are not recorded, so a compromise cannot be detected or investigated.",
      remediation:
        "Enable Cloud Audit Logs (Admin Activity and Data Access) for all services and export them to a retained, access-restricted sink.",
      cwe: ["CWE-778"],
    },
    {
      keys: ["service_account_keys_rotated", "no_user_managed_sa_keys"],
      expect: "true",
      rule: "cis-gcp-sa-keys",
      severity: "high",
      title: "User-managed service-account keys are in use",
      description:
        "Long-lived user-managed service-account keys are a frequently leaked credential. CIS recommends avoiding them in favor of short-lived, automatically rotated credentials.",
      remediation:
        "Avoid user-managed service-account keys; use Workload Identity Federation or attached service accounts, and rotate any remaining keys.",
      cwe: ["CWE-798", "CWE-321"],
    },
    {
      keys: ["os_login_enabled"],
      expect: "true",
      rule: "cis-gcp-os-login",
      severity: "medium",
      title: "OS Login is not enabled for Compute Engine",
      description:
        "Without OS Login, SSH access is governed by project-wide metadata keys rather than IAM, breaking centralized, auditable access control.",
      remediation:
        "Enable OS Login project-wide so Compute Engine SSH access is managed and audited through IAM.",
      cwe: ["CWE-284"],
    },
    {
      keys: ["default_network_unused", "default_network_in_use"],
      expect: "true",
      rule: "cis-gcp-default-network",
      severity: "low",
      title: "The default VPC network is in use",
      description:
        "The default network ships with permissive pre-populated firewall rules (including broad SSH/RDP). CIS recommends not using it for workloads.",
      remediation:
        "Delete or avoid the default network; deploy workloads into custom-mode VPCs with explicitly reviewed firewall rules.",
      cwe: ["CWE-1008"],
    },
    {
      keys: ["bucket_uniform_access_enabled", "uniform_bucket_level_access"],
      expect: "true",
      rule: "cis-gcp-bucket-uniform-access",
      severity: "medium",
      title: "Cloud Storage uniform bucket-level access is not enforced",
      description:
        "With per-object ACLs still permitted, access to a bucket is hard to reason about and a single object ACL can expose data unexpectedly.",
      remediation:
        "Enable uniform bucket-level access so all access is governed consistently by IAM rather than per-object ACLs.",
      cwe: ["CWE-284"],
    },
  ],
  azure: [
    {
      keys: ["mfa_enabled_all_users", "mfa_enforced"],
      expect: "true",
      rule: "cis-azure-mfa",
      severity: "high",
      title: "MFA is not enforced for all Entra ID users",
      description:
        "Without enforced MFA, every Entra ID account is one phished or reused password away from takeover, including privileged roles.",
      remediation:
        "Enforce MFA for all users via Conditional Access, requiring it for privileged roles and risky sign-ins at a minimum.",
      cwe: ["CWE-308", "CWE-287"],
    },
    {
      keys: ["security_defaults_enabled", "conditional_access_configured"],
      expect: "true",
      rule: "cis-azure-security-defaults",
      severity: "medium",
      title: "Security Defaults or Conditional Access is not configured",
      description:
        "Without Security Defaults or Conditional Access policies, baseline protections such as blocking legacy authentication are not applied.",
      remediation:
        "Enable Security Defaults, or configure Conditional Access policies that block legacy authentication and enforce MFA.",
      cwe: ["CWE-1188"],
    },
    {
      keys: ["storage_secure_transfer_enabled", "secure_transfer_required"],
      expect: "true",
      rule: "cis-azure-secure-transfer",
      severity: "high",
      title: "Storage account 'secure transfer required' is disabled",
      description:
        "With secure transfer off, a storage account accepts plaintext HTTP requests, exposing data and access keys to network interception.",
      remediation:
        "Enable 'Secure transfer required' on every storage account so only HTTPS connections are accepted.",
      cwe: ["CWE-319"],
    },
    {
      keys: ["activity_log_retention_enabled", "diagnostic_logging_enabled"],
      expect: "true",
      rule: "cis-azure-activity-log",
      severity: "medium",
      title: "Activity Log retention / diagnostic logging is not configured",
      description:
        "Without retained Activity Logs and diagnostic settings, control-plane actions are not durably recorded, so an incident cannot be reconstructed.",
      remediation:
        "Configure diagnostic settings to export the Activity Log to a Log Analytics workspace or storage account with adequate retention.",
      cwe: ["CWE-778"],
    },
    {
      keys: ["network_watcher_enabled"],
      expect: "true",
      rule: "cis-azure-network-watcher",
      severity: "low",
      title: "Network Watcher is not enabled",
      description:
        "Without Network Watcher, network-level diagnostics and NSG flow logs are unavailable, limiting visibility into traffic and lateral movement.",
      remediation:
        "Enable Network Watcher in every region in use and turn on NSG flow logs for traffic visibility.",
      cwe: ["CWE-778"],
    },
  ],
};

/** Interpret a setting value as a boolean, or undefined if it is not clearly boolean. */
function asBoolean(value: unknown): boolean | undefined {
  if (typeof value === "boolean") return value;
  if (typeof value === "number") {
    if (value === 1) return true;
    if (value === 0) return false;
    return undefined;
  }
  if (typeof value === "string") {
    const v = value.trim().toLowerCase();
    if (v === "true" || v === "yes" || v === "on" || v === "enabled" || v === "1") return true;
    if (v === "false" || v === "no" || v === "off" || v === "disabled" || v === "0") return false;
  }
  return undefined;
}

export function checkHardening(input: HardeningInput): readonly Finding[] {
  const controls = CONTROLS[input.platform];
  const findings: Finding[] = [];

  for (const control of controls) {
    let presentKey: string | undefined;
    let raw: unknown;
    for (const key of control.keys) {
      if (Object.prototype.hasOwnProperty.call(input.settings, key)) {
        presentKey = key;
        raw = input.settings[key];
        break;
      }
    }

    if (presentKey === undefined) {
      // Control not reported on — flag as unverified so the gap is visible.
      findings.push(
        mkFinding(
          control,
          input.platform,
          control.severity === "high" ? "medium" : "low",
          `${control.title.replace(/ is not | are not /, " ")} — control not verified`,
          `${control.description} The supplied settings do not report this control, so its state is unknown and it should be verified explicitly.`,
          `${control.keys[0] ?? control.rule}=absent`,
          "-unverified",
        ),
      );
      continue;
    }

    const actual = asBoolean(raw);
    if (actual === undefined) continue; // value not interpretable as boolean — skip
    const expected = control.expect === "true";
    if (actual !== expected) {
      findings.push(
        mkFinding(
          control,
          input.platform,
          control.severity,
          control.title,
          control.description,
          `${presentKey}=${String(raw)}`,
          "",
        ),
      );
    }
  }

  return findings;
}

function mkFinding(
  control: Control,
  platform: HardeningPlatform,
  severity: Severity,
  title: string,
  description: string,
  evidence: string,
  ruleSuffix: string,
): Finding {
  return buildInfraFinding(
    {
      rule: `${control.rule}${ruleSuffix}`,
      severity,
      title: `[${platform}] ${title}`,
      description,
      remediation: control.remediation,
      cwe: control.cwe,
      references: REFS,
      evidence,
      tags: ["hardening", "cis-benchmark", platform],
    },
    undefined,
  );
}
