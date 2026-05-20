import { describe, expect, it } from "vitest";
import { checkHardening, type HardeningInput } from "./hardening.js";

const run = (input: HardeningInput): ReturnType<typeof checkHardening> => checkHardening(input);

const has = (input: HardeningInput, rule: string): boolean =>
  run(input).some((f) => f.rule === rule);

describe("checkHardening — linux", () => {
  it("flags SSH root login when not disabled", () => {
    expect(
      has(
        { platform: "linux", settings: { ssh_root_login_disabled: false } },
        "cis-linux-ssh-root-login",
      ),
    ).toBe(true);
  });

  it("does not flag SSH root login when disabled", () => {
    expect(
      has(
        { platform: "linux", settings: { ssh_root_login_disabled: true } },
        "cis-linux-ssh-root-login",
      ),
    ).toBe(false);
  });

  it("flags world-writable files when present (false-expectation control)", () => {
    expect(
      has(
        { platform: "linux", settings: { world_writable_files_present: true } },
        "cis-linux-world-writable-files",
      ),
    ).toBe(true);
  });

  it("marks an unreported control as unverified", () => {
    expect(has({ platform: "linux", settings: {} }, "cis-linux-firewall-unverified")).toBe(true);
  });

  it("interprets a string value such as 'enabled'", () => {
    expect(
      has({ platform: "linux", settings: { firewall_enabled: "disabled" } }, "cis-linux-firewall"),
    ).toBe(true);
  });
});

describe("checkHardening — docker and kubernetes", () => {
  it("flags privileged docker containers", () => {
    expect(
      has(
        { platform: "docker", settings: { privileged_containers_present: true } },
        "cis-docker-privileged",
      ),
    ).toBe(true);
  });

  it("flags kubernetes anonymous auth left enabled", () => {
    expect(
      has(
        { platform: "kubernetes", settings: { anonymous_auth_disabled: false } },
        "cis-k8s-anonymous-auth",
      ),
    ).toBe(true);
  });

  it("flags kubernetes RBAC disabled as high severity", () => {
    const f = run({ platform: "kubernetes", settings: { rbac_enabled: false } }).find(
      (x) => x.rule === "cis-k8s-rbac",
    );
    expect(f?.severity).toBe("high");
  });

  it("does not flag a compliant kubernetes control", () => {
    expect(
      has(
        { platform: "kubernetes", settings: { privileged_pods_present: false } },
        "cis-k8s-privileged-pods",
      ),
    ).toBe(false);
  });
});

describe("checkHardening — cloud platforms", () => {
  it("flags AWS root account without MFA", () => {
    expect(
      has({ platform: "aws", settings: { root_mfa_enabled: false } }, "cis-aws-root-mfa"),
    ).toBe(true);
  });

  it("flags an Azure storage account without secure transfer", () => {
    expect(
      has(
        { platform: "azure", settings: { storage_secure_transfer_enabled: false } },
        "cis-azure-secure-transfer",
      ),
    ).toBe(true);
  });

  it("flags GCP user-managed service-account keys in use", () => {
    expect(
      has(
        { platform: "gcp", settings: { service_account_keys_rotated: false } },
        "cis-gcp-sa-keys",
      ),
    ).toBe(true);
  });
});

describe("checkHardening — shape and determinism", () => {
  it("produces deterministic finding IDs across runs", () => {
    const input: HardeningInput = {
      platform: "linux",
      settings: { ssh_root_login_disabled: false },
    };
    expect(run(input).map((f) => f.id)).toEqual(run(input).map((f) => f.id));
  });

  it("tags every finding with the infra module and a CWE", () => {
    const findings = run({ platform: "linux", settings: { ssh_root_login_disabled: false } });
    expect(findings.length).toBeGreaterThan(0);
    for (const f of findings) {
      expect(f.module).toBe("infra");
      expect(f.tags).toContain("infra");
      expect(f.cwe?.length ?? 0).toBeGreaterThan(0);
    }
  });
});
