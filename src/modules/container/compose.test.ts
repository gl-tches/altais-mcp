import { describe, expect, it } from "vitest";
import { auditCompose } from "./compose.js";

const has = (content: string, rule: string): boolean =>
  auditCompose({ content }).some((f) => f.rule === rule);

describe("auditCompose — host control", () => {
  it("flags privileged mode", () => {
    const c = "services:\n  app:\n    image: app:1.0\n    privileged: true\n";
    expect(has(c, "compose-privileged-container")).toBe(true);
  });

  it("flags host network mode", () => {
    const c = "services:\n  app:\n    image: app:1.0\n    network_mode: host\n";
    expect(has(c, "compose-host-network")).toBe(true);
  });

  it("flags the host PID namespace", () => {
    const c = 'services:\n  app:\n    image: app:1.0\n    pid: "host"\n';
    expect(has(c, "compose-host-pid")).toBe(true);
  });

  it("flags the host IPC namespace", () => {
    const c = "services:\n  app:\n    image: app:1.0\n    ipc: host\n";
    expect(has(c, "compose-host-ipc")).toBe(true);
  });

  it("flags a mounted Docker socket", () => {
    const c =
      "services:\n  app:\n    image: app:1.0\n    volumes:\n      - /var/run/docker.sock:/var/run/docker.sock\n";
    expect(has(c, "compose-docker-socket-mount")).toBe(true);
  });

  it("reports the Docker socket mount exactly once per line", () => {
    const c =
      "services:\n  app:\n    image: app:1.0\n    volumes:\n      - /var/run/docker.sock:/var/run/docker.sock\n";
    const socket = auditCompose({ content: c }).filter(
      (f) => f.rule === "compose-docker-socket-mount",
    );
    expect(socket).toHaveLength(1);
  });

  it("does not flag a clean service", () => {
    const c = "services:\n  app:\n    image: app:1.2.3\n    read_only: true\n";
    const findings = auditCompose({ content: c });
    expect(findings).toHaveLength(0);
  });
});

describe("auditCompose — capabilities and sandbox", () => {
  it("flags a dangerous capability in block form", () => {
    const c = "services:\n  app:\n    image: app:1.0\n    cap_add:\n      - SYS_ADMIN\n";
    expect(has(c, "compose-dangerous-capability")).toBe(true);
  });

  it("flags a dangerous capability in inline-list form", () => {
    const c = 'services:\n  app:\n    image: app:1.0\n    cap_add: ["NET_ADMIN"]\n';
    expect(has(c, "compose-dangerous-capability")).toBe(true);
  });

  it("does not flag cap_drop: [ALL]", () => {
    const c = "services:\n  app:\n    image: app:1.0\n    cap_drop:\n      - ALL\n";
    expect(has(c, "compose-dangerous-capability")).toBe(false);
  });

  it("flags a disabled seccomp profile", () => {
    const c =
      "services:\n  app:\n    image: app:1.0\n    security_opt:\n      - seccomp:unconfined\n";
    expect(has(c, "compose-sandbox-disabled")).toBe(true);
  });

  it("flags a disabled AppArmor profile", () => {
    const c =
      "services:\n  app:\n    image: app:1.0\n    security_opt:\n      - apparmor:unconfined\n";
    expect(has(c, "compose-sandbox-disabled")).toBe(true);
  });
});

describe("auditCompose — secrets and images", () => {
  it("flags a hardcoded password in environment (map form)", () => {
    const c =
      "services:\n  db:\n    image: postgres:16\n    environment:\n      POSTGRES_PASSWORD: supersecret\n";
    expect(has(c, "compose-hardcoded-secret")).toBe(true);
  });

  it("flags a hardcoded secret in environment (list form)", () => {
    const c =
      "services:\n  db:\n    image: mysql:8\n    environment:\n      - MYSQL_ROOT_PASSWORD=rootpw123\n";
    expect(has(c, "compose-hardcoded-secret")).toBe(true);
  });

  it("does not flag an interpolated secret reference", () => {
    const c =
      "services:\n  db:\n    image: postgres:16\n    environment:\n      POSTGRES_PASSWORD: ${DB_PASSWORD}\n";
    expect(has(c, "compose-hardcoded-secret")).toBe(false);
  });

  it("masks the secret value in the finding evidence", () => {
    const c =
      "services:\n  db:\n    image: postgres:16\n    environment:\n      POSTGRES_PASSWORD: supersecret\n";
    const finding = auditCompose({ content: c }).find((f) => f.rule === "compose-hardcoded-secret");
    expect(finding?.evidence ?? "").not.toContain("supersecret");
  });

  it("flags an unpinned :latest image", () => {
    const c = "services:\n  app:\n    image: nginx:latest\n";
    expect(has(c, "compose-unpinned-image")).toBe(true);
  });

  it("flags an untagged image", () => {
    const c = "services:\n  app:\n    image: nginx\n";
    expect(has(c, "compose-unpinned-image")).toBe(true);
  });

  it("does not flag a version-pinned image", () => {
    const c = "services:\n  app:\n    image: nginx:1.27.3\n";
    expect(has(c, "compose-unpinned-image")).toBe(false);
  });

  it("does not flag an image driven by a variable", () => {
    const c = "services:\n  app:\n    image: ${APP_IMAGE}\n";
    expect(has(c, "compose-unpinned-image")).toBe(false);
  });
});

describe("auditCompose — finding shape", () => {
  it("produces deterministic finding IDs across runs", () => {
    const c = "services:\n  app:\n    image: app:latest\n    privileged: true\n";
    const a = auditCompose({ content: c, filename: "docker-compose.yml" });
    const b = auditCompose({ content: c, filename: "docker-compose.yml" });
    expect(a.map((f) => f.id)).toEqual(b.map((f) => f.id));
  });
});
