// Phase 6 — end-to-end test (task 6.3).
//
// Writes a small but realistic multi-file vulnerable sample project into a
// temp directory, then drives a real MCP `Client` (over `InMemoryTransport`)
// against a server with every module enabled. Exercises a representative
// cross-module workflow — file scanning, container / IaC audits, OWASP
// coverage — and asserts the findings consolidate into a coherent report
// with a non-zero risk score.

import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";

import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { afterAll, beforeAll, describe, expect, it } from "vitest";

import { configSchema } from "./config.js";
import { buildServer } from "./index.js";

interface CallResult {
  readonly content?: readonly { readonly type: string; readonly text?: string }[];
  readonly isError?: boolean;
}

interface Finding {
  readonly rule: string;
  readonly module?: string;
}

let tempDir = "";
let server: McpServer | null = null;
let client: Client | null = null;

// ─── The sample vulnerable project ─────────────────────────────────────────

const APP_JS = `// app.js — deliberately vulnerable sample
const express = require("express");
const { exec } = require("child_process");
const app = express();

app.get("/user", (req, res) => {
  // SQL injection — user input concatenated into a query.
  db.query("SELECT * FROM users WHERE id = " + req.params.id, (e, rows) => {
    res.json(rows);
  });
});

app.get("/ping", (req, res) => {
  // Command injection — user input passed to a shell.
  exec("ping -c 1 " + req.query.host, (e, out) => {
    res.send(out);
  });
});

module.exports = app;
`;

const AUTH_JS = `// auth.js — weak authentication
const jwt = require("jsonwebtoken");

// Hardcoded signing secret committed to the repo.
const JWT_SECRET = "supersecret123";

function sign(user) {
  // Weak algorithm choice and an embedded secret.
  return jwt.sign({ sub: user.id }, JWT_SECRET, { algorithm: "HS256" });
}

module.exports = { sign, JWT_SECRET };
`;

const DOCKERFILE = `FROM node:latest
COPY . /app
WORKDIR /app
RUN npm install
USER root
CMD ["node", "app.js"]
`;

const DOCKER_COMPOSE = `version: "3.8"
services:
  api:
    build: .
    privileged: true
    network_mode: host
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock
    environment:
      - API_KEY=hardcoded-secret-value
`;

const MAIN_TF = `resource "aws_security_group" "open" {
  name = "open-sg"

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_s3_bucket" "public" {
  bucket = "my-public-bucket"
  acl    = "public-read"
}
`;

const PACKAGE_LOCK = JSON.stringify(
  {
    name: "vulnerable-sample",
    version: "1.0.0",
    lockfileVersion: 3,
    packages: {
      "node_modules/event-stream": {
        version: "3.3.6",
        resolved: "https://registry.npmjs.org/event-stream/-/event-stream-3.3.6.tgz",
      },
    },
  },
  null,
  2,
);

beforeAll(async () => {
  tempDir = await mkdtemp(path.join(tmpdir(), "altais-e2e-"));
  await Promise.all([
    writeFile(path.join(tempDir, "app.js"), APP_JS, "utf8"),
    writeFile(path.join(tempDir, "auth.js"), AUTH_JS, "utf8"),
    writeFile(path.join(tempDir, "Dockerfile"), DOCKERFILE, "utf8"),
    writeFile(path.join(tempDir, "docker-compose.yml"), DOCKER_COMPOSE, "utf8"),
    writeFile(path.join(tempDir, "main.tf"), MAIN_TF, "utf8"),
    writeFile(path.join(tempDir, "package-lock.json"), PACKAGE_LOCK, "utf8"),
  ]);

  // Enable every module so the full tool set is reachable; the default
  // seven (scan/threat_model/owasp/secrets/headers/supply_chain/auth) are
  // already on. Point scan_file at the sample project.
  const config = configSchema.parse({
    modules: {
      crypto: true,
      container: true,
      code: true,
      data: true,
      iac: true,
      api: true,
      compliance: true,
      infra: true,
      protocol: true,
      vuln_db: true,
      incident: true,
      testing: true,
      sdlc: true,
      ml_security: true,
      agentic: true,
      runtime: true,
    },
    scan: { scan_root: tempDir },
  });

  const built = await buildServer(config);
  server = built.server;

  const [serverTx, clientTx] = InMemoryTransport.createLinkedPair();
  await server.connect(serverTx);

  client = new Client({ name: "altais-e2e", version: "0.0.0" });
  await client.connect(clientTx);
});

afterAll(async () => {
  if (client) await client.close();
  if (server) await server.close();
  if (tempDir) await rm(tempDir, { recursive: true, force: true });
});

function expectClient(): Client {
  if (!client) throw new Error("client not initialized");
  return client;
}

async function call(name: string, args: Record<string, unknown>): Promise<CallResult> {
  return (await expectClient().callTool({ name, arguments: args })) as CallResult;
}

function expectText(result: CallResult): string {
  expect(result.isError).not.toBe(true);
  expect(result.content?.length ?? 0).toBeGreaterThan(0);
  const first = result.content?.[0];
  expect(first?.type).toBe("text");
  return first?.text ?? "";
}

function readSample(name: string): Promise<string> {
  return readFile(path.join(tempDir, name), "utf8");
}

describe("Phase 6 — end-to-end scan of a vulnerable sample project (6.3)", () => {
  it("scans app.js from disk and flags injection vulnerabilities", async () => {
    const parsed = JSON.parse(expectText(await call("altais_scan_file", { path: "app.js" }))) as {
      file: string;
      findings: Finding[];
    };
    expect(parsed.file).toBe("app.js");
    expect(parsed.findings.length).toBeGreaterThan(0);
    expect(parsed.findings.some((f) => f.rule.startsWith("sql-injection"))).toBe(true);
  });

  it("scans auth.js from disk without error", async () => {
    const parsed = JSON.parse(expectText(await call("altais_scan_file", { path: "auth.js" }))) as {
      file: string;
      findings: Finding[];
    };
    expect(parsed.file).toBe("auth.js");
    expect(Array.isArray(parsed.findings)).toBe(true);
  });

  it("scans the committed JWT secret in auth.js", async () => {
    const source = await readSample("auth.js");
    const parsed = JSON.parse(
      expectText(await call("altais_scan_secrets", { source, filename: "auth.js" })),
    ) as { findings: Finding[] };
    expect(parsed.findings.length).toBeGreaterThan(0);
  });

  it("audits the Dockerfile and flags root user / latest base image", async () => {
    const content = await readSample("Dockerfile");
    const parsed = JSON.parse(
      expectText(await call("altais_audit_dockerfile", { content, filename: "Dockerfile" })),
    ) as { summary: { total: number }; findings: Finding[] };
    expect(parsed.summary.total).toBeGreaterThan(0);
  });

  it("audits the docker-compose file and flags privileged / docker.sock", async () => {
    const content = await readSample("docker-compose.yml");
    const parsed = JSON.parse(
      expectText(await call("altais_audit_compose", { content, filename: "docker-compose.yml" })),
    ) as { summary: { total: number }; findings: Finding[] };
    expect(parsed.summary.total).toBeGreaterThan(0);
  });

  it("audits the Terraform file and flags the open security group", async () => {
    const content = await readSample("main.tf");
    const parsed = JSON.parse(
      expectText(await call("altais_audit_terraform", { content, filename: "main.tf" })),
    ) as { summary: { total: number }; findings: Finding[] };
    expect(parsed.summary.total).toBeGreaterThan(0);
  });

  it("maps the accumulated session findings to the OWASP Web Top 10", async () => {
    const parsed = JSON.parse(
      expectText(await call("altais_check_owasp_web", { use_session_findings: true })),
    ) as {
      categories: { id: string; status: string; matched_findings: unknown[] }[];
      summary: { covered: number };
    };
    expect(parsed.summary.covered).toBeGreaterThan(0);
  });

  it("produces a consolidated JSON report spanning multiple modules", async () => {
    const parsed = JSON.parse(expectText(await call("altais_report", { format: "json" }))) as {
      findings: Finding[];
      by_module: { module: string; total: number }[];
    };
    expect(parsed.findings.length).toBeGreaterThan(0);
    // Findings should come from more than one module after the workflow.
    expect(parsed.by_module.length).toBeGreaterThan(1);
    const modules = new Set(parsed.by_module.map((m) => m.module));
    expect(modules.has("scan")).toBe(true);
    // Container and IaC audits ran — at least one of them should appear.
    expect(modules.has("container") || modules.has("iac")).toBe(true);
  });

  it("reports a non-zero risk score after the cross-module scan", async () => {
    const parsed = JSON.parse(expectText(await call("altais_risk_summary", {}))) as {
      risk_score: number;
      total: number;
      by_module: Record<string, number>;
    };
    expect(parsed.total).toBeGreaterThan(0);
    expect(parsed.risk_score).toBeGreaterThan(0);
    expect(Object.keys(parsed.by_module).length).toBeGreaterThan(1);
  });
});
