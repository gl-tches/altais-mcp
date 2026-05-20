// Phase 6 — load test (task 6.5).
//
// Exercises both transports under concurrent load:
//   • stdio  — a single in-memory `Client` firing a batch of concurrent
//     tool calls.
//   • HTTP   — several `StreamableHTTPClientTransport` clients firing
//     concurrent `listTools()` / tool calls against a real HTTP server,
//     plus a batch of unauthenticated `fetch` calls that must all 401.
//
// Iteration counts are kept modest (tens, not thousands) so the suite
// finishes in a few seconds.

import net from "node:net";
import type http from "node:http";

import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";
import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { afterAll, beforeAll, describe, expect, it } from "vitest";

import { configSchema } from "./config.js";
import { buildServer, HTTP_TOKEN_ENV, startHttp } from "./index.js";

interface CallResult {
  readonly content?: readonly { readonly type: string; readonly text?: string }[];
  readonly isError?: boolean;
}

const TOKEN = "load-test-token-0123456789abcdef0123456789abcdef";

function getFreePort(): Promise<number> {
  return new Promise((resolve, reject) => {
    const srv = net.createServer();
    srv.once("error", reject);
    srv.listen(0, "127.0.0.1", () => {
      const addr = srv.address();
      if (addr === null || typeof addr === "string") {
        reject(new Error("could not allocate a port"));
        return;
      }
      const { port } = addr;
      srv.close(() => {
        resolve(port);
      });
    });
  });
}

// ─── stdio transport under load ────────────────────────────────────────────

describe("Phase 6 — stdio transport under concurrent load (6.5)", () => {
  let server: McpServer | null = null;
  let client: Client | null = null;

  beforeAll(async () => {
    const built = await buildServer(configSchema.parse({}));
    server = built.server;
    const [serverTx, clientTx] = InMemoryTransport.createLinkedPair();
    await server.connect(serverTx);
    client = new Client({ name: "altais-load-stdio", version: "0.0.0" });
    await client.connect(clientTx);
  });

  afterAll(async () => {
    if (client) await client.close();
    if (server) await server.close();
  });

  function expectClient(): Client {
    if (!client) throw new Error("client not initialized");
    return client;
  }

  it("resolves a batch of 60 concurrent tool calls", async () => {
    const c = expectClient();
    const calls: Promise<CallResult>[] = [];
    for (let i = 0; i < 60; i++) {
      if (i % 2 === 0) {
        calls.push(
          c.callTool({
            name: "altais_scan_code",
            arguments: {
              source: `db.query('SELECT * FROM t WHERE id = ' + req.params.id${String(i)});`,
              language: "javascript",
            },
          }) as Promise<CallResult>,
        );
      } else {
        calls.push(
          c.callTool({
            name: "altais_explain_cwe",
            arguments: { cwe: "CWE-79" },
          }) as Promise<CallResult>,
        );
      }
    }

    const results = await Promise.all(calls);
    expect(results).toHaveLength(60);
    for (const result of results) {
      expect(result.isError).not.toBe(true);
      expect(result.content?.[0]?.type).toBe("text");
    }
  });
});

// ─── HTTP transport under load ─────────────────────────────────────────────

describe("Phase 6 — HTTP transport under concurrent load (6.5)", () => {
  let httpServer: http.Server | null = null;
  const clients: Client[] = [];
  let base = "";

  beforeAll(async () => {
    process.env[HTTP_TOKEN_ENV] = TOKEN;
    const port = await getFreePort();
    base = `http://127.0.0.1:${port}`;
    httpServer = await startHttp(configSchema.parse({}), port);
  });

  afterAll(async () => {
    await Promise.all(clients.map((c) => c.close()));
    if (httpServer) {
      const srv = httpServer;
      await new Promise<void>((resolve) => {
        srv.close(() => {
          resolve();
        });
      });
    }
    Reflect.deleteProperty(process.env, HTTP_TOKEN_ENV);
  });

  async function newClient(name: string): Promise<Client> {
    const transport = new StreamableHTTPClientTransport(new URL(`${base}/mcp`), {
      requestInit: { headers: { Authorization: `Bearer ${TOKEN}` } },
    });
    const client = new Client({ name, version: "0.0.0" });
    await client.connect(transport);
    clients.push(client);
    return client;
  }

  it("serves concurrent listTools() to several authenticated clients", async () => {
    const sessions = await Promise.all([
      newClient("altais-load-http-1"),
      newClient("altais-load-http-2"),
      newClient("altais-load-http-3"),
    ]);

    const listings = await Promise.all(
      Array.from({ length: 30 }, (_, i) => {
        const session = sessions[i % sessions.length];
        if (session === undefined) throw new Error("session missing");
        return session.listTools();
      }),
    );

    expect(listings).toHaveLength(30);
    for (const { tools } of listings) {
      expect(tools.length).toBeGreaterThan(0);
      expect(tools.map((t) => t.name)).toContain("altais_get_config");
    }
  });

  it("serves concurrent tool calls across authenticated clients", async () => {
    const sessions = await Promise.all([
      newClient("altais-load-http-call-1"),
      newClient("altais-load-http-call-2"),
    ]);

    const results = await Promise.all(
      Array.from({ length: 30 }, (_, i) => {
        const session = sessions[i % sessions.length];
        if (session === undefined) throw new Error("session missing");
        return session.callTool({
          name: "altais_scan_code",
          arguments: {
            source: `eval(userInput${String(i)});`,
            language: "javascript",
          },
        }) as Promise<CallResult>;
      }),
    );

    expect(results).toHaveLength(30);
    for (const result of results) {
      expect(result.isError).not.toBe(true);
      expect(result.content?.[0]?.type).toBe("text");
    }
  });

  it("rejects every concurrent unauthenticated request with 401", async () => {
    const responses = await Promise.all(
      Array.from({ length: 25 }, () => fetch(`${base}/mcp`, { method: "POST" })),
    );

    expect(responses).toHaveLength(25);
    for (const res of responses) {
      expect(res.status).toBe(401);
      await res.body?.cancel();
    }
  });
});
