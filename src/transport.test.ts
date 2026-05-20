// Streamable HTTP transport tests (task 3.8 / 3.12).
//
// Exercises the HTTP transport end-to-end: 127.0.0.1 binding, bearer-token
// authentication, and a full MCP session over `StreamableHTTPClientTransport`.

import net from "node:net";
import type http from "node:http";

import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";
import { afterAll, beforeAll, describe, expect, it } from "vitest";

import { configSchema } from "./config.js";
import { isAuthorized, resolveHttpToken, startHttp, HTTP_TOKEN_ENV } from "./index.js";

const TOKEN = "test-token-0123456789abcdef0123456789abcdef";

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

describe("isAuthorized", () => {
  it("rejects a missing Authorization header", () => {
    expect(isAuthorized(undefined, TOKEN)).toBe(false);
  });

  it("rejects a non-Bearer scheme", () => {
    expect(isAuthorized(`Basic ${TOKEN}`, TOKEN)).toBe(false);
  });

  it("rejects a wrong bearer token", () => {
    expect(isAuthorized("Bearer wrong-token", TOKEN)).toBe(false);
  });

  it("rejects a token of a different length", () => {
    expect(isAuthorized(`Bearer ${TOKEN}extra`, TOKEN)).toBe(false);
  });

  it("accepts the exact bearer token", () => {
    expect(isAuthorized(`Bearer ${TOKEN}`, TOKEN)).toBe(true);
  });
});

describe("resolveHttpToken", () => {
  it("uses the token from the environment when set", () => {
    const r = resolveHttpToken({ [HTTP_TOKEN_ENV]: "from-env" });
    expect(r).toEqual({ token: "from-env", generated: false });
  });

  it("generates a random token when the environment variable is absent", () => {
    const r = resolveHttpToken({});
    expect(r.generated).toBe(true);
    expect(r.token).toMatch(/^[0-9a-f]{64}$/);
  });
});

describe("Streamable HTTP transport", () => {
  let httpServer: http.Server | null = null;
  let client: Client | null = null;
  let base = "";

  beforeAll(async () => {
    process.env[HTTP_TOKEN_ENV] = TOKEN;
    const port = await getFreePort();
    base = `http://127.0.0.1:${port}`;
    httpServer = await startHttp(configSchema.parse({}), port);
  });

  afterAll(async () => {
    if (client) await client.close();
    if (httpServer) {
      await new Promise<void>((resolve) => {
        httpServer?.close(() => {
          resolve();
        });
      });
    }
    Reflect.deleteProperty(process.env, HTTP_TOKEN_ENV);
  });

  it("returns 404 for a path outside the MCP endpoint", async () => {
    const res = await fetch(`${base}/not-mcp`, { method: "POST" });
    expect(res.status).toBe(404);
    await res.body?.cancel();
  });

  it("rejects an unauthenticated request with 401", async () => {
    const res = await fetch(`${base}/mcp`, { method: "POST" });
    expect(res.status).toBe(401);
    expect(res.headers.get("www-authenticate")).toMatch(/Bearer/);
    await res.body?.cancel();
  });

  it("rejects a request bearing the wrong token with 401", async () => {
    const res = await fetch(`${base}/mcp`, {
      method: "POST",
      headers: { authorization: "Bearer not-the-token" },
    });
    expect(res.status).toBe(401);
    await res.body?.cancel();
  });

  it("serves a full MCP session to an authenticated client", async () => {
    const transport = new StreamableHTTPClientTransport(new URL(`${base}/mcp`), {
      requestInit: { headers: { Authorization: `Bearer ${TOKEN}` } },
    });
    client = new Client({ name: "altais-http-test", version: "0.0.0" });
    await client.connect(transport);

    const { tools } = await client.listTools();
    const names = tools.map((t) => t.name);
    expect(names).toContain("altais_get_config");
    expect(tools.length).toBeGreaterThan(0);
  });
});
