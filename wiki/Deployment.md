# Deploying altais-mcp

altais-mcp runs as a [Model Context Protocol](https://modelcontextprotocol.io)
server. It supports two transports:

- **stdio** — the server is launched as a child process by an MCP client
  (Claude Code, IDE extensions). This is the normal way to run it.
- **streamable HTTP** — the server listens on a local TCP port for one or
  more MCP clients. Bound to `127.0.0.1` only and **always** requires a
  bearer token.

This guide covers both, plus Docker and systemd.

---

## Table of contents

- [Prerequisites](#prerequisites)
- [Install](#install)
- [Run as a stdio MCP server](#run-as-a-stdio-mcp-server)
- [Run as a streamable HTTP server](#run-as-a-streamable-http-server)
- [Configuration](#configuration)
- [Docker](#docker)
- [systemd service](#systemd-service)
- [Operations & hardening](#operations--hardening)

---

## Prerequisites

- **Node.js >= 20** (Node 22 recommended).
- No database, no external services — altais-mcp is self-contained and makes
  no network calls at runtime.

---

## Install

### From source

```bash
git clone <repository-url> altais-mcp
cd altais-mcp
npm install
npm run build      # compiles to dist/
```

The entry point is `dist/index.js` (also exposed as the `altais-mcp` bin).

### From npm

Once published, altais-mcp can be installed directly:

```bash
npm install -g altais-mcp     # global install -> `altais-mcp` on PATH
# or run without installing:
npx altais-mcp
```

---

## Run as a stdio MCP server

This is the default transport. The MCP client spawns the process and speaks
the protocol over stdin/stdout. **Do not run it by hand for stdio** — point
your client at it.

Add altais-mcp to your MCP client configuration. For Claude Code
(`~/.claude.json` or the project `.mcp.json`):

```json
{
  "mcpServers": {
    "altais": {
      "command": "node",
      "args": ["/absolute/path/to/altais-mcp/dist/index.js"]
    }
  }
}
```

If installed from npm:

```json
{
  "mcpServers": {
    "altais": { "command": "npx", "args": ["-y", "altais-mcp"] }
  }
}
```

A custom config file can be passed with `--config`:

```json
{ "command": "node",
  "args": ["/path/to/dist/index.js", "--config", "/path/to/altais.config.toml"] }
```

> **stdio rule:** stdout is reserved for the MCP protocol. altais-mcp logs
> only to **stderr** — never add code that prints to stdout in stdio mode.

---

## Run as a streamable HTTP server

Use HTTP when several local clients/agents share one server instance. The
HTTP transport:

- binds **`127.0.0.1` only** (never `0.0.0.0`) — it is not directly
  reachable from another host by design;
- validates the `Origin` header and enables DNS-rebinding protection;
- **requires a bearer token on every request** — there is no unauthenticated
  mode.

### 1. Enable the HTTP transport

In `altais.config.toml`:

```toml
[server]
transport = "http"
port = 3100
```

### 2. Set the bearer token

The token comes from the **`ALTAIS_HTTP_TOKEN`** environment variable (never
from the config file):

```bash
export ALTAIS_HTTP_TOKEN="$(openssl rand -hex 32)"
node dist/index.js
```

If `ALTAIS_HTTP_TOKEN` is unset, altais-mcp generates a random ephemeral
token at startup and logs it to **stderr** — copy it from there. Setting the
variable yourself gives a stable token across restarts.

### 3. Connect a client

Clients connect to `http://127.0.0.1:3100/mcp` and send:

```
Authorization: Bearer <ALTAIS_HTTP_TOKEN>
```

Requests without a valid token receive `401 Unauthorized`. Each client gets
an isolated session (its own findings store), routed by the
`mcp-session-id` header.

---

## Configuration

altais-mcp reads `altais.config.toml` from the working directory (or the
`--config` path). **It runs with no config file at all** — every value has a
default.

```toml
[server]
name = "altais-mcp"
transport = "stdio"       # "stdio" | "http"
port = 3100               # http transport only
log_level = "info"        # debug | info | warn | error

[modules]
# Default-on modules
scan = true
threat_model = true
owasp = true
secrets = true
headers = true
supply_chain = true
auth = true
# Opt-in modules (enable the ones you need)
crypto = false
container = false
code = false
data = false
compliance = false
infra = false
protocol = false
incident = false
testing = false
vuln_db = false
ml_security = false
sdlc = false
iac = false
agentic = false
api = false
runtime = false

[scan]
scan_root = ""            # absolute dir altais_scan_file may read; "" = CWD
max_file_size_kb = 512
max_source_bytes = 2097152
```

`core` is always loaded. Enabling more modules exposes more tools — see the
[module list](Home.md#modules). Per-module sections (`[scan]`, `[secrets]`,
`[supply_chain]`, `[severity]`, `[iac]`, `[compliance]`, `[agentic]`) tune
behavior; all keys have defaults.

---

## Docker

The HTTP transport binds the container's loopback by design, so a container
is reached either with host networking or via a same-host reverse proxy —
**never expose the port directly to an untrusted network.**

A sample multi-stage `Dockerfile` (audit it with `altais_audit_dockerfile`):

```dockerfile
# ---- build ----
FROM node:22-bookworm-slim AS build
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci
COPY tsconfig.json tsconfig.build.json ./
COPY src ./src
COPY data ./data
RUN npm run build && npm prune --omit=dev

# ---- runtime ----
FROM node:22-bookworm-slim AS runtime
WORKDIR /app
ENV NODE_ENV=production
COPY --from=build /app/node_modules ./node_modules
COPY --from=build /app/dist ./dist
COPY --from=build /app/data ./data
COPY altais.config.toml ./
USER node
HEALTHCHECK NONE
CMD ["node", "dist/index.js"]
```

> Pin the base image to a digest (`node:22-bookworm-slim@sha256:...`) for
> reproducible builds — `altais_check_base_image` will flag it otherwise.

Run it with host networking so the container's `127.0.0.1` is the host
loopback:

```bash
docker build -t altais-mcp .
docker run --rm --network host \
  -e ALTAIS_HTTP_TOKEN="$(openssl rand -hex 32)" \
  altais-mcp
```

The container's `altais.config.toml` must set `transport = "http"`. Local
clients then reach `http://127.0.0.1:3100/mcp`. If you need it on another
host, terminate TLS in a reverse proxy **on the same host** that forwards to
`127.0.0.1:3100` — and keep the bearer token.

---

## systemd service

To run the HTTP server as a managed service under a dedicated unprivileged
user:

```ini
# /etc/systemd/system/altais-mcp.service
[Unit]
Description=altais-mcp security analysis MCP server
After=network.target

[Service]
Type=simple
User=altais
Group=altais
WorkingDirectory=/opt/altais-mcp
Environment=ALTAIS_HTTP_TOKEN=replace-with-a-strong-secret
ExecStart=/usr/bin/node /opt/altais-mcp/dist/index.js
Restart=on-failure

# Hardening
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
ReadWritePaths=
CapabilityBoundingSet=

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now altais-mcp
journalctl -u altais-mcp -f      # logs go to stderr -> the journal
```

Prefer storing `ALTAIS_HTTP_TOKEN` in an `EnvironmentFile=` with `0600`
permissions rather than inline in the unit.

---

## Operations & hardening

- **Logging** — all logs go to stderr (`[altais-mcp] ...`). In stdio mode
  stdout carries the protocol; in HTTP/systemd mode stderr goes to the
  journal.
- **Least privilege** — run as a non-root user with no extra capabilities.
  altais-mcp only ever *reads* files.
- **`scan_root`** — set `scan.scan_root` to the project directory you want
  `altais_scan_file` to be allowed to read. Paths resolving outside it
  (including via symlink) are rejected.
- **The HTTP token is a secret** — supply it via the environment or a
  `0600` env file; never commit it; rotate it by restarting with a new
  value.
- **No runtime network access** — altais-mcp needs none; you may deploy it
  with egress blocked.
- **Upgrading** — `git pull && npm install && npm run build` (or
  `npm update -g altais-mcp`), then restart the service. Check the
  [CHANGELOG](../CHANGELOG.md) for breaking changes.

---

See also: [Wiki home](Home.md) · [Contributing](Contributing.md) ·
[Security policy](../SECURITY.md) · [Configuration in the README](../README.md)
