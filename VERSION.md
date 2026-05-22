# Version History

Release history for **altais-mcp**. This file is a high-level summary; the
full, detailed changelog is in [CHANGELOG.md](./CHANGELOG.md). The format
follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the
project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.1.1] — Unreleased

altais-mcp provides **148 tools across 25 modules**.

- **Fixed — npx entrypoint.** `isEntrypoint()` in `src/index.ts` compared
  `process.argv[1]` to `import.meta.url` directly. npm installs the
  `altais-mcp` bin as a symlink, so launching via `npx altais-mcp` never
  matched and the server exited silently without starting. The check now
  resolves the symlink with `realpathSync` and converts it with
  `pathToFileURL` before comparing.
- **Added — `database` module.** A new opt-in module with **16 tools** for
  database-layer security auditing: connection-string hygiene, query
  parameterization across ORMs and raw drivers, per-engine configuration
  audits (PostgreSQL/CockroachDB, MySQL/MariaDB, MongoDB, Redis/Memcached,
  SQLite, SQL Server, Elasticsearch, DynamoDB/Supabase/PlanetScale),
  connection pooling, migration safety, backup posture, NoSQL injection,
  TLS, and audit logging. This brings altais-mcp to 148 tools / 25 modules.
- **Changed — version bump.** `package.json`, `package-lock.json`,
  `SERVER_VERSION`, and the `database` module version are bumped to
  `1.1.1`.
- **Changed — README installation.** The installation section now makes
  `npm install altais-mcp` (and `npx altais-mcp`) the primary, recommended
  path, with building from source as the secondary path for contributors.

## [1.1.0]

Minor release. Introduced the `database` security module (16 tools). See
[CHANGELOG.md](./CHANGELOG.md) for the full detail.

## [1.0.2]

Patch release. Reworded loose "fetch" wording in threat-model and testing
template strings.

## [1.0.1]

Patch release. Resolved Socket.dev supply-chain-scanner false positives by
moving detection-pattern tokens into bundled data files.

## [1.0.0]

Initial production release — 132 tools across 24 modules.
