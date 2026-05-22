# `database` module

The `database` module covers database-layer security. It audits connection-string hygiene, query parameterization across ORMs and raw drivers, per-engine configuration (PostgreSQL / CockroachDB, MySQL / MariaDB, MongoDB, Redis / Memcached, SQLite, SQL Server, Elasticsearch, and DynamoDB / Supabase / PlanetScale), connection pooling, migration safety, backup posture, NoSQL injection, TLS, and audit logging. Every tool pushes findings into the session report.

| Property | Value |
|----------|-------|
| Module name | `database` |
| Status | Opt-in (disabled by default) |
| Config key | `[modules] database` in `altais.config.toml` |
| Tools | 16 |

## Tools

| Tool | Description |
|------|-------------|
| [`altais_audit_connection`](../tools/altais_audit_connection.md) | Audits connection strings for embedded credentials, disabled TLS, and plaintext schemes. |
| [`altais_audit_queries`](../tools/altais_audit_queries.md) | Detects unsafe query construction across the supported ORMs and raw drivers. |
| [`altais_audit_postgres`](../tools/altais_audit_postgres.md) | Audits a PostgreSQL / CockroachDB configuration. |
| [`altais_audit_mysql`](../tools/altais_audit_mysql.md) | Audits a MySQL / MariaDB configuration. |
| [`altais_audit_mongodb`](../tools/altais_audit_mongodb.md) | Audits a MongoDB configuration. |
| [`altais_audit_redis`](../tools/altais_audit_redis.md) | Audits a Redis / Memcached configuration. |
| [`altais_audit_sqlite`](../tools/altais_audit_sqlite.md) | Audits a SQLite configuration. |
| [`altais_audit_mssql`](../tools/altais_audit_mssql.md) | Audits a Microsoft SQL Server configuration. |
| [`altais_audit_elasticsearch`](../tools/altais_audit_elasticsearch.md) | Audits an Elasticsearch configuration. |
| [`altais_audit_dynamodb`](../tools/altais_audit_dynamodb.md) | Audits an AWS DynamoDB configuration. |
| [`altais_audit_pooling`](../tools/altais_audit_pooling.md) | Audits a database connection-pool configuration. |
| [`altais_audit_migrations`](../tools/altais_audit_migrations.md) | Detects destructive or unsafe database migrations. |
| [`altais_audit_backup`](../tools/altais_audit_backup.md) | Audits a database backup configuration. |
| [`altais_audit_nosql_injection`](../tools/altais_audit_nosql_injection.md) | Detects NoSQL injection sinks (MongoDB, Elasticsearch, Redis). |
| [`altais_audit_db_tls`](../tools/altais_audit_db_tls.md) | Audits a database's TLS / SSL configuration. |
| [`altais_audit_db_logging`](../tools/altais_audit_db_logging.md) | Audits a database's audit-logging configuration. |

## Database coverage

Relational: PostgreSQL, MySQL / MariaDB, Microsoft SQL Server, SQLite, CockroachDB · Document: MongoDB · Key-value: Redis, Memcached · Search: Elasticsearch · Cloud-managed: AWS DynamoDB, Supabase, PlanetScale.

The `altais_audit_queries` tool covers query parameterization for the Prisma, Drizzle, TypeORM, Sequelize, Knex, pg, mysql2, better-sqlite3, mongoose, ioredis, and `@elastic/elasticsearch` (TypeScript / JavaScript); SQLAlchemy, Django ORM, psycopg2 / psycopg3, PyMongo, and redis-py (Python); diesel, sqlx, and sea-orm (Rust); and GORM, `database/sql`, and pgx (Go) ecosystems.

## Configuration

The optional `[database]` section in `altais.config.toml`:

```toml
[database]
drivers = ["postgres", "mysql", "mongodb", "redis", "sqlite", "mssql", "elasticsearch", "dynamodb"]
check_connection_strings = true
check_parameterization = true
check_migrations = true
check_backup = true
check_nosql_injection = true
```

## Enabling this module

The module is opt-in. Enable it by setting `database = true` under `[modules]` in `altais.config.toml`.

## See also

- [Wiki home](../Home.md)
- [Module development](../Module-Development.md)
