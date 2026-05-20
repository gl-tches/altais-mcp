# `protocol` module

The `protocol` module provides application- and transport-protocol security audits. It performs deep TLS / mTLS configuration review, webhook signature verification, email authentication review (SPF / DKIM / DMARC), and security audits for WebSocket, GraphQL, gRPC, and Server-Sent Events. Every tool is a static analyzer that emits findings into the session report.

| Property | Value |
|----------|-------|
| Module name | `protocol` |
| Status | Opt-in (disabled by default) |
| Config key | `[modules] protocol` in `altais.config.toml` |
| Tools | 7 |

## Tools

| Tool | Description |
|------|-------------|
| [`altais_audit_tls_config`](../tools/altais_audit_tls_config.md) | Audit a structured TLS / mTLS configuration against RFC 9325 and RFC 8996. |
| [`altais_check_webhook`](../tools/altais_check_webhook.md) | Verify a webhook receiver's HMAC signature implementation. |
| [`altais_audit_email_security`](../tools/altais_audit_email_security.md) | Audit a domain's SPF / DKIM / DMARC posture. |
| [`altais_audit_websocket`](../tools/altais_audit_websocket.md) | Review a WebSocket server or client. |
| [`altais_audit_graphql`](../tools/altais_audit_graphql.md) | Audit a GraphQL API. |
| [`altais_audit_grpc`](../tools/altais_audit_grpc.md) | Audit a gRPC service or client. |
| [`altais_audit_sse`](../tools/altais_audit_sse.md) | Audit a Server-Sent Events endpoint. |

## Enabling this module

All five of these modules are opt-in. Enable one by setting its key to `true` under `[modules]` in `altais.config.toml`. Note `iac` also has an `[iac]` config section, and `compliance` has a `[compliance]` section.

## See also

- [Wiki home](../Home.md)
