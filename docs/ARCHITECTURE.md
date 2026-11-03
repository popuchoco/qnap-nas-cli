# Architecture

## Goals

- Python 3.8+ standard library only.
- The same typed observations feed text, JSON, and MCP output.
- Authentication secrets and QTS sessions remain ephemeral.
- Read-only evidence ships before mutation.
- Firmware variance degrades to explicit unknown fields, never invented health.

## Backends

The web backend uses documented QTS authentication and narrowly scoped CGI reads. The SSH backend invokes only fixed commands through the system OpenSSH client with batch authentication. A future local backend may execute the same fixed probes directly on a NAS.

QTS does not expose one stable public system-health API across every model and firmware. Parser fixtures and redacted dumps are therefore part of the compatibility contract.

## Mutation gate

A future modifying command must provide all of the following before release:

1. A user-visible question and affected QTS versions.
2. Current state and planned target state.
3. `--dry-run` output with exact operations.
4. Explicit confirmation and a non-interactive `--yes` boundary.
5. Post-change verification.
6. Recovery instructions when the connection is lost.
7. Unit fixtures and a real-device result.
