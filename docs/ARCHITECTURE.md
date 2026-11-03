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

## Health semantics

Health is three-state. `healthy` means required evidence was observed and no known anomaly was found. `unhealthy` means at least one known anomaly was found. `indeterminate` means no known anomaly was found but required evidence was missing or unknown. Known anomalies are returned in `findings`; evidence gaps are returned in `unknowns`.

The storage parser retains raw QTS status codes and adds explicit semantics (`known_good`, `known_bad`, or `unknown`). New codes remain unknown until a real, reviewed fixture establishes their meaning.

The initial QTS request uses `extra_get` with `extra_vol_index=1`. Its source metadata is explicitly `coverage: unverified`. Until live comparison establishes how a target firmware enumerates additional pools and volumes, this evidence gap prevents an overall healthy result but does not hide known bad findings.

## Fixture contract

`qts dump` writes redacted response files plus a versioned manifest and local parser validation. `qts fixture validate` performs the same validation without contacting a NAS. Synthetic unit fixtures test edge cases, but they are never labeled as device evidence.

## Mutation gate

A future modifying command must provide all of the following before release:

1. A user-visible question and affected QTS versions.
2. Current state and planned target state.
3. `--dry-run` output with exact operations.
4. Explicit confirmation and a non-interactive `--yes` boundary.
5. Post-change verification.
6. Recovery instructions when the connection is lost.
7. Unit fixtures and a real-device result.
