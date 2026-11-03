# Architecture

## Goals

- Python 3.8+ standard library only.
- The same typed observations feed text, JSON, and MCP output.
- Authentication secrets and QTS sessions remain ephemeral.
- Read-only evidence ships before mutation.
- Firmware variance degrades to explicit unknown fields, never invented health.

## Backends

The web backend uses documented QTS authentication and narrowly scoped CGI reads. The SSH backend invokes only fixed argv through the system OpenSSH client with batch authentication; it never invokes a shell. An explicit identity-file path may be stored in config, but key material and passphrases are not. A future local backend may execute the same fixed probes directly on a NAS.

QTS does not expose one stable public system-health API across every model and firmware. Parser fixtures and redacted dumps are therefore part of the compatibility contract.

## Health semantics

Health is three-state. `healthy` means required evidence was observed and no known anomaly was found. `unhealthy` means at least one known anomaly was found. `indeterminate` means no known anomaly was found but required evidence was missing or unknown. Known anomalies are returned in `findings`; evidence gaps are returned in `unknowns`.

The machine-readable `healthy_claim` field is `not_permitted` whenever evidence gaps remain. Storage also carries user-visible `limitations`; clients must not hide these while presenting an indeterminate result.

The storage parser retains raw QTS status codes and adds explicit semantics (`known_good`, `known_bad`, or `unknown`). New codes remain unknown until a real, reviewed fixture establishes their meaning.

Volume discovery uses `extra_get` with `extra_vol_index=1`, whose coverage remains explicitly unverified. Disk evidence merges flat bay observations from sysinfo with `qsmart.cgi?func=all_hd_data`; enclosure locators such as `0:2` are normalized to bay `2` while the raw locator is retained. Top-level SMART Health is evidence, not proof that every attribute and historical QTS warning is clear.

## Fixture contract

`qts dump` v2 writes redacted sysinfo, volume, and SMART response files plus a versioned manifest and local parser validation. Redaction covers hostnames, serials, IP addresses, netmasks, MAC addresses, and DNS values while preserving non-secret capability flags. `qts fixture validate` performs the same validation without contacting a NAS. Synthetic unit fixtures test edge cases, but they are never labeled as device evidence.

The reviewed TS-431K fixture comes from QTS 5.2.8 build 20251216. The firmware reports the internal model alias `TS-X41`; compatibility must not rely only on the retail model string.

Interactive CLI authentication prompts for a TOTP only after QTS reports that the password phase requires 2FA. Non-interactive CLI and MCP never prompt inside their protocols and require the short-lived `QTS_SECURITY_CODE` environment variable.

## Mutation gate

A future modifying command must provide all of the following before release:

1. A user-visible question and affected QTS versions.
2. Current state and planned target state.
3. `--dry-run` output with exact operations.
4. Explicit confirmation and a non-interactive `--yes` boundary.
5. Post-change verification.
6. Recovery instructions when the connection is lost.
7. Unit fixtures and a real-device result.

Initial mutation candidates are limited to reversible service start/stop and non-destructive notification or configuration changes. A candidate also requires a verified second administrator account and an independent recovery route. RAID rebuild, SMART repair, disk writes, and broad firewall changes are excluded from early releases.
