# Development Decisions

## ADR-001 — Zero-dependency Python core

Python 3.8 standard library keeps the CLI runnable on management computers and NAS environments without a package dependency chain. External `ssh` is optional and discovered at runtime.

## ADR-002 — Hybrid QTS web and allowlisted SSH backends

QTS authentication and general status use HTTPS CGI. Deep operating-system observations use passwordless SSH only when the command is fixed in source. There is no arbitrary command transport in CLI or MCP.

## ADR-003 — Read-only first release

The first release does not repair disks, rebuild RAID, stop containers, restart Tailscale, or change the firewall. QTS fields vary too much across models to make those operations safe without TS-431K fixtures and live validation.

## ADR-004 — Compatibility evidence is privacy-redacted

`qts dump` removes hostnames, serials, interface addresses and DNS values before writing files. Raw SID and credentials are never included. Users must still review a dump before publishing it.

## ADR-005 — Architecture references are acknowledged

The safety model and CLI/MCP product shape were informed by `synology-nas-cli`; QTS request behavior was checked against QNAP's authentication/File Station documents and the independently implemented `rvben/qnap-cli`. This project owns its QTS-specific implementation and records direct reuse if introduced later.

## ADR-006 — Unknown health evidence is not healthy

Health uses three states: `healthy`, `unhealthy`, and `indeterminate`. Known bad status codes create findings. Missing fields, QTS `vol_status=0`, unrecognized codes, and parser omissions create evidence gaps. A result is healthy only when no finding or required evidence gap remains.

## ADR-007 — Real dumps define compatibility

Hand-written XML remains useful for edge cases but cannot establish a device contract. Parser mappings for new firmware or status codes require a redacted, manually reviewed real-device dump. Dumps include a versioned manifest and offline validation so fixture provenance is not confused with health proof.

## ADR-008 — MCP requests are stateless per line

Every JSON-RPC line starts with a fresh null request ID. Parse errors use code `-32700`; non-object or malformed requests use `-32600`; invalid params use `-32602`. Notifications do not receive responses, and an error must never inherit an earlier request's ID.

## ADR-009 — QTS 2FA remains ephemeral

QTS 5.x may accept the password phase while withholding a SID and returning `need_2_step_verification=1`. The client supports the documented `security_code` field with `dont_verify_2sv_again=0`; it does not request a persistent bypass token. Interactive CLI prompts only after that response. Automation and MCP use process-only `QTS_SECURITY_CODE`; it is never written to config, dumps, logs, or fixtures.

## ADR-010 — Storage evidence is merged, not overclaimed

The reviewed TS-431K/QTS 5.2.8 fixture showed that `disk_manage.cgi extra_get` returned a volume row but no disk records, while sysinfo exposed bay temperatures and `qsmart.cgi all_hd_data` exposed model, capacity, serial, and top-level Health. These sources are merged by normalized bay locator. Volume scope and `vol_status=0` remain unknown, and a top-level SMART `Normal` cannot negate a more specific QTS warning.

## ADR-011 — SSH probes are shell-free and allowlisted

Deep read-only evidence uses direct OpenSSH argv for `cat /proc/mdstat`, QNAP SMART attributes, fixed QPKG reads, Container Station status, and Tailscale JSON status. No probe accepts arbitrary commands or package names, and `/bin/sh -c` is forbidden. Disk slots are numeric and bounded. Password authentication is not automated; an explicit identity path may be configured.

## ADR-012 — Mutation maturity is gated by recovery

Read-only coverage and real fixtures come first. The first mutations, if implemented, are one or two low-risk reversible service or settings operations. Every mutation requires plan, dry-run, explicit confirmation, post-change verification, and concrete rescue steps. A second administrator and an independent recovery path must be proven before higher-risk work. RAID rebuild, SMART repair, disk operations, and broad firewall changes are excluded from early versions.

## ADR-013 — QNAP-specific output remains unknown until proven

The TS-431K fixture contains QNAP system arrays with `[128/3]` member maps. Their underscores are not interpreted as ordinary Linux md failures; the parser preserves the map and reports unknown semantics. Empty `get_hd_smartinfo` output is reported as firmware-unavailable, not healthy. QPKG `Enable` and `Status=complete` are package metadata and do not prove daemon or workload health.

## ADR-014 — Plan replay is at-most-once, not idempotency proof

A completed plan cannot be replayed as another success: its before-state has changed, so apply stops as `stale_plan` before invoking the adapter again. An ambiguous transport failure remains `partial_failure` even if readback sees the target state. Retrying requires a fresh observation and plan. This prevents accidental duplicate action, but each future QTS adapter must still prove that its endpoint is convergent and document side effects; engine-level replay protection is not evidence that a vendor operation is idempotent. A second administrator and independent recovery path are accepted only after a live login and route exercise in the current maintenance window.
