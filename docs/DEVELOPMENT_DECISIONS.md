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
