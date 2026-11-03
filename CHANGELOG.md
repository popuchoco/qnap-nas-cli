# Changelog

## 0.1.2 — 2026-11-03

- Add QTS 2FA TOTP authentication without persistent bypass tokens.
- Add a reviewed TS-431K/QTS 5.2.8 real-device fixture.
- Merge sysinfo bay observations with `qsmart.cgi` model, capacity, temperature, and Health data.
- Normalize QTS enclosure locators such as `0:2` while retaining the raw locator.
- Expand dump v2 redaction to netmasks and MAC addresses without corrupting IPv6 capability flags.
- Keep `vol_status=0`, fixed volume query scope, and top-level SMART limitations explicit.
- Add `healthy_claim` and user-visible Storage limitations when evidence cannot support a healthy declaration.
- Prompt for TOTP interactively after QTS requests 2FA; keep MCP and automation environment-only.

## 0.1.1 — 2026-11-03

- Separate healthy, unhealthy, and indeterminate health outcomes.
- Preserve unknown QTS volume status codes as evidence gaps rather than critical findings.
- Mark the fixed `extra_vol_index=1` storage query scope as unverified.
- Add versioned dump validation and `qts fixture validate`.
- Parse nested DNS response values and report unknown DNS formats explicitly.
- Make MCP JSON-RPC request IDs stateless and validate malformed requests and parameters.

## 0.1.0 — 2026-11-03

- Initial read-only QTS diagnostics CLI and MCP server.
