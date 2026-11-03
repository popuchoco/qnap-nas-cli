# Changelog

## 0.1.1 — 2026-11-03

- Separate healthy, unhealthy, and indeterminate health outcomes.
- Preserve unknown QTS volume status codes as evidence gaps rather than critical findings.
- Mark the fixed `extra_vol_index=1` storage query scope as unverified.
- Add versioned dump validation and `qts fixture validate`.
- Parse nested DNS response values and report unknown DNS formats explicitly.
- Make MCP JSON-RPC request IDs stateless and validate malformed requests and parameters.

## 0.1.0 — 2026-11-03

- Initial read-only QTS diagnostics CLI and MCP server.
