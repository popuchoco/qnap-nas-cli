# Changelog

## Unreleased

## 0.3.0 — 2026-11-06

- Add opt-in redacted File Station dump capture, offline fixture replay, and structural/leak validation; the reviewed live TS-431K fixture and redactor privacy fix landed in `5ad937e`. Synthetic fixtures remain for clean/IOC/truncation edge cases only.
- Validate the QTS web path on 2026-11-06: `status` and `health` were exercised, and `repair plan`/`apply` returned `refused`. The existing checklist/tooling remains; the mutation gate stays closed and no mutation adapter is added.
- Add the `qts_smart_details` MCP tool with bounded disk-bay validation.
- Sync installation and publishing documentation with the published PyPI 0.2.0 release.
- Strengthen incident coverage and CLI exit-code contract tests.
- Add Traditional Chinese installation and credential injection guides; surface the support policy in README.

## 0.2.0 — 2026-11-06

- Prepare setuptools packaging and a gated PyPI trusted-publishing workflow; this release skeleton does not publish automatically without the configured `pypi` environment approval.
- Freeze read-only health, storage, RAID, and incident observation schemas with stdlib contract tests.
- Add contributor guidance, the TS-431K compatibility baseline, and the observation contract.
- Keep the mutation gate closed; no production mutation adapter is included.

## 0.1.3 — 2026-11-03

- Add shell-free read-only SSH probes for `/proc/mdstat`, physical disk topology, SMART attributes, and fixed Container Station/Tailscale package state.
- Parse degraded RAID member maps and recovery/resync progress.
- Add explicit SSH identity-file configuration without storing key material or passwords.
- Expose RAID and service status through CLI and read-only MCP tools.
- Formalize the recovery-gated progression from real fixtures to low-risk reversible mutations.
- Add reviewed TS-431K SSH fixtures; keep QNAP 128-wide RAID maps, empty SMART output, and QPKG runtime health explicitly unknown.

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
