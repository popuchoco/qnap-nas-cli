# Changelog

## Unreleased

- Configure Windows CLI stdout/stderr for UTF-8 so Unicode help text and observations do not crash under legacy code pages; cover the behavior in unit tests.
- Fix Windows evidence capsule CI path comparison to compare filesystem identity rather than short/long path spelling. Test the full suite and install/smoke-test the universal wheel on Windows, macOS Apple silicon, and macOS Intel; require all three platforms to pass the release wheel before PyPI/GitHub publication.
- Document that the `py3-none-any` wheel already supports Windows and macOS, add native PowerShell/macOS installation and offline-wheel steps, and explicitly defer unsigned standalone `.exe`/`.dmg` packages.
- Fix redacted security report bundles so schema-owned report/rule IDs and bounded four-component version/build fields survive redaction; add an end-to-end assessment → bundle → schema validation regression test.
- Stop legacy QPKG collection at the first SSH/configuration failure, retain a fixed `collection_errors` code and explicit unknown posture, publish the report, then return exit 2 so schedulers cannot mistake an incomplete collection for success. Apply the same structured failure contract to Plex and make SSH identity-file use explicit with `IdentitiesOnly=yes`.
- Sort webhook findings by severity before item/body truncation; a critical/high advisory finding can no longer be displaced by earlier low-severity QSnatch checklist entries. Photo Station exposure remains a high finding without being mislabeled as `suspected`, while still triggering an alert.
- Separate health, Plex, and legacy indeterminate-webhook environment controls; persist scheduled report bundles before delivery and keep delivery status outside the report manifest.
- Give Plex scheduled reports the same exposure/IOC parameters as direct audits, use an absolute `/bin/pidof` path, add Windows atomic-report CI coverage, and correct release/version/SSH privilege documentation.
- Add a narrow candidate parser for four-part Plex versions with a 7–40 hex hash suffix. The syntax has synthetic tests but remains unverified against a real Plex QPKG; do not infer or fabricate a device version string.
- Keep live NAS test results out of public fixtures and changelog by default. The remaining raw QPKG/process wrapper formats and SSH-account compatibility must be validated with reviewed, privacy-minimized samples before any support or release claim; do not cut `0.5.0` before that review.
- Add a read-only Plex2Shell patch-posture and IOC-triage audit using fixed QPKG metadata probes, operator-reported indicators, and opt-in exact-name `pidof` checks; classify unknowns conservatively and never perform broad runtime scanning or modify the NAS.
- Add read-only Qlocker / DeadBolt / QSnatch posture audit for the published HBS 3 and Photo Station package baselines, Malware Remover/Security Counselor metadata, and operator-confirmed NAS-201911-01 controls; unverified branch, scan freshness, exposure, and compromise state remain unknown.
- Add `qts_legacy_ransomware_security` MCP tool, a versioned observation schema, and advisory-specific response/limitations documentation with official QNAP sources.
- Add atomic, redacted `qts report legacy-ransomware` bundles with codes-only summaries and alert-only webhook notifications for vulnerable/suspected posture; indeterminate delivery remains explicitly opt-in.

## 0.4.0 — 2026-11-06

- Add opt-in, fail-soft HTTPS webhook notifications for unhealthy health results and suspected incident scans; keep indeterminate health opt-in and the mutation gate closed. Scrub password/sid/qtoken assignments from redacted string values used in payloads.
- Privacy fix: webhook findings and unknowns no longer include free-text messages; summaries use only fixed trigger/status/count text.
- Add `qts report health` for atomic local timestamped JSON + codes-only Markdown + SHA-256 manifest reports, with `docs/SCHEDULE.md` cron／systemd timer examples; no in-process daemon; mutation gate stays closed.
- Add atomic, recursively redacted incident evidence capsules with codes-only summaries, format v2 payload hashes, and optional exact-example sample attachments under a combined byte cap; keep the mutation gate closed.
- Validate scheduled reports, webhook delivery/failure semantics, and format-v2 evidence capsules live against the TS-431K on 2026-11-06. Add Windows-safe atomic publication and sample validation without weakening symlink/non-regular-file rejection.

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
