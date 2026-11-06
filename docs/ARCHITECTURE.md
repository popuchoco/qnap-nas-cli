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

Volume queries use `extra_get` with `extra_vol_index=1` by default; CLI/MCP can query explicitly supplied indices, but there is no verified index-discovery contract and coverage remains unverified. Disk evidence merges flat bay observations from sysinfo with `qsmart.cgi?func=all_hd_data`; enclosure locators such as `0:2` are normalized to bay `2` while the raw locator is retained. Top-level SMART Health is evidence, not proof that every attribute and historical QTS warning is clear. Deduplication canonicalizes nested mappings to avoid relying on insertion order.

## Fixture contract

`qts dump` v2 writes redacted sysinfo, volume, and SMART response files plus a versioned manifest and local parser validation. Optional `qts dump --filestation` adds a format v3 manifest and bounded first pages for visible shares; File Station keys, addresses, share names/paths, file names, and folder names are replaced before writing. Ordinary entry names become non-identifying `Entry_REDACTED` placeholders rather than guessable name hashes; only `.7z`, `.deadbolt`, and `!!!READ_ME.txt` semantics needed by the incident rules survive. Capture is limited to 5,000 shares, at most 10,000 returned entries, one page of at most 200 entries per share, and depth zero (within the incident scanner's 5,000-folder, 10,000-item, and depth-12 limits). `qts fixture validate` performs structural and leak-pattern checks without contacting a NAS. The TS-431K fixture now includes a reviewed live File Station capture; synthetic fixtures remain for clean/IOC/truncation edge cases.

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

The repository now contains `remediation.py`, a fail-closed plan/apply engine. Plans include device identity, creation/expiry timestamps, canonical SHA-256 `plan_id`, before/after state, explicit preconditions and recovery notes. Applying requires a matching ID, a device identity reader, a passing precondition checker, registered action adapters, an unchanged pre-state, and a successful per-step readback. A mismatch stops the sequence; the engine does not guess rollback behavior. CLI production has no registered mutation adapter today: `qts repair plan` emits a refused/manual-only plan and `qts repair apply` refuses it. This deliberately exercises the workflow without pretending a QNAP mutation endpoint has been verified.

## Incident workflow

`incident.py` is a bounded read-only scan using File Station `get_tree`/`get_list`. It traverses visible shared folders with configurable total-item cap (default 10,000, hard maximum 100,000) and fixed depth cap (12). It checks a small, explicit set of known names: `.deadbolt`, the Qlocker note `!!!READ_ME.txt`, and a low-confidence large `.7z` cluster. This is not behavior analytics, process inspection, content scanning, general malware detection, or proof of no infection. No hit remains `indeterminate`; inaccessible paths, parser issues, unreported totals, depth/item caps are visible as partial coverage.

`qts incident contain` emits operator steps only. It does not stop processes, modify firewall/QPKG state, or change shares. `evidence`, scan `--evidence-dir` and rescue candidate export share an atomic capsule writer: private staging, recursive report redaction, code-preserving incident summary, format v2 payload hashes, and fail-closed publication into a new or empty non-symlink directory. Optional evidence attachments and rescue samples are accepted only for exact report-listed IOC examples and use an aggregate byte cap. Full file recovery must use independently validated offline/immutable backups after containment and trusted rebuild. Neither workflow deletes, decrypts, or writes to the NAS. Capsules are local summaries, not full forensics; they make no claim of complete NAS logs and contain no disk image. The reviewed TS-431K File Station fixture covers only depth-zero root pages and is partial; first use on each supported QTS/model still requires review of redacted response fixtures and live read-only validation.
