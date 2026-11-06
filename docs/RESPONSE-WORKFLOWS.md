# Repair and ransomware-response workflows

This document distinguishes **device health**, **known indicators**, and **proof of compromise**. The current implementation is a read-only v1 plus a generic fail-closed repair engine. It is not an incident-cleanup product and does not claim a negative scan proves safety.

## Ordinary repair: observe → plan → approve → apply → verify

1. **Observe:** query current health, storage, RAID, package state and exact model/firmware. Preserve unknowns and parser coverage gaps; don't transform missing data into healthy.
2. **Plan:** generate a short-lived plan tied to device identity. Each operation must state its exact target, before state, desired after state, read-only preflight, risk, dependencies, recovery path and verification query. No arbitrary API endpoint, shell string or user-supplied executable is allowed.
3. **Approve:** display the whole plan; require an exact plan ID, a fresh state read, a second administrator and independent recovery route for any remote mutation.
4. **Apply:** execute one operation at a time through a reviewed adapter. Recheck device identity, preconditions and before state immediately before the write. Stop on any mismatch or error; don't silently retry or continue to the next operation.
5. **Verify:** re-read through an independent observation where possible, compare with the desired state, emit an audit record and rerun health. A failed verification produces `partial_failure` and recovery guidance, never a success result.

`remediation.py` implements this contract and has fake-adapter tests for confirmation, state drift, readback and stop-on-failure. No real QTS action is registered, so CLI plans currently have `status: refused`; `repair apply` cannot change a NAS. Every future mutation adapter must pass explicit gates before registration: a reviewed QTS API/SSH and dry-run contract for the named model/firmware; idempotency analysis; concrete failure and recovery steps; live tests including failure/readback cases; and confirmation of a second administrator plus an independent recovery/management path. These are required in addition to the plan/apply confirmation flow, not substitutes for it.

### Idempotency and replay contract

- A plan is bound to the observed `before` state, device identity, 15-minute expiry and exact `plan_id`. It is not a reusable command token.
- Replaying a successfully applied plan observes a different current state and returns `stale_plan`; the adapter is not called twice. This is deliberate at-most-once behavior rather than treating replay as another success.
- If transport fails after QTS may have accepted an operation, the engine reads state once and returns `partial_failure` with `observed_after` and rescue guidance. Even when the desired state is observed, it does not invent a successful response.
- A later retry requires a new observation and a new plan. An adapter must separately prove that its underlying QTS operation is convergent (`target → target` has no additional side effect), because plan-level replay protection cannot prove endpoint idempotency.
- Multi-step plans stop at the first stale read, operation error or failed readback. Automatic rollback is forbidden until the inverse operation has its own model/firmware evidence and failure analysis.

### Recovery-readiness proof

Text in a plan is not proof. Before any production adapter can return `ready`, the maintenance record must show that, during the current window: (1) a distinct administrator account logged in successfully; (2) a LAN or physical management route that does not depend on the target service was exercised; (3) the operator knows which QTS App Center action restores the exact service; and (4) post-recovery `services`, `health` and `raid` observations can be collected. Tailscale on the NAS is not an independent route when Tailscale itself or its subnet routing is the mutation target. An untested account, saved password, ordinary client path through the same VPN, or a promise of later physical access does not satisfy this gate.

The current TS-431K result is recorded in [LIVE-DRY-RUN-TS431K.md](LIVE-DRY-RUN-TS431K.md).

## Suspected ransomware: scan → contain → preserve → rescue/recover

### Scan

`qts incident scan` walks File Station-visible shares using `get_tree` and paged `get_list` from QNAP's [File Station HTTP API v5](https://download.qnap.com/dev/QNAP_QTS_File_Station_API_v5.pdf), with a hard item limit and a depth limit. The report exposes `coverage.truncated`, `coverage.depth_limited`, and `coverage.truncation_reasons`; `coverage.status: partial` or either limit flag means the inventory is incomplete and a missing indicator is not negative evidence. It searches names only for campaign-specific indicators:

- `!!!READ_ME.txt` as a Qlocker-related indicator.
- 10 or more `.7z` names as a low-confidence Qlocker-like archive cluster. Large `.7z` groups can be ordinary backups; the cluster alone does not raise the assessment to `suspected` and requires corroboration such as `!!!READ_ME.txt`, DeadBolt indicators, QTS alerts, or other independent evidence.
- `.deadbolt` as DeadBolt-related evidence.

QNAP documents Qlocker archive/note behavior and DeadBolt's extension in its [Qlocker response](https://www.qnap.com/static/landing/2021/qlocker/response/en/) and [DeadBolt advisory QSA-22-02](https://www.qnap.com/en-us/security-advisory/qsa-22-02). A `.7z` alone is common and low-confidence. The tool does not inspect file content, process behavior, logs, credentials, deleted files, or inaccessible paths. A hit is **suspected**, not confirmed; no hit is **indeterminate**, never clean.

### Contain

`qts incident contain REPORT` returns an operator checklist, not commands. For a suspected event, reduce new writes and use router/switch controls to limit external and unnecessary client traffic while preserving a controlled evidence/management path. Avoid unreviewed NAS firewall changes, process kills, package stops, deletion or reboot from this CLI. If there is active encryption, use the QNAP guidance for the identified family and contact vendor support; QNAP's Qlocker guidance specifically says not to shut down/reboot during active encryption/compression.

### Preserve evidence

`qts incident scan --evidence-dir CASE` and `qts incident evidence REPORT CASE` use the same hardened capsule writer. It accepts a new or empty target directory, stages files privately, and publishes the directory atomically. The capsule contains a recursively redacted `incident.json` with `emitted_at`, a `summary.md` listing assessment, coverage flags, indicator families/codes and finding/unknown codes only, and a format v2 `manifest.json` with payload sizes and SHA-256 digests. Symlink, non-empty, root, current-working-directory and home-directory targets are refused.

This is a local capsule, not full forensics. It makes no claim of complete NAS log coverage and contains no disk image. Optional `qts incident evidence REPORT CASE --attach-candidate PATH` may be repeated for up to 100 exact paths listed in the report's indicator `examples`; `--max-bytes` applies to their combined size (100 MiB by default, 1 GiB maximum). Samples stream read-only into safe names under `samples/`. They are not written back to the NAS, executed or decrypted. Keep the case directory access-controlled and record who collected it and when.

### Rescue and recovery

`qts incident rescue REPORT` emits a manual recovery checklist. `--candidate-path` may export a file only if that exact path appears in the report's IOC examples; streaming is size-bounded and the report, sample and rescue receipt are published through the same atomic capsule writer. This is **evidence/sample export**, not restoration. The CLI does not decrypt or write files back to the NAS. For recovery, first contain and rebuild/patch from a trusted process; restore verified offline/immutable backups to a clean isolated destination, validate sample hashes, permissions and application behavior, then perform an approved cutover. Preserve original affected media/data for support and investigation.

## Expansion gates

The next safe detection step is read-only process/log evidence with firmware fixtures and explicit coverage, then correlation of file-change rates, process identity/start time and QTS alerts. The current capsule contains the structured report and optional explicitly selected samples; it is not full forensic acquisition and does not claim complete NAS logs or include a disk image. Automated process suspension, network isolation, package stop, ransomware cleanup and backup restore each require a separate reviewed adapter and a two-step plan/apply gate; they must not be inferred from a filename hit.
