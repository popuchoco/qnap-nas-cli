# TS-431K live dry-run validation

## Scope and result

Validation attempted on 2026-11-04 against the previously used TS-431K LAN endpoint. Only fixed read-only SSH probes and the fail-closed `repair plan` path were in scope. No service, package, network, firewall, RAID, disk or notification setting was changed.

Overall result: **live read-only dry-run verified; mutation gate remains blocked**. The first attempt failed because no accepted automation key or stored credential was available. After the operator authenticated interactively and installed a dedicated temporary Ed25519 public key, fixed SSH probes succeeded. They identified internal model `TS-X41`, QTS 5.2.8 build 20251216, five md arrays, Container Station/Tailscale QPKG metadata and live Tailscale status. No password, TOTP, SID, private key material, hostname or address is stored in this report.

**File Station dump, web path and offline replay were validated live on 2026-11-06.** The reviewed TS-431K fixture contains five placeholder shares and five root pages. Replay is deliberately partial because depth-zero capture does not include child pages; no indicator was found, but the result remains `indeterminate`, never clean. A second administrator and a second device model remain unproven, so the mutation gate stays closed.

**Scheduled reports, webhook behavior and Evidence Capsule v2 were also validated live on 2026-11-06.** A new report directory produced JSON, a codes-only Markdown summary and a matching SHA-256 manifest; reuse of that non-empty directory was refused with exit code 2. A loopback HTTPS sink received only the allowlisted model/firmware/build, fixed summary and finding/unknown codes. A forced delivery failure returned `connection_error` while preserving the same health observation and exit code. The evidence capsule hashes and sizes matched both payload files. The 10,000-item incident scan was partial and truncated at the configured item limit, found zero IOC examples and remained `indeterminate`; therefore candidate attachment/rescue export was correctly not attempted.

The live dry-run was bound to that observed model/firmware/build and used `unavailable_plan()` directly because the production CLI deliberately has no SSH mutation adapter. It returned `status: refused`, zero operations, four service-stop rescue steps, and both initial and repeated apply attempts returned `refused`. No service, package or setting was changed.

## Contract results

| Requirement | Result | Evidence / consequence |
|---|---|---|
| Dry-run performs no mutation | Pass live | Production has no mutation adapter; the live-bound `unavailable_plan()` contained zero operations and both apply attempts returned `refused`. |
| Live device identity binding | Pass via SSH and QTS web paths | Model `TS-X41`, firmware 5.2.8 and build 20251216 matched both reviewed captures. |
| QTS web status / health | Pass conservatively | Web login succeeded. Health returned `indeterminate` and `healthy_claim: not_permitted` for unverified storage scope and unknown volume status; no write endpoint was used. |
| File Station dump / replay | Pass with partial coverage | Format v3 dump validated; 5 shares and 24 root entries replayed. Twenty-two child folders have no captured child page, so coverage is partial and no-hit remains indeterminate. |
| Exact confirmation and expiry | Pass offline | Plan hash, exact confirmation, timezone-aware 15-minute expiry and tamper rejection are unit-tested. |
| State-drift rejection | Pass offline | A changed before-state returns `stale_plan` before an adapter is called. |
| Replay / at-most-once behavior | Pass offline | Replaying a completed fake-adapter plan cannot invoke the adapter twice. |
| Ambiguous transport failure | Pass offline | Changed-then-error remains `partial_failure`, records observed state and returns rescue steps. |
| Second administrator | Not proven | Only the existing `admin` account was authenticated; no distinct account was exercised. This keeps every mutation adapter blocked. |
| Independent recovery path | Partial | Direct LAN SSH worked while NAS-hosted Tailscale was observed separately as running, so LAN is independent of the Tailscale overlay for a Tailscale service operation. A second-account QTS login and physical/Qfinder recovery exercise were not completed. |
| Live service evidence | Pass with limitations | Container Station and Tailscale metadata were enabled/complete; Tailscale reported Running and online. QPKG metadata alone is not daemon/workload health. |
| Live RAID evidence | Pass with unknowns | No ordinary md member map was degraded. QNAP 128-wide maps for `md13`/`md9` remain unknown by design and are not asserted healthy. |
| Scheduled health report | Pass live | New/empty-directory publication produced JSON, codes-only Markdown and matching hashes; a repeated write to the same directory was refused with exit 2. |
| Webhook allowlist / failure isolation | Pass live | The HTTPS sink saw only allowlisted device fields and codes. A connection failure was recorded in `webhook` but did not change the observation exit code. |
| Evidence Capsule v2 | Pass live with partial scan | Manifest format 2 hashes and sizes matched. The bounded scan reached 10,000 items, was partial/truncated and contained no IOC example, so no sample was exported. |

## Required live rerun

1. Replace the temporary full-admin automation key with a dedicated, least-privilege read-only login where QTS permits it, and create a separate administrator account for recovery; do not put either password or TOTP in repository files or command arguments.
2. From the NAS LAN, log in with the second administrator and confirm access to App Center while keeping the first session open. Record only pass/fail, account role, time and route—never credentials or session tokens.
3. Exercise the independent route without relying on the service being evaluated. For Tailscale or subnet-router work, use direct LAN plus local presence/Qfinder recovery, not another path through NAS-hosted Tailscale.
4. Repeat the QTS web path after firmware changes; the 2026-11-06 run confirmed the plan remains `refused`, contains zero operations and identifies the same model/firmware/build.
5. Do not register a real adapter yet. First capture redacted before/readback fixtures for one named package and document its exact QTS-version-specific start/stop interface, dependencies and inverse action.

## QTS web login path (validated 2026-11-06)

The operator injected password and TOTP through process-only environment variables from the trusted LAN. `status` returned the expected model/firmware/build; `health` remained indeterminate; the service-stop plan was integrity-valid, `status: refused`, contained zero operations and four rescue steps. Applying that refused plan through the local engine also returned `refused`. PowerShell 5 redirected JSON as UTF-16, so validation used BOM-aware decoding; this was an output-file encoding issue, not malformed JSON.

```bash
QTS_PASSWORD='…' QTS_SECURITY_CODE='…' qts --json status
QTS_PASSWORD='…' QTS_SECURITY_CODE='…' qts --json health
QTS_PASSWORD='…' QTS_SECURITY_CODE='…' qts repair plan --action service-stop --output /tmp/qts-repair-plan.json --json
QTS_PASSWORD='…' QTS_SECURITY_CODE='…' qts repair apply /tmp/qts-repair-plan.json --confirm '<plan_id>' --json
```

For the final command, substitute the `plan_id` returned by the plan command. Paste back only redacted pass/fail results, exit codes, model/firmware/build, and `plan status: refused`. Never paste the password, security code/TOTP, SID, hostname, or IP address. Keep the local plan file private and remove it after reporting the redacted result.

## File Station reviewed fixture capture (completed 2026-11-06)

The live format-v3 dump and offline validation completed successfully. The first review found that arbitrary first-level folder names survived the original redactor even though network/session pattern scans passed. The redactor was corrected to replace every ordinary entry name with a deterministic placeholder while preserving only incident-rule semantics. The fixture was then transformed, validated, replayed and reviewed before inclusion.

```bash
QTS_PASSWORD='…' QTS_SECURITY_CODE='…' qts dump --filestation /tmp/qts-dump-filestation --json
qts fixture validate /tmp/qts-dump-filestation --json
```

Final review covered 29 name fields and found zero unsafe names, private/Tailscale IPs, MACs or SID/qtoken patterns. Replay saw 5 shares, 24 entries and no indicator, but reported partial coverage because 22 child paths were intentionally not captured. The original local dump is not committed.

## Concrete rescue baseline for the first service adapter

Keep the existing QTS session open. If a future service operation loses the primary path, stop automated retries, use the already-tested second administrator over direct LAN, and restore the same package in App Center. If QTS is unavailable, use the already-tested local/Qfinder or physical recovery route and follow the model-specific QNAP procedure; do not improvise with firewall, RAID or disk commands. After access returns, collect `services`, `health` and `raid`, verify dependent clients, and preserve the plan ID, timestamps and observations. Until this sequence is exercised successfully, the mutation gate remains closed.
