# TS-431K live dry-run validation

## Scope and result

Validation attempted on 2026-11-04 against the previously used TS-431K LAN endpoint. Only fixed read-only SSH probes and the fail-closed `repair plan` path were in scope. No service, package, network, firewall, RAID, disk or notification setting was changed.

Overall result: **live read-only dry-run verified; mutation gate remains blocked**. The first attempt failed because no accepted automation key or stored credential was available. After the operator authenticated interactively and installed a dedicated temporary Ed25519 public key, fixed SSH probes succeeded. They identified internal model `TS-X41`, QTS 5.2.8 build 20251216, five md arrays, Container Station/Tailscale QPKG metadata and live Tailscale status. No password, TOTP, SID, private key material, hostname or address is stored in this report.

**File Station / incident scan tooling and offline replay are ready, but still 仍需 reviewed fixture（需實機＋小鑫審閱）.** The checked-in synthetic-shape fixture exercises clean, IOC, and partial-page replay only; it was not captured from a device and is not reviewed evidence. A second administrator and a second device model also remain unproven, so the mutation gate stays closed.

The live dry-run was bound to that observed model/firmware/build and used `unavailable_plan()` directly because the production CLI deliberately has no SSH mutation adapter. It returned `status: refused`, zero operations, four service-stop rescue steps, and both initial and repeated apply attempts returned `refused`. No service, package or setting was changed.

## Contract results

| Requirement | Result | Evidence / consequence |
|---|---|---|
| Dry-run performs no mutation | Pass live | Production has no mutation adapter; the live-bound `unavailable_plan()` contained zero operations and both apply attempts returned `refused`. |
| Live device identity binding | Pass via SSH observation | Model, firmware and build matched the reviewed fixture. This did not exercise QTS web login or a mutation endpoint. |
| Exact confirmation and expiry | Pass offline | Plan hash, exact confirmation, timezone-aware 15-minute expiry and tamper rejection are unit-tested. |
| State-drift rejection | Pass offline | A changed before-state returns `stale_plan` before an adapter is called. |
| Replay / at-most-once behavior | Pass offline | Replaying a completed fake-adapter plan cannot invoke the adapter twice. |
| Ambiguous transport failure | Pass offline | Changed-then-error remains `partial_failure`, records observed state and returns rescue steps. |
| Second administrator | Not proven | Only the existing `admin` account was authenticated; no distinct account was exercised. This keeps every mutation adapter blocked. |
| Independent recovery path | Partial | Direct LAN SSH worked while NAS-hosted Tailscale was observed separately as running, so LAN is independent of the Tailscale overlay for a Tailscale service operation. A second-account QTS login and physical/Qfinder recovery exercise were not completed. |
| Live service evidence | Pass with limitations | Container Station and Tailscale metadata were enabled/complete; Tailscale reported Running and online. QPKG metadata alone is not daemon/workload health. |
| Live RAID evidence | Pass with unknowns | No ordinary md member map was degraded. QNAP 128-wide maps for `md13`/`md9` remain unknown by design and are not asserted healthy. |

## Required live rerun

1. Replace the temporary full-admin automation key with a dedicated, least-privilege read-only login where QTS permits it, and create a separate administrator account for recovery; do not put either password or TOTP in repository files or command arguments.
2. From the NAS LAN, log in with the second administrator and confirm access to App Center while keeping the first session open. Record only pass/fail, account role, time and route—never credentials or session tokens.
3. Exercise the independent route without relying on the service being evaluated. For Tailscale or subnet-router work, use direct LAN plus local presence/Qfinder recovery, not another path through NAS-hosted Tailscale.
4. Complete the QTS web-authenticated path below. Confirm the plan remains `refused`, contains no operations and identifies the same model/firmware/build. The SSH-bound dry-run is already verified, but it does not substitute for this web path.
5. Do not register a real adapter yet. First capture redacted before/readback fixtures for one named package and document its exact QTS-version-specific start/stop interface, dependencies and inverse action.

## QTS web login path (offline checklist pending operator run)

No web login was attempted for this checklist. It needs 小鑫 to run from the trusted NAS LAN with the existing config from `qts setup --origin https://<NAS> --user <acct> ...`. Inject secrets through environment variables only; never put them in application arguments or files. Run each command once. Stop immediately after any authentication failure; do not retry with alternate credentials or codes.

```bash
QTS_PASSWORD='…' QTS_SECURITY_CODE='…' qts --json status
QTS_PASSWORD='…' QTS_SECURITY_CODE='…' qts --json health
QTS_PASSWORD='…' QTS_SECURITY_CODE='…' qts repair plan --action service-stop --output /tmp/qts-repair-plan.json --json
QTS_PASSWORD='…' QTS_SECURITY_CODE='…' qts repair apply /tmp/qts-repair-plan.json --confirm '<plan_id>' --json
```

For the final command, substitute the `plan_id` returned by the plan command. Paste back only redacted pass/fail results, exit codes, model/firmware/build, and `plan status: refused`. Never paste the password, security code/TOTP, SID, hostname, or IP address. Keep the local plan file private and remove it after reporting the redacted result.

## File Station reviewed fixture capture (pending operator)

Still needs a reviewed live dump（需實機＋小鑫審閱）. After `qts setup` and env injection of secrets (never argv / never write secrets to disk):

```bash
QTS_PASSWORD='…' QTS_SECURITY_CODE='…' qts dump --filestation /tmp/qts-dump-filestation --json
qts fixture validate /tmp/qts-dump-filestation --json
```

Before any commit: manually review `filestation/*.json` for hostnames, IPs, serials, usernames, share names, SID/qtoken, MACs; keep only redacted structure. Record PROVENANCE with capture date, model/firmware/build, and that a human reviewed the redaction. Do not paste secrets into chat or the repository.

## Concrete rescue baseline for the first service adapter

Keep the existing QTS session open. If a future service operation loses the primary path, stop automated retries, use the already-tested second administrator over direct LAN, and restore the same package in App Center. If QTS is unavailable, use the already-tested local/Qfinder or physical recovery route and follow the model-specific QNAP procedure; do not improvise with firewall, RAID or disk commands. After access returns, collect `services`, `health` and `raid`, verify dependent clients, and preserve the plan ID, timestamps and observations. Until this sequence is exercised successfully, the mutation gate remains closed.
