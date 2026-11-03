# TS-431K live dry-run validation

## Scope and result

Validation attempted on 2026-11-04 against the previously used TS-431K LAN endpoint. Only fixed read-only SSH probes and the fail-closed `repair plan` path were in scope. No service, package, network, firewall, RAID, disk or notification setting was changed.

Overall result: **blocked / not verified**. The NAS endpoint responded, but OpenSSH rejected the available key (`publickey,password,keyboard-interactive`). The previously referenced Windows Credential Manager entries were absent. Without authenticated read access, the CLI could not bind a fresh dry-run plan to live device identity. No password, TOTP, SID, key material, hostname or address is stored in this report.

## Contract results

| Requirement | Result | Evidence / consequence |
|---|---|---|
| Dry-run performs no mutation | Pass offline | Production has no mutation adapter; `unavailable_plan()` contains zero operations and apply returns `refused`. |
| Live device identity binding | Blocked | Authentication was unavailable; do not call this live-verified. |
| Exact confirmation and expiry | Pass offline | Plan hash, exact confirmation, timezone-aware 15-minute expiry and tamper rejection are unit-tested. |
| State-drift rejection | Pass offline | A changed before-state returns `stale_plan` before an adapter is called. |
| Replay / at-most-once behavior | Pass offline | Replaying a completed fake-adapter plan cannot invoke the adapter twice. |
| Ambiguous transport failure | Pass offline | Changed-then-error remains `partial_failure`, records observed state and returns rescue steps. |
| Second administrator | Not proven | No distinct account was authenticated during this window. |
| Independent recovery path | Not proven | The prior LAN endpoint is reachable, but neither a second-account login nor a physical/Qfinder recovery exercise was completed. NAS-hosted Tailscale cannot count as independent for Tailscale-related work. |

## Required live rerun

1. Restore a dedicated, least-privilege read-only login for the CLI and a separate administrator account for recovery; do not put either password or TOTP in repository files or command arguments.
2. From the NAS LAN, log in with the second administrator and confirm access to App Center while keeping the first session open. Record only pass/fail, account role, time and route—never credentials or session tokens.
3. Exercise the independent route without relying on the service being evaluated. For Tailscale or subnet-router work, use direct LAN plus local presence/Qfinder recovery, not another path through NAS-hosted Tailscale.
4. Run `qts status`, `qts services`, `qts health` and `qts raid`; then generate `qts repair plan --action service-start|service-stop`. Confirm it remains `refused`, contains no operations and identifies the same model/firmware/build.
5. Do not register a real adapter yet. First capture redacted before/readback fixtures for one named package and document its exact QTS-version-specific start/stop interface, dependencies and inverse action.

## Concrete rescue baseline for the first service adapter

Keep the existing QTS session open. If a future service operation loses the primary path, stop automated retries, use the already-tested second administrator over direct LAN, and restore the same package in App Center. If QTS is unavailable, use the already-tested local/Qfinder or physical recovery route and follow the model-specific QNAP procedure; do not improvise with firewall, RAID or disk commands. After access returns, collect `services`, `health` and `raid`, verify dependent clients, and preserve the plan ID, timestamps and observations. Until this sequence is exercised successfully, the mutation gate remains closed.
