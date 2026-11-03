# SSH fixture provenance

- Device: TS-431K (`TS-X41`), QTS 5.2.8 build 20251216
- Captured: 2026-11-03 through a temporary key with read-only commands
- Commands: `cat /proc/mdstat`, `/sbin/qcli_storage -d`, `/sbin/get_hd_smartinfo -d 1..4`, and fixed-field QPKG `getcfg` reads
- SMART result: all four `get_hd_smartinfo` probes returned empty output; `smartctl` was not installed
- Redaction review: no credentials, serial numbers, LAN addresses, Tailnet addresses, or NAS hostname are included
- Interpretation: `md1` is `[3/3] [UUU]`; the 128-wide `md9`/`md13` maps are retained as unknown QNAP semantics rather than labeled degraded
