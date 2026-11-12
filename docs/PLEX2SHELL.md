# Plex2Shell read-only posture audit

`qts security audit plex2shell` is a first defensive milestone for the Plex2Shell issue. It reads the `PlexMediaServer` QPKG `Name`, `Version`, `Status`, and `Enable` keys through fixed, shell-free SSH `getcfg` probes and compares the observed version with QNAP's published patched baseline. It can also accept explicit operator-reported answers about current exposure and exposure while the vulnerable version was installed.

```sh
qts security audit plex2shell --json
qts security audit plex2shell \
  --exposure-during-vulnerable-version yes \
  --current-exposure no --json
qts security audit plex2shell \
  --ioc-unknown-plex-process yes \
  --ioc-proxystream-st-connection yes --json
qts security audit plex2shell --check-known-process-iocs --json
```

Equivalent read-only MCP tool: `qts_plex_security`, with optional `exposure_during_vulnerable_version` and `current_exposure` values (`yes` or `no`). Omitted values remain `unknown`.

The audit can structure five **operator-reported** QNAP indicators using `--ioc-unknown-plex-process`, `--ioc-unfamiliar-codecs-files`, `--ioc-proxystream-st-connection`, `--ioc-sustained-idle-cpu`, and `--ioc-malware-remover-detection`. Each accepts only `yes` or `no`; omitted fields remain `unknown`. A reported positive indicator changes the assessment to `suspected` and adds a fixed finding code. The MCP tool accepts corresponding `ioc_*` fields.

`--check-known-process-iocs` is a separate explicit opt-in. It invokes only fixed `/bin/pidof` probes for the three process names QNAP calls out (`myawesomeproxy`, `mylovelyminer`, `x12345`); the report contains names and match counts, never PIDs or command lines. A restricted SSH key may reject this direct probe before execution; that is a collection failure, not evidence that the binary is absent or the process was not running. A no-match only means those exact names were not running at that instant. If an environment provides a separate process-snapshot wrapper, its exact output format must be reviewed before this CLI consumes it.

`qts report plex2shell` accepts the same `--exposure-during-vulnerable-version`, `--current-exposure`, and `--ioc-*` operator assertions as the direct audit. Those values are included in the observation and should only be supplied after operator review. The scheduled bundle is atomically published before webhook delivery; webhook delivery status remains in the CLI receipt, not in the signed-off observation bundle.

## Assessment contract

- The current QNAP advisory identifies Plex Media Server 1.43.2 and earlier as affected, and identifies 1.43.3 (build 1.43.3.10861) as the patched release. QNAP's App Center can expose the coarse `1.43.3` label, so this implementation treats that exact three-component label as meeting QNAP's patched baseline. Four-component builds are compared numerically. A provisional parser also accepts exactly four numeric components followed by `-` and 7–40 hexadecimal characters as a build/hash suffix; the numeric components are compared and the raw string remains in the report. This syntax is covered by synthetic tests only; no real QPKG value has validated it. Other suffixes, pre-release labels, malformed, or absent versions remain unknown; do not strip arbitrary suffixes.
- `vulnerable` and `vulnerable_exposed` indicate version posture, not proof of exploitation. `potentially_compromised` is raised when the operator reports reachability while a vulnerable version was installed. `suspected` means an operator reports a QNAP-listed indicator or an opt-in exact-name probe matches; neither is a forensic confirmation. `patched` means only that the observed package version meets the rule; it does not mean clean or uncompromised.
- `not_installed` means this QPKG section was not observed. It does not rule out a manual/container/alternate Plex installation.
- `suspected` means an operator reported at least one QNAP-listed indicator or the opt-in exact-name process probe matched; it is a triage signal, not a confirmed incident.
- External exposure is not probed. Router port-forwarding, UPnP, myQNAPcloud, firewall rules and historical reachability are not inferable from QPKG metadata. Unknown remains explicit in the report.

## Scope and response

This is a bounded inventory/triage aid, **not** a complete incident scanner or compromise determination. Apart from the optional exact-name `pidof` probes, it does not inspect process trees, Plex Codecs, logs, file contents, outbound network connections, router configuration, CPU telemetry, or Malware Remover status. It does not stop services, change exposure, uninstall Plex, delete files, or rotate credentials. The QPKG `Status`/`Enable` values do not prove runtime health.

If the result is vulnerable, update Plex in QNAP App Center to the current QNAP-supported patched release and verify the version afterward. Reduce unnecessary Internet reachability (Remote Access, TCP 32400, UPnP, and myQNAPcloud port forwarding); use a VPN for remote access where possible. If Plex was reachable while vulnerable or an indicator is reported, preserve the Plex Logs folder and relevant evidence before uninstalling or cleaning up, then follow QNAP's clean reinstall and credential-reset sequence and contact QNAP support. Do not just delete a suspicious process or Codecs file. Any rebuild/reinstall and credential rotation are administrator-led; this tool does not automate them.

This initial implementation is versioned under rule `plex2shell-qnap-2026-11`. Review it when QNAP/Plex publish updated advisories or new fixed versions.

## SSH access boundary

The SSH probes use a fixed client-side argv allowlist, `shell=False`, and no user-provided remote command. This is a property of this client, **not** a restriction on the SSH key itself. QTS may require SSH users to be administrators; do not describe an identity as a “read-only SSH account/key” unless the account privileges have been independently verified. Protect the key according to the NAS account's privileges. A server-side `command=` wrapper must validate exact `SSH_ORIGINAL_COMMAND` values and dispatch only reviewed fixed probes; a generic forced command can reject this client's direct `getcfg`/`pidof` probes. Do not infer that a rejected command or file is missing. Where the QTS SSH server supports it, `from=` and `restrict` may further reduce exposure; verify support and behavior on the target firmware. When an explicit identity file is configured, the client adds `IdentitiesOnly=yes` to avoid offering unrelated agent identities.

## References

- [QNAP Plex2Shell check and remediation FAQ](https://www.qnap.com/zh-tw/how-to/faq/article/plex2shell-check-and-remediation-faq-for-qnap-nas-users)
- [Plex security update announcement](https://forums.plex.tv/t/important-security-update-for-plex-media-server-v1-43-2-and-earlier/942319/1)
- [HKEPC report](https://www.hkepc.com/27202) (secondary reporting; indicators in the article are not implemented as detection rules here)
