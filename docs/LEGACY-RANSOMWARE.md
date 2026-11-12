# Legacy ransomware and QSnatch posture audit

`qts security audit legacy-ransomware` and MCP `qts_legacy_ransomware_security` combine bounded, read-only QPKG version reads with explicit operator confirmations. The report considers Qlocker / HBS 3 (QSA-21-13), DeadBolt / Photo Station (QSA-22-24), and QSnatch (NAS-201911-01). It is a posture checklist, not a malware scanner, compromise verdict, or clean bill of health.

## What is checked

The SSH backend reads only fixed `getcfg` fields for `HybridBackup`, `PhotoStation`, `MalwareRemover`, `SecurityCenter`, and `SecurityCounselor` from QPKG metadata. App versions are compared only against the exact firmware families published in QNAP's advisories. An unlisted firmware branch, missing version, failed probe, or ambiguous package state remains `unknown`; the tool does not infer a newer branch's baseline from an older one. SSH configuration/transport failure stops collection at the first failed probe and adds a stable `collection_errors` code plus an unknown finding to the posture report; it never retries each of the remaining QPKG fields independently.

QTS SSH authorization may require an administrators account; a non-admin SSH path has not been verified on TS-431K. The client-side fixed command allowlist is not a server-side key restriction. Treat the key as admin-level access until the account policy is tested. `from=` and `restrict` may narrow source/forwarding if the firmware SSH server supports them. Do not apply `command=` unless a separately reviewed forced-command dispatcher safely validates every fixed `SSH_ORIGINAL_COMMAND`; a generic forced command will block the probes. See the SSH boundary section in [SCHEDULE.md](SCHEDULE.md).

| Advisory | Read-only package check | Published fixed baseline represented in the rules |
| --- | --- | --- |
| [QSA-21-13 / Qlocker](https://www.qnap.com/en-as/security-advisory/qsa-21-13) | HBS 3 (`HybridBackup`) | QTS 4.5.2: 16.0.0415; QTS 4.3.6: 3.0.210412; QTS 4.3.3/4.3.4: 3.0.210411; QuTS hero h4.5.1 and QuTScloud c4.5.1–c4.5.4: 16.0.0419 |
| [QSA-22-24 / DeadBolt](https://www.qnap.com/zh-tw/security-advisory/qsa-22-24) | Photo Station (`PhotoStation`) | QTS 5.0.1: 6.1.2; QTS 5.0.0 / 4.5.x: 6.0.22; QTS 4.3.6: 5.7.18; QTS 4.3.3: 5.4.15; QTS 4.2.6: 5.2.14 |
| [NAS-201911-01 / QSnatch](https://www.qnap.com/zh-tw/security-advisory/nas-201911-01) | Malware Remover, Security Center and Security Counselor package metadata | Package presence/version/Enable metadata only. Latest definitions and completed scans cannot be proven from these fields. |

Photo Station is end-of-service. A version at an old advisory's fixed threshold does not restore ongoing vendor security updates; migrate away and remove unnecessary exposure through the QTS UI. The audit surfaces installed Photo Station as a warning. Current external exposure adds a separate `high` finding and makes webhook alertable, but does not change the assessment to `suspected`; that status is reserved for campaign indicators rather than exposure alone.

## QSnatch operator-confirmed controls

The QSnatch advisory recommends current QTS and application updates, current Malware Remover and Security Counselor plus scans, credential rotation, reviewing/removing suspicious accounts, IP/account access protection, disabling unused SSH/Telnet/Web Server/SQL services, avoiding default management ports, and restricting router/myQNAPcloud-published access. Since the current read-only probes cannot verify these settings or scan completion, each output control is `unknown` unless the operator explicitly supplies a confirmation.

```bash
qts security audit legacy-ransomware \
  --qsnatch-control qts_latest=yes \
  --qsnatch-control malware_remover_updated_and_scan_run=yes \
  --qsnatch-control access_protection_enabled=no \
  --historical-internet-exposure no --current-internet-exposure no --json
```

Control names accepted by CLI and MCP are `qts_latest`, `apps_latest`, `malware_remover_updated_and_scan_run`, `security_counselor_updated_and_scan_run`, `credentials_rotated`, `accounts_reviewed`, `access_protection_enabled`, `unused_services_disabled`, and `external_access_hardened`. `yes` and `no` are operator assertions, not independent verification. An omitted answer stays `unknown`. Security Counselor availability varies by model / QTS support; use `unknown` when unsupported or unconfirmed.

The output intentionally keeps security-app freshness and scan completion `unknown`, even if package version metadata was found. Do not interpret a QPKG version as current malware definitions, a completed scan, or proof of no infection. Findings are manual follow-up indicators; this command never installs/updates packages, runs a scan, changes credentials, edits account/network settings, removes software, or executes a containment action.

No real TS-431K fixture currently covers these QPKG section/key names or their exact `getcfg` version strings. The current report and package collection tests are synthetic contract tests only; live compatibility claims remain pending the fixture procedure in [COMPATIBILITY.md](../COMPATIBILITY.md). A completed report records SSH collection failures explicitly in `collection_errors`; the schedule process should not treat `assessment: indeterminate` as a successful posture check.

For a NAS confirmed affected by Qlocker, QNAP's guide says not to shut down, reboot, or update QTS whether encryption/compression is in progress or complete. Follow QNAP's [Qlocker response guide](https://www.qnap.com/static/landing/2021/qlocker/response/zh-hk/), including vendor-directed Malware Remover handling, and contact QNAP support. This posture command does not run Malware Remover or change the NAS. The existing incident scan remains bounded to visible File Station names and never reports a no-hit result as clean.

## Sources

- [QNAP QSA-21-13](https://www.qnap.com/en-as/security-advisory/qsa-21-13)
- [QNAP Qlocker response guide (zh-HK)](https://www.qnap.com/static/landing/2021/qlocker/response/zh-hk/)
- [QNAP QSA-22-24](https://www.qnap.com/zh-tw/security-advisory/qsa-22-24)
- [QNAP NAS-201911-01](https://www.qnap.com/zh-tw/security-advisory/nas-201911-01)
- [QNAP QSnatch follow-up (2020)](https://www.qnap.com/zh-tw/security-news/2020/%E5%9B%9E%E6%87%89-qsnatch-%E6%94%BB%E6%93%8A%E4%BA%8B%E4%BB%B6%E6%83%A1%E6%84%8F%E8%BB%9F%E9%AB%94%E7%84%A1%E8%AE%8A%E7%A8%AE%E5%8F%97%E5%BD%B1%E9%9F%BF%E7%94%A8%E6%88%B6%E6%95%B8%E6%8C%81%E7%BA%8C%E7%B8%AE%E6%B8%9B)
- [QNAP Photo Station product status](https://www.qnap.com/en/product/status?category=software)
- [NTHU ESS Qlocker notice](https://ess.site.nthu.edu.tw/p/406-1351-205347,r1602.php?Lang=zh-tw) (secondary reference)
