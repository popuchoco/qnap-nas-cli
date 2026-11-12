# QTS 相容性基線

此表只記錄 repository 中的 fixture provenance、live dry-run 紀錄與 README 所載證據。支援命令表示有對應樣本或唯讀驗證，不代表完整涵蓋或健康保證；`unknown` 是明確的證據缺口。

凍結的五欄 health envelope 由 `qts health` 與 MCP `qts_health` 輸出；incident report 只在 `observations.health` 巢狀包含該 envelope。`qts storage` 是 storage observation，不是 health envelope。

| 機型 | 內部 model | QTS build | 覆蓋命令 | 已知 unknown |
|---|---|---|---|---|
| TS-431K | TS-X41 | QTS 5.2.8 build 20251216 | `status`、`health`、`storage`（sysinfo、volume、SMART 摘要 fixture）；`raid`、`disk-topology`、`smart-details`、`services`（唯讀 SSH fixture/probe）；`tailscale`（live read-only smoke test）；`incident scan` tooling/replay ready（reviewed File Station fixture，僅 depth 0） | `vol_status=0` 語義 unknown；`md9`/`md13` QNAP 128-wide member map 語義 unknown；`get_hd_smartinfo` 1..4 回應為空，SMART attributes unknown；QPKG metadata 不證明 daemon/workload 健康；volume index/full coverage unknown；第二管理員帳號未驗證；File Station 僅含 5 個可見 shares、24 個項目與 depth-0 root pages，22 個子資料夾沒有子頁面，覆蓋不完整且無指標仍為 `indeterminate`、不代表 clean。 |

Reviewed File Station fixture 位於 [`tests/fixtures/ts431k-qts-5.2.8-build-20251216/filestation/`](tests/fixtures/ts431k-qts-5.2.8-build-20251216/filestation/)；它是 depth-0 partial capture，不提供完整 filesystem coverage。Synthetic fixtures 僅保留作 clean、IOC 與 truncation edge-case 測試。

## 尚未列入發布支援範圍的 main-only security posture audits

以下子命令存在於 `main`，但尚未列入已發布 `0.4.0` 支援範圍。此表記錄待驗證項目，不包含使用者 NAS 的實機結果：

| 功能 | 尚待實機確認 |
|---|---|
| Plex2Shell audit/report | 需取得經遮蔽的實際 `PlexMediaServer` `getcfg Version` 字串（含任何 hash/build 後綴），並確認固定 runtime probe 在目標 SSH policy 下可用。候選 suffix parser 目前只有 synthetic tests。 |
| Legacy ransomware/QSnatch audit/report | 需 fixture 驗證 HBS 3、Photo Station、Malware Remover、Security Center、Security Counselor 的實際 QPKG section/key、版本與 direct collector 輸出。 |
| SSH account/key boundary | 非管理員 SSH 登入、forced-command dispatcher 輸出協定，以及 `from=`／`restrict` 支援均需實測。Client allowlist 不限制 NAS 帳號或遭複製 key 的權限。 |
| Windows atomic report/evidence writes | GitHub Actions workflow 包含 Windows 2022 report/evidence atomic writer tests；請以 CI run 確認目標 revision 的結果。 |

若要新增公開 fixture，先取得明確同意並做隱私／安全審查；預設不將使用者的實機輸出、設備識別資訊、SSH policy、程序快照或套件清單提交到 repository。若只需要 regression coverage，使用 synthetic fixture 並清楚標示，不冒充真機資料。實機相容性只有在授權公開、經遮蔽審查的 fixture 存在後才更新為公開支援 claim；之後才評估 `0.5.0`。

相容性證據流程見 [`docs/LIVE-DRY-RUN-TS431K.md`](docs/LIVE-DRY-RUN-TS431K.md) 與 fixture provenance。任何公開證據只說明其明確涵蓋的觀察範圍，不代表當前或未來設備狀態。
