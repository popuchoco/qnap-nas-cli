# QTS 相容性基線

此表只記錄 repository 中的 fixture provenance、live dry-run 紀錄與 README 所載證據。支援命令表示有對應樣本或唯讀驗證，不代表完整涵蓋或健康保證；`unknown` 是明確的證據缺口。

凍結的五欄 health envelope 由 `qts health` 與 MCP `qts_health` 輸出；incident report 只在 `observations.health` 巢狀包含該 envelope。`qts storage` 是 storage observation，不是 health envelope。

| 機型 | 內部 model | QTS build | 覆蓋命令 | 已知 unknown |
|---|---|---|---|---|
| TS-431K | TS-X41 | QTS 5.2.8 build 20251216 | `status`、`health`、`storage`（sysinfo、volume、SMART 摘要 fixture）；`raid`、`disk-topology`、`smart-details`、`services`（唯讀 SSH fixture/probe）；`tailscale`（live read-only smoke test）；`incident scan` tooling/replay ready（reviewed File Station fixture，僅 depth 0） | `vol_status=0` 語義 unknown；`md9`/`md13` QNAP 128-wide member map 語義 unknown；`get_hd_smartinfo` 1..4 回應為空，SMART attributes unknown；QPKG metadata 不證明 daemon/workload 健康；volume index/full coverage unknown；第二管理員帳號未驗證；File Station 僅含 5 個可見 shares、24 個項目與 depth-0 root pages，22 個子資料夾沒有子頁面，覆蓋不完整且無指標仍為 `indeterminate`、不代表 clean。 |

Reviewed File Station fixture 位於 [`tests/fixtures/ts431k-qts-5.2.8-build-20251216/filestation/`](tests/fixtures/ts431k-qts-5.2.8-build-20251216/filestation/)；它是 depth-0 partial capture，不提供完整 filesystem coverage。Synthetic fixtures 僅保留作 clean、IOC 與 truncation edge-case 測試。

## 尚未經真機 fixture 驗證的 main-only posture audits

以下子命令存在於 `main`，但尚未列入已發布 `0.4.0` 支援範圍，且目前沒有 TS-431K 的專屬實機 fixture：

| 功能 | 尚待實機確認 |
|---|---|
| Plex2Shell audit/report | `PlexMediaServer` 的精確 `getcfg Version` 字串（含任何 hash/build 後綴）、`/bin/pidof` 是否存在且能以配置的 SSH account 執行、各 QPKG key 是否在 TS-431K/QTS 5.2.8 存在。版本 parser 不會猜測未知後綴；格式不符時仍為 unknown。 |
| Legacy ransomware/QSnatch audit/report | HBS 3、Photo Station、Malware Remover、Security Center、Security Counselor 的精確 QPKG section/key 與輸出格式；SSH 權限不足／首次 timeout 的報告契約。 |
| SSH account/key boundary | QTS 上非 administrators 是否可用 SSH、`authorized_keys` 是否支援 `from=`／`restrict`／forced-command wrapper。CLI allowlist 只限制本工具發出的固定命令，不限制遭複製的 key 在 NAS 上的權限。 |

收集上述 fixture 時，在隔離管理 LAN 上以實機 read-only audit 命令輸出 JSON，審閱確認只保留型號、QTS build、QPKG 欄位、固定 IOC probe 狀態及 collection error code；不要提交 hostname、IP、使用者名稱、憑證、日誌或不相關 package data。必須保留實際版本字串原貌，供 M3 version parser 測試；不可以用手寫或猜測字串冒充 TS-431K fixture。加入 fixture 前記錄 firmware/build、擷取日期、命令及審閱者；之後才更新 compatibility claim 與評估 `0.5.0`。

證據來源：[`docs/LIVE-DRY-RUN-TS431K.md`](docs/LIVE-DRY-RUN-TS431K.md)、[`PROVENANCE.md`](tests/fixtures/ts431k-qts-5.2.8-build-20251216/PROVENANCE.md)、[`ssh-provenance.md`](tests/fixtures/ts431k-qts-5.2.8-build-20251216/ssh-provenance.md)。這些記錄證明觀察到的輸出形狀與測試範圍，不代表當前或未來設備狀態。
