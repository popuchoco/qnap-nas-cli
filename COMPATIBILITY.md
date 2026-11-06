# QTS 相容性基線

此表只記錄 repository 中的 fixture provenance、live dry-run 紀錄與 README 所載證據。支援命令表示有對應樣本或唯讀驗證，不代表完整涵蓋或健康保證；`unknown` 是明確的證據缺口。

凍結的五欄 health envelope 由 `qts health` 與 MCP `qts_health` 輸出；incident report 只在 `observations.health` 巢狀包含該 envelope。`qts storage` 是 storage observation，不是 health envelope。

| 機型 | 內部 model | QTS build | 覆蓋命令 | 已知 unknown |
|---|---|---|---|---|
| TS-431K | TS-X41 | QTS 5.2.8 build 20251216 | `status`、`health`、`storage`（sysinfo、volume、SMART 摘要 fixture）；`raid`、`disk-topology`、`smart-details`、`services`（唯讀 SSH fixture/probe）；`tailscale`（live read-only smoke test） | `vol_status=0` 語義 unknown；`md9`/`md13` QNAP 128-wide member map 語義 unknown；`get_hd_smartinfo` 1..4 回應為空，SMART attributes unknown；QPKG metadata 不證明 daemon/workload 健康；volume index/full coverage unknown；第二管理員帳號未驗證；`incident scan` 尚無此機型實機 fixture。 |

證據來源：[`docs/LIVE-DRY-RUN-TS431K.md`](docs/LIVE-DRY-RUN-TS431K.md)、[`PROVENANCE.md`](tests/fixtures/ts431k-qts-5.2.8-build-20251216/PROVENANCE.md)、[`ssh-provenance.md`](tests/fixtures/ts431k-qts-5.2.8-build-20251216/ssh-provenance.md)。這些記錄證明觀察到的輸出形狀與測試範圍，不代表當前或未來設備狀態。
