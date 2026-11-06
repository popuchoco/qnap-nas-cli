# qnap-nas-cli

[![CI](https://github.com/popuchoco/qnap-nas-cli/actions/workflows/ci.yml/badge.svg)](https://github.com/popuchoco/qnap-nas-cli/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

> **支援範圍：**唯讀 QTS 診斷 CLI 與 MCP；已審查基線為 TS-431K / QTS 5.2.8，其他機型／韌體可能回報 unknown。請見[相容性表](COMPATIBILITY.md)與[觀察資料契約](docs/OBSERVATION_CONTRACT.md)。
>
> **支援政策：**僅支援最新的 `main` 與最新 release。
>
> **Mutation 尚未啟用：**沒有生產用 mutation adapter；MCP 不提供通用 shell 或任意 QTS API 工具。`0.2.0` 已發布到 PyPI，可用 pipx 或 pip 安裝；安裝方式見[安裝指南](docs/INSTALL.md)。維護與發布流程見[貢獻指南](CONTRIBUTING.md)及[發布說明](docs/PUBLISHING.md)。

安全優先、零第三方 Python 相依的 QNAP QTS 診斷 CLI 與唯讀 MCP Server。目標是讓人與 AI agent 都能取得可稽核的 NAS 健康證據，而不是在缺乏實機驗證時直接修改 RAID、磁碟或網路服務。

目前版本為 `0.2.0`，主要相容目標為 QTS 5.x 與 TS-431K。QTS CGI 欄位會因機型、韌體及安裝套件而異；請使用 `qts dump` 提供已遮蔽的相容性樣本。

## 目前狀態

- 初始唯讀診斷版本已於 2026-11-03 發布到 `main`。
- CI 執行離線測試、Python bytecode compilation 與 CLI smoke test；repair 已完成 SSH 身分綁定的零操作實機 dry-run，但第二管理帳號與 QTS web 路徑尚未驗證，因此 mutation gate 仍關閉，詳見 [`docs/LIVE-DRY-RUN-TS431K.md`](docs/LIVE-DRY-RUN-TS431K.md)。
- GitHub Actions 在 Python 3.8、3.12、3.13 驗證：[CI workflow](https://github.com/popuchoco/qnap-nas-cli/actions/workflows/ci.yml)。
- CI 固定使用 Ubuntu 22.04，因為 GitHub 的 Ubuntu 26 runner 不再提供 Python 3.8；這是為了保留較舊 NAS／管理環境的相容性，不是測試降級。
- 已用 TS-431K、QTS 5.2.8 build 20251216 完成 2FA 與唯讀 SSH live smoke test，並納入人工審查的 system／volume／SMART、`mdstat` 與實體磁碟拓樸 fixture。QTS 在此機型回報的內部 model 是 `TS-X41`。

維護者：`popuchoco <p.choco@daum.net>`

## 功能

- `setup`：保存 HTTPS、帳號與選用的 SSH 主機；不保存密碼。
- `doctor`／`whoami`：檢查本機條件並驗證 QTS 登入。
- `status`：型號、韌體、CPU、記憶體、溫度與 uptime。
- `health`：唯讀彙整磁碟、Volume、已知異常 finding 與資料不足 unknown；`healthy`、`unhealthy`、`indeterminate` 不混為一談，回報使用中的通用溫度門檻。
- `storage`／`disks`／`volumes`：合併 Volume、sysinfo bay 與 `qsmart.cgi` SMART 摘要；可重複指定 `--volume-index N`，但尚無 endpoint 可證明全部 index 已查齊。
- `network`：介面、IP、速度與 DNS。
- `tailscale`：從已驗證的 QPKG 安裝路徑執行固定的 `tailscale status --json`。
- `raid`：直接讀取並解析 `/proc/mdstat`，標示 degraded、member state 與 recovery/resync 進度；QNAP 128-wide bitmap 保守標為未知語義。
- `disk-topology`：用 `qcli_storage -d` 讀取實體 bay、data/spare 角色、容量與型號。
- `smart-details DISK`：以已驗證的 bay 編號讀取 QNAP SMART attributes；韌體空回應會明確標為 unavailable。
- `services`：唯讀觀察 Container Station／Tailscale QPKG metadata，不把 `Status=complete` 誤稱為 daemon 正常運行。
- `dump`：匯出已遮蔽 hostname、序號、IP 與 DNS 的相容性樣本。
- `fixture validate`：不連 NAS，離線檢查 dump 能否解析及是否存在未知欄位／狀態碼。
- `incident scan`：有上限地遞迴掃描 File Station 可見共享資料夾的檔名，檢查 Qlocker／DeadBolt 已知指標，並彙整 health、RAID 與套件 observation；報告會標記 `truncated`、`depth_limited` 與截斷原因。
- `incident contain`：由 report 產生人工網路隔離／取證清單；不改 NAS 防火牆或停止程序。
- `incident evidence`：保存 report 到新的本機目錄並寫 SHA-256 manifest；不宣稱包含 NAS 原始日誌。
- `incident rescue`：輸出離線備份復原步驟；也可將 report 已列出的可疑檔案唯讀串流匯出到新的本機 case directory，產生 SHA-256，不會解密、執行或回寫 NAS。
- `repair plan`／`repair apply`：具備確認碼、短效 plan、裝置身分／前置條件／before-state／readback 驗證的 fail-closed 框架；目前沒有生產用 QTS mutation adapter，所有 CLI plan 都會明確拒絕執行，apply 不會改 NAS。
- `mcp`：提供十個唯讀 stdio MCP tools。
- 全部資料命令支援 `--json`。

本版不提供 RAID 重建、SMART 修復、Container Station 停止、Tailscale 重啟、惡意程序 suspend/kill、QTS 防火牆修改、惡意檔案刪除或 NAS 上直接還原。通用 plan/apply 執行引擎可由測試用 adapter 驗證，但正式 adapter 必須先有指定機型／韌體的實機契約測試、前置條件與第二管理路徑、before/after readback、失敗中止與回復程序。

## 安裝

需求為 Python 3.8 以上，執行時不需要第三方套件。套件已發布到 PyPI；pipx、venv/pip、Git checkout 與離線 wheel 的安裝方式見[安裝指南](docs/INSTALL.md)。

```bash
pipx install qnap-nas-cli
qts --help
qts --version
```

也可在虛擬環境中用 pip 安裝，或直接從 checkout 執行。完整步驟見[安裝指南](docs/INSTALL.md)：

```bash
python3 -m venv .venv
. .venv/bin/activate
python -m pip install qnap-nas-cli

# 從 checkout 開發安裝
git clone https://github.com/popuchoco/qnap-nas-cli.git
cd qnap-nas-cli
python -m pip install -e .

# 或不安裝，直接執行
python -m qnap_nas_cli --help
```

## 快速開始

QTS 應使用有效 HTTPS 憑證。`--insecure` 只適合受信任區網內的暫時測試。

```bash
qts setup --origin https://192.0.2.10 --user ops \
  --ssh-host 192.0.2.10 --ssh-user ops \
  --ssh-identity-file ~/.ssh/qnap_ops

# 互動式輸入密碼；若帳號啟用 2FA，CLI 會接著提示 TOTP
qts status
qts health
qts storage --json
qts storage --volume-index 1 --volume-index 2 --json
qts network
qts raid --json
qts disk-topology --json
qts smart-details 2 --json
qts services --json

# 勒索事件：有限掃描，並建立本機 evidence bundle
qts incident scan --max-items 10000 --evidence-dir case-2026-01 --json
qts incident contain case-2026-01/incident.json --json
qts incident rescue case-2026-01/incident.json --json
# 只有在要匯出 report 已列出的 IOC 範例檔時才提供 candidate path。
# 匯出到全新的本機目錄，預設上限 100 MiB；不是 NAS restore。
qts incident rescue case-2026-01/incident.json --candidate-path '/Public/!!!READ_ME.txt' --directory case-sample

# 一般修復流程目前只會建立明確拒絕執行的計畫，不會修改 NAS
qts repair plan --action service-stop --output qts-repair-plan.json --json
qts repair apply qts-repair-plan.json --confirm '<plan_id>' --json

# 自動化或 MCP；不要把密碼寫進 shell history
QTS_PASSWORD='...' qts --json health
QTS_PASSWORD='...' qts mcp

# 啟用 2FA 的帳號：驗證碼只存在當次 process environment
QTS_PASSWORD='...' QTS_SECURITY_CODE='…' qts --json health

# 產生已遮蔽的相容性資料
qts dump qts-dump
# 可選：額外擷取已遮蔽 File Station（仍需實機＋人工審閱才算 reviewed fixture）
qts dump --filestation qts-dump
qts fixture validate qts-dump --json
```

若 stdin 不是終端，CLI 也能從 stdin 第一行讀取密碼。互動終端在 QTS 回報需要 2FA 時才提示 TOTP；非互動與 MCP 必須注入 `QTS_SECURITY_CODE`。密碼與驗證碼不接受命令列參數，也不會寫入設定檔。自動化注入與 shell history 安全說明見[憑證注入指南](docs/SECRETS.md)。

## MCP

```json
{
  "mcpServers": {
    "qnap-nas": {
      "command": "qts",
      "args": ["mcp"],
      "env": {"QTS_PASSWORD": "由安全的秘密管理工具注入"}
    }
  }
}
```

提供的 tools：

- `qts_status`
- `qts_health`
- `qts_storage`
- `qts_network`
- `qts_tailscale`
- `qts_raid`
- `qts_smart_details`
- `qts_disk_topology`
- `qts_services`
- `qts_incident`（有限名稱 IOC 掃描；assessment 不會回報 clean）

MCP 目前刻意只讀，不提供通用 shell 或任意 QTS API 呼叫。

## Health 語義

`health` 不把「沒有發現異常」直接等同「已證明健康」：

- `status: healthy`／`healthy: true`：必要狀態完整，而且觀察值沒有已知異常。
- `status: unhealthy`／`healthy: false`：存在已知異常，例如 degraded Volume、明確 SMART warning 或過熱。
- `status: indeterminate`／`healthy: null`：資料缺少、`vol_status=0`、未知狀態碼，或 parser 沒找到必要記錄。

當結果為 `indeterminate` 時也會輸出 `healthy_claim: not_permitted`；這不是「可能健康」的捷徑，而是明確表示目前證據不足、不能宣告 healthy。Storage 的 `limitations` 會列出未驗證的 volume coverage 與 SMART 深度限制。

已知異常放在 `findings`；資料不足放在 `unknowns`。兩者不互相替代。原始 `status_code` 仍保留，方便用真實 fixture 校準新韌體。

Volume 可用 `--volume-index` 重複指定，也可在 MCP `qts_storage`／`qts_health` 傳 `volume_indices`；預設仍為 index 1。沒有經實機核對的 index discovery API，因此即使查了多個 index，coverage 一樣是 `unverified`。系統 70°C、磁碟 55°C 是報告揭露的 generic default，不是經各機型校正的安全界線。

Volume 查詢目前固定使用 `func=extra_get&extra_vol_index=1`，回應仍標記 `source.coverage: unverified`。磁碟則合併 `manaRequest.cgi` 的 bay／溫度與 `qsmart.cgi?func=all_hd_data` 的型號、容量、序號遮蔽值與頂層 Health。TS-431K 實機的 `vol_status=0` 尚未有足夠證據映射成 healthy，因此整體仍為 `indeterminate`。

注意：`qsmart.cgi` 的頂層 `Health=OK/Normal` 不代表所有 SMART attribute、歷史 I/O 錯誤或 QTS 告警都正常。例如實機 HDD2 曾由 QTS UI 報告健康度不佳，但此次頂層欄位為 `Normal`；CLI 不會用它覆蓋或否定較具體的告警。

TS-431K 的 `/sbin/get_hd_smartinfo -d 1..4` 實測皆為空，而且系統未安裝 `smartctl`；因此 `smart-details` 回傳 `data_status: unavailable_on_firmware`，不會假造 attributes。`md9`／`md13` 的 `[128/3]` QNAP wide bitmap 也不套用一般 Linux md 的底線判讀，`degraded` 會是 `null`。

## 真實 dump 與 fixture 流程

```bash
# 在受信任管理電腦上連線 NAS，輸出已遮蔽資料
qts dump qts-dump-ts431k

# 離線確認 XML 可解析，並列出未知狀態
qts fixture validate qts-dump-ts431k --json
```

`dump` v2 會保存 `sysinfo.xml`、`storage.xml`、`smart.xml` 與版本化 manifest。提交 fixture 前仍應人工檢查內容；驗證通過只代表結構可解析，不代表 NAS 健康。已審查的實機資料位於 `tests/fixtures/ts431k-qts-5.2.8-build-20251216`，手寫 XML 只用於 edge cases。

## Incident / repair 工作流（目前為受限 v1）

`qts incident scan` 使用 QNAP File Station API 的 `get_tree`／`get_list` 做 bounded read-only inventory：最多掃描 100,000 個項目、深度 12；預設 10,000。僅掃描登入帳號可見的共享資料夾名稱，不讀內容、不掃程序／行為／系統日誌，也不代表完整 filesystem coverage。報告的 `coverage.truncated`、`coverage.depth_limited` 與 `coverage.truncation_reasons` 會明確標示項目數或深度上限造成的覆蓋缺口；`partial`／截斷掃描的無命中尤其不能解讀為乾淨。已知規則包含 `.deadbolt`、Qlocker 的 `!!!READ_ME.txt`，以及大量 `.7z` 的低信心群聚；`.7z` 群聚可能是正常備份，單獨不會升級成 `suspected`，需搭配勒索字條、DeadBolt 指標、QTS 告警或其他獨立異常證據。無命中永遠回 `indeterminate`，不回 `clean`；命中代表疑似而非確診。官方事件說明、公告與 API 規格列於下方參考資料。

應變分工：

1. **scan**：保存有限掃描、health、可用的 RAID/QPKG observation 與 coverage gaps。
2. **contain**：只輸出人工步驟，建議從 router/switch 限制外部與不必要用戶端流量，同時保留受控管理／取證路徑；不自動更改 NAS firewall 或 stop process。
3. **evidence**：建立全新本機目錄、保存 JSON report 和 SHA-256 manifest。`rescue --candidate-path` 只可匯出 report 已列出的 IOC 範例，使用串流與大小上限，另算 SHA-256；不執行檔案、不傳回 NAS。
4. **rescue**：全量資料復原仍需先遏止、可信任重建與修補，再由離線／不可變備份恢復至新位置、驗證後切換；本 CLI 不會在疑似受感染 NAS 上覆寫還原。若疑似正在進行 Qlocker 活動，請依 QNAP 對應事件指引處理；家族與韌體不同時應以對應官方公告為準。

### QNAP 官方事件與 API 參考

- [Qlocker 說明與處置指引](https://www.qnap.com/static/landing/2021/qlocker/response/en/)：Qlocker 事件回應資訊與官方建議。
- [DeadBolt 安全公告（QSA-22-02）](https://www.qnap.com/en-us/security-advisory/qsa-22-02)：DeadBolt 事件與受影響產品／處置資訊。
- [QTS File Station HTTP API v5（PDF）](https://download.qnap.com/dev/QNAP_QTS_File_Station_API_v5.pdf)：`incident scan` 使用之 File Station API 契約參考。

一般 `repair plan/apply` 的 code contract 已定義：計畫有 15 分鐘有效期與 hash `plan_id`；apply 要求逐字確認、裝置身分相同、前置條件已核對，每一步重新讀取 before state，操作後 readback 驗證，失敗即停止後續步驟。CLI 目前只輸出 `refused` plan，因為 QNAP 寫入 API/SSH 動作尚未通過實機測試；因此這不是可以改 NAS 的功能預告，而是安全框架先行。

## 內部架構

```text
CLI / JSON / MCP
       |
       +-- commands.py ------- 純讀診斷與 finding
       |       |
       |       +-- client.py -------- HTTPS + SID + QTS CGI
       |       +-- parsers.py ------- 韌體差異容錯解析
       |       +-- ssh_backend.py --- 固定 allowlist 命令，無任意 shell API
       |
       +-- config.py --------- 原子設定寫入，不保存密碼
       +-- redaction.py ------ dump 與支援資料遮蔽
```

Web 後端適合 QTS 通用資料；SSH 後端只用於 Web API 無法可靠提供、且命令已列入 allowlist 的深度診斷。未來 local backend 會在 NAS 本機執行相同 allowlist，而不是開放任意命令。

## 安全模型

- 遠端連線強制 HTTPS，只有 `localhost`／`127.0.0.1` 可使用 HTTP。
- 預設驗證 TLS；`--insecure` 不會寫成隱性預設值。
- 密碼不放 CLI argument、不保存於 JSON config、不寫入錯誤。
- SID 只存於 process memory，命令結束會嘗試 logout。
- SSH 使用 `BatchMode=yes`，只執行程式內固定 allowlist。
- SSH probe 直接組合 argv，不經 `/bin/sh -c`；SMART bay 僅接受 `1..64`，沒有任意 package 或命令參數。
- `dump` 預設遮蔽 hostname、序號、介面 IP、netmask、MAC 與 DNS。
- MCP 無通用 `api_call`、shell、刪除或修復工具。

詳見 [SECURITY.md](SECURITY.md)、[docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) 與 [docs/RESPONSE-WORKFLOWS.md](docs/RESPONSE-WORKFLOWS.md)。

## 測試

```bash
python -m unittest discover -s tests -v
python -m compileall -q qnap_nas_cli
```

CI 在 Ubuntu 22.04 上以 Python 3.8、3.12 與 3.13 執行離線測試與 wheel 建置。固定 runner 的理由是 Ubuntu 26 已無 Python 3.8 toolcache。Live smoke test 不會在公開 CI 使用真實 NAS credential。

## Roadmap

1. 已完成：以 TS-431K/QTS 5.2.8 真實 fixture 固化 system、disk、volume 與 SMART summary parsing。
2. 進行中：以 TS-431K 真實 SSH fixture 固化 SMART attributes、RAID `/proc/mdstat`、Container Station 與 Tailscale 狀態。
3. 完成唯讀面與依賴圖後，只挑 1～2 個低風險、可逆操作；每項強制 plan、dry-run、明確確認、post-verify 與 rescue steps。
4. 只有在確認第二管理帳號、SSH／本地復原路徑與失聯處置後，才評估更高風險操作。
5. RAID rebuild、SMART repair、磁碟寫入與大幅防火牆修改不列入早期版本。
6. Webhook 告警、排程健康報告與 Evidence Capsule。

## 授權與商標

本專案採 [MIT License](LICENSE)，研究來源與授權記錄於 [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md)。本專案不隸屬 QNAP Systems, Inc.；QNAP、QTS、QuTS hero 與其產品名稱為各自權利人的商標。
