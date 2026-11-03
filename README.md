# qnap-nas-cli

[![CI](https://github.com/popuchoco/qnap-nas-cli/actions/workflows/ci.yml/badge.svg)](https://github.com/popuchoco/qnap-nas-cli/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

安全優先、零第三方 Python 相依的 QNAP QTS 診斷 CLI 與唯讀 MCP Server。目標是讓人與 AI agent 都能取得可稽核的 NAS 健康證據，而不是在缺乏實機驗證時直接修改 RAID、磁碟或網路服務。

目前是 `0.1.1`，主要相容目標為 QTS 5.x 與 TS-431K。QTS CGI 欄位會因機型、韌體及安裝套件而異；請使用 `qts dump` 提供已遮蔽的相容性樣本。

## 目前狀態

- 初始唯讀診斷版本已於 2026-11-03 發布到 `main`。
- 25 項離線測試、Python bytecode compilation、CLI smoke test 與 wheel build 均已通過。
- GitHub Actions 已在 Python 3.8、3.12、3.13 完成驗證：[成功的 CI run](https://github.com/popuchoco/qnap-nas-cli/actions/runs/41594356258)。
- CI 固定使用 Ubuntu 22.04，因為 GitHub 的 Ubuntu 26 runner 不再提供 Python 3.8；這是為了保留較舊 NAS／管理環境的相容性，不是測試降級。
- QTS response parser 目前使用離線 fixture 驗證；TS-431K 實機 dump 與 live smoke test 尚未完成，因此會明確保留 `unknown`，不把缺少欄位誤判為健康。

維護者：`popuchoco <p.choco@daum.net>`

## 功能

- `setup`：保存 HTTPS、帳號與選用的 SSH 主機；不保存密碼。
- `doctor`／`whoami`：檢查本機條件並驗證 QTS 登入。
- `status`：型號、韌體、CPU、記憶體、溫度與 uptime。
- `health`：唯讀彙整磁碟、Volume、已知異常 finding 與資料不足 unknown；`healthy`、`unhealthy`、`indeterminate` 不混為一談。
- `storage`／`disks`／`volumes`：列出 QTS CGI 可觀察到的儲存資料。
- `network`：介面、IP、速度與 DNS。
- `tailscale`：經過明確設定的免密 SSH 執行固定的 `tailscale status --json`。
- `dump`：匯出已遮蔽 hostname、序號、IP 與 DNS 的相容性樣本。
- `fixture validate`：不連 NAS，離線檢查 dump 能否解析及是否存在未知欄位／狀態碼。
- `mcp`：提供五個唯讀 stdio MCP tools。
- 全部資料命令支援 `--json`。

本版不提供 RAID 重建、SMART 修復、Container Station 停止、Tailscale 重啟或防火牆修改。這些操作必須先有 TS-431K 實機契約測試、dry-run 計畫、前後狀態驗證與回復程序。

## 安裝

需求為 Python 3.8 以上，不需要第三方套件。

```bash
git clone https://github.com/popuchoco/qnap-nas-cli.git
cd qnap-nas-cli
python -m pip install -e .
qts --help
```

也可直接從 checkout 執行：

```bash
python -m qnap_nas_cli --help
```

## 快速開始

QTS 應使用有效 HTTPS 憑證。`--insecure` 只適合受信任區網內的暫時測試。

```bash
qts setup --origin https://192.0.2.10 --user ops \
  --ssh-host 192.0.2.10 --ssh-user ops

# 互動式輸入密碼
qts status
qts health
qts storage --json
qts network

# 自動化或 MCP；不要把密碼寫進 shell history
QTS_PASSWORD='...' qts --json health
QTS_PASSWORD='...' qts mcp

# 產生已遮蔽的相容性資料
qts dump qts-dump
qts fixture validate qts-dump --json
```

若 stdin 不是終端，CLI 也能從 stdin 第一行讀取密碼。密碼不接受命令列參數，也不會寫入設定檔。

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

MCP 目前刻意只讀，不提供通用 shell 或任意 QTS API 呼叫。

## Health 語義

`health` 不把「沒有發現異常」直接等同「已證明健康」：

- `status: healthy`／`healthy: true`：必要狀態完整，而且觀察值沒有已知異常。
- `status: unhealthy`／`healthy: false`：存在已知異常，例如 degraded Volume、明確 SMART warning 或過熱。
- `status: indeterminate`／`healthy: null`：資料缺少、`vol_status=0`、未知狀態碼，或 parser 沒找到必要記錄。

已知異常放在 `findings`；資料不足放在 `unknowns`。兩者不互相替代。原始 `status_code` 仍保留，方便用真實 fixture 校準新韌體。

目前 Storage CGI 固定使用 `func=extra_get&extra_vol_index=1`。回應會標記 `source.coverage: unverified`；在真實 NAS dump 尚未與 QTS UI／其他索引對照前，即使觀察到的 Volume 都是 ready，整體 Health 仍為 `indeterminate`，不會宣稱所有 Storage 健康。

## 真實 dump 與 fixture 流程

```bash
# 在受信任管理電腦上連線 NAS，輸出已遮蔽資料
qts dump qts-dump-ts431k

# 離線確認 XML 可解析，並列出未知狀態
qts fixture validate qts-dump-ts431k --json
```

`dump` manifest 使用版本化格式並包含同一次 parser validation。提交 fixture 前仍應人工檢查內容；驗證通過只代表結構可解析，不代表 NAS 健康。Repository 不會用手寫 XML 冒充 TS-431K 實機 fixture。

## 架構參考與設計來源

本專案不是把 Synology API 名稱替換成 QNAP 名稱，而是重新實作 QTS 專用協定層。

### `synology-nas-cli`

[akari-sora/synology-nas-cli](https://github.com/akari-sora/synology-nas-cli) 提供以下產品與架構構想：

- Python 標準函式庫即可執行，讓工具能在 NAS 或管理電腦上運作。
- 同一核心同時服務人類 CLI、JSON 自動化與 stdio MCP。
- 稽核與修復分離；危險操作先產生計畫並要求明確確認。
- 設定、credential source、TLS、相容性 dump 與 agent 安全邊界是產品的一部分。

該專案使用 Synology DSM 7 Web API；本專案沒有複製其 DSM endpoint、修復命令或勒索軟體判斷。兩者皆採 MIT License，若日後直接移植程式碼，將在來源檔保留原作者 copyright 與授權聲明。

### QNAP 官方介面

- QTS Authentication API：`authLogin.cgi`、SID／qtoken 與 2-step verification 契約。
- QTS File Station HTTP API v5：檔案、分享與部分 Storage 資訊的公開契約。
- QTS Web UI CGI：`manaRequest.cgi` 與 `disk_manage.cgi` 提供型號、負載、介面與儲存觀察值，但欄位跨韌體並非完整穩定公開 API，因此解析器採容錯設計並保留 `unknown`。

### 現有 QNAP 工具研究

[rvben/qnap-cli](https://github.com/rvben/qnap-cli) 的公開實作與相容性 fixture 協助確認 QTS 5.1/5.2 常見 CGI 請求、登入 form、sysinfo 與 storage response 形狀。本專案沒有複製其 Rust 原始碼；它偏向完整檔案管理，本專案則聚焦健康診斷、事件證據、Tailscale／Container Station 維運與 AI agent 的安全操作模型。

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
- `dump` 預設遮蔽 hostname、序號、介面 IP 與 DNS。
- MCP 無通用 `api_call`、shell、刪除或修復工具。

詳見 [SECURITY.md](SECURITY.md) 與 [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md)。

## 測試

```bash
python -m unittest discover -s tests -v
python -m compileall -q qnap_nas_cli
```

CI 在 Ubuntu 22.04 上以 Python 3.8、3.12 與 3.13 執行離線測試與 wheel 建置。固定 runner 的理由是 Ubuntu 26 已無 Python 3.8 toolcache。Live smoke test 不會在公開 CI 使用真實 NAS credential。

## Roadmap

1. 以 TS-431K/QTS 5.x 的真實、已人工審查 `qts dump` fixture 固化 system、disk、volume parsing。
2. 新增原始 SMART 與 RAID `/proc/mdstat` 唯讀 SSH 報告。
3. Container Station、Tailscale 與 AdGuard 的狀態／依賴圖。
4. 具 plan、dry-run、確認、重測與 rescue steps 的受控修復命令。
5. Webhook 告警、排程健康報告與 Evidence Capsule。

## 授權與商標

本專案採 [MIT License](LICENSE)，研究來源與授權記錄於 [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md)。本專案不隸屬 QNAP Systems, Inc.；QNAP、QTS、QuTS hero 與其產品名稱為各自權利人的商標。
