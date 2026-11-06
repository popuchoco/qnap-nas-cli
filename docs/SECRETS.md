# 憑證注入

密碼和 QTS 2FA 驗證碼只在執行期間提供，不是 CLI 參數，也不會寫入設定檔。`qts setup` 輸出 `password_saved: false`。設定檔只保存 `origin`、`username`、`insecure`、`ssh_host`、`ssh_user`、`timeout` 和 `ssh_identity_file`。

## 環境變數

| 變數 | 用途 |
| --- | --- |
| `QTS_PASSWORD` | CLI 與 MCP 使用的 QTS 密碼。 |
| `QTS_SECURITY_CODE` | QTS 要求 2FA 時供 CLI 與 MCP 登入使用；CLI 會移除空白。 |
| `QTS_WEBHOOK_URL` | 選用 webhook endpoint；整個 URL 視為秘密，僅支援 HTTPS，且不寫入設定檔。 |
| `QTS_WEBHOOK_SECRET` | 選用 webhook 簽章秘密；以 HMAC-SHA256 放在 HTTP header，不放入 payload。 |
| `QTS_WEBHOOK_TIMEOUT_SEC` | 選用 webhook timeout 秒數；預設 5，限制在 1 到 10 秒。 |
| `QTS_WEBHOOK_ON_INDETERMINATE` | 設為 `1`、`true` 或 `yes` 時，允許 health indeterminate 結果觸發通知。 |
| `QTS_CONFIG` | 設定 JSON 檔案的路徑覆寫，不是秘密或憑證。 |
| `XDG_CONFIG_HOME` | 標準設定目錄；未設定時使用 `~/.config`。 |

預設設定檔位置為 `$XDG_CONFIG_HOME/qnap-nas-cli/config.json`；若未設定 `XDG_CONFIG_HOME`，則為 `~/.config/qnap-nas-cli/config.json`。`QTS_CONFIG` 可覆寫此路徑。這些路徑設定不會使密碼或驗證碼成為設定檔內容。

## 自動化 CLI 與 MCP

Webhook 的 URL、簽章秘密與相關 policy 是 operator-local 環境秘密，不屬於 `config.json`。URL 可能含有 endpoint token，因此不要貼入 issue、shell history 或 log；由 secret manager／service manager 注入程序環境。Webhook 僅使用 HTTPS、驗證 TLS 憑證，並不跟隨 redirect 或重試。Payload 是有限的 allowlist 摘要，但仍應依內部事件資料政策選擇接收端。

以下 `...` 與 `…` 是示例佔位值，請勿替換後把真實秘密直接貼入會保存命令歷史的 shell：

```bash
QTS_PASSWORD='...' qts --json health
QTS_PASSWORD='...' QTS_SECURITY_CODE='…' qts --json health
QTS_PASSWORD='...' qts mcp
QTS_PASSWORD='...' QTS_SECURITY_CODE='…' qts mcp
```

由秘密管理工具或服務管理器在啟動程序時注入環境變數。不要將密碼或 TOTP 寫入 shell 腳本、shell history、設定檔、log 或 fixture。若 QTS 帳號啟用 2FA，非互動 CLI 與 MCP 在需要 2FA 時必須預先提供 `QTS_SECURITY_CODE`；這些模式不會提示輸入。MCP 執行需要 `QTS_PASSWORD`。CLI 讀取 `QTS_SECURITY_CODE` 時會去除空白；MCP 則直接使用環境變數原值，不做空白處理。

未設定 `QTS_PASSWORD` 時，非 TTY CLI 可從 stdin 第一行讀取密碼；互動終端則透過 `getpass` 提示密碼。互動終端只會在 QTS 回應需要 2FA 後，才透過 `getpass` 提示驗證碼。

## 不支援的憑證方式

- 沒有 CLI 密碼參數；不要把密碼放進命令列 arguments。
- 密碼不保存於設定檔；`qts setup` 不會保存密碼。
- 沒有可持續使用的 2FA bypass token；驗證碼只供當次程序使用。
- 密碼、2FA 驗證碼與 SID 不應寫入設定檔、log 或 fixture。

更多安全規則見 [SECURITY.md](../SECURITY.md)；2FA 的設計決策見 [ADR-009](DEVELOPMENT_DECISIONS.md#adr-009--qts-2fa-remains-ephemeral)。

Cron 與 systemd timer 的環境注入範例，以及 `qts report health` 的目錄和 exit code 語義，見[排程健康報告](SCHEDULE.md)。
