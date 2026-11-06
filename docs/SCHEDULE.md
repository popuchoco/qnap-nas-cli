# 排程健康報告

`qts report health --directory DIR` 會執行與 `qts health` 相同的唯讀觀察，並在指定的新目錄或空目錄中一次發布完整報告：時間戳記 JSON、短版 Markdown 摘要與 `manifest.sha256`。JSON 保留 health observation 欄位並加入 `emitted_at`；Markdown 僅列狀態、finding／unknown codes、可用的型號／韌體／build 與 emitted time。所有輸出會遞迴遮蔽敏感欄位與字串。Manifest 驗證 JSON 和 Markdown 的 SHA-256。

目標目錄若不存在會建立；已存在時必須是實際的空目錄。非空目錄、檔案與 symlink 會被拒絕。三個檔案先在同一個父目錄的私有暫存目錄完成，再將整個目錄原子發布；寫入失敗不會留下部分報告檔。`--directory` 應使用每次執行的新路徑，避免排程重用非空目錄。

```bash
qts report health --directory ./health-report-once --json
```

健康狀態沿用 `qts health` 的 exit code：觀察成功時，即使狀態為 `unhealthy` 或 `indeterminate`，仍回傳 `0`；連線或報告寫入錯誤回傳 `2`。輸出檔案的時間戳記以 UTC 秒為單位。

## Cron（每日 06:00）

建立只供排程帳號讀取的 `/etc/qnap-nas-cli/health.env`，由秘密管理流程寫入，不要把密碼放入 crontab 或 wrapper。Cron wrapper 載入環境後執行 CLI；crontab 命令中的 `%` 必須跳脫：

```cron
0 6 * * * /bin/bash -c 'set -a; . /etc/qnap-nas-cli/health.env; set +a; d=$(/usr/bin/date -u +\%Y\%m\%dT\%H\%M\%SZ); exec /usr/local/bin/qts report health --directory "/var/lib/qnap-nas-cli/reports/$d"' >> /var/log/qnap-nas-cli/health-report.log 2>&1
```

`health.env` 至少需提供 `QTS_PASSWORD`，並由 `QTS_CONFIG` 或預設設定路徑提供 NAS 連線設定。若使用 webhook，可在此環境注入 `QTS_WEBHOOK_URL` 和選用的 `QTS_WEBHOOK_SECRET`。檔案權限應限制為排程帳號可讀；Cron wrapper 請引用秘密檔，不要複製秘密內容。

## systemd service 與 timer

以下 service 以 oneshot 執行，每次使用 UTC 時間建立新目錄。將 `User`、binary 路徑、環境檔和報告目錄改成主機上的實際設定：

```ini
# /etc/systemd/system/qnap-health-report.service
[Unit]
Description=QNAP read-only health report

[Service]
Type=oneshot
User=qnap-reports
EnvironmentFile=/etc/qnap-nas-cli/health.env
ExecStart=/bin/sh -c 'd=$$(/usr/bin/date -u +%%Y%%m%%dT%%H%%M%%SZ); exec /usr/local/bin/qts report health --directory=/var/lib/qnap-nas-cli/reports/$$d'
```

```ini
# /etc/systemd/system/qnap-health-report.timer
[Unit]
Description=Run the QNAP health report daily

[Timer]
OnCalendar=daily
Persistent=true

[Install]
WantedBy=timers.target
```

將 `/etc/qnap-nas-cli/health.env` 設為只有 `qnap-reports` 和管理者可讀。`EnvironmentFile=` 只負責注入環境，不能放入 `export` 或 shell 命令。憑證與 webhook 環境變數的說明見[憑證注入指南](SECRETS.md)。

Webhook 仍預設關閉；`QTS_WEBHOOK_URL` 才會啟用符合既有政策的通知。Health `indeterminate` 預設不通知，只有設定 `QTS_WEBHOOK_ON_INDETERMINATE=1`、`true` 或 `yes` 才啟用。`--webhook`／`--no-webhook` 可覆寫本次執行。

2026-11-06 已在 TS-431K/QTS 5.2.8 實機驗證：新目錄會產生 JSON、codes-only Markdown 與 `manifest.sha256`，兩個 payload 的雜湊均吻合；同一非空目錄重跑會以 exit 2 拒絕覆寫。Webhook 對本機 HTTPS 測試 sink 傳送的內容只有 allowlisted 裝置欄位與 finding/unknown codes，刻意讓 sink 無法連線時則回報 `connection_error`，但不改變 health observation 的 exit code。

## 範圍

本功能只產生本機報告，不啟動 daemon 或程序內排程器。沒有雲端 relay、內建 SMTP email 或 NAS mutation；報告結果也不代表完整 storage coverage 或證明設備健康。
