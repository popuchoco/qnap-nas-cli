# 排程唯讀安全報告

`qts report health --directory DIR` 會執行與 `qts health` 相同的唯讀觀察，並在指定的新目錄或空目錄中一次發布完整報告：時間戳記 JSON、短版 Markdown 摘要與 `manifest.sha256`。JSON 保留 health observation 欄位並加入 `emitted_at`；Markdown 僅列狀態、finding／unknown codes、可用的型號／韌體／build 與 emitted time。所有輸出會遞迴遮蔽敏感欄位與字串。Manifest 驗證 JSON 和 Markdown 的 SHA-256。

`qts report plex2shell --directory DIR` 使用相同的 atomic/redacted bundle writer，輸出 Plex patch posture 與 finding/unknown code 摘要。可傳入 `--exposure-during-vulnerable-version`、`--current-exposure` 及 `--ioc-*` operator-reported 欄位；`--check-known-process-iocs` 額外執行三個固定名稱的 `pidof` probe，預設不執行。這仍不是完整事件掃描，也不會清除或修改 NAS。三種 report 目標目錄都需每次使用新的路徑。

`qts report legacy-ransomware --directory DIR` 會取得 QTS system info 和固定 allowlist 的 QPKG metadata，再發布相同格式的本機 capsule。QTS 的 SSH 權限政策可能要求 administrators；目前不能假設可使用非 admin SSH 帳號，也未在 TS-431K 驗證這點。不要把客戶端固定命令 allowlist 誤當成 SSH key/account 的伺服器端限制。可在 NAS `authorized_keys` 以 `from=`、`restrict`（僅在韌體 SSH server 支援時）縮小來源與 forwarding；`command=` 會攔截本工具不同 probe，只有部署能精確驗證 `$SSH_ORIGINAL_COMMAND` 的安全 dispatcher 才適用，且尚未在實機測試。SSH 身分檔指定後會加上 `IdentitiesOnly=yes`。首次 SSH 探針若失敗，collection 立即停止，報告保留 unknown 與 `collection_errors`，而非重複等待後續 probe。

目標目錄若不存在會建立；已存在時必須是實際的空目錄。非空目錄、檔案與 symlink 會被拒絕。三個檔案先在同一個父目錄的私有暫存目錄完成，再將整個目錄原子發布；寫入失敗不會留下部分報告檔。`--directory` 應使用每次執行的新路徑，避免排程重用非空目錄。

```bash
qts report health --directory ./health-report-once --json
qts report plex2shell --directory ./plex-security-once --json
# 選擇性固定名稱檢查（需要已設定 SSH）：
qts report plex2shell --directory ./plex-security-ioc-once --check-known-process-iocs --json
# 可選的 operator-reported fields 也可加入排程命令：
qts report plex2shell --directory ./plex-security-reviewed-once --current-exposure yes --ioc-malware-remover-detection no --json
qts report legacy-ransomware --directory ./legacy-security-once --json
```

`report health` 沿用 health exit semantics：觀察完成時，即使狀態為 `unhealthy` 或 `indeterminate`，仍回傳 `0`；連線或報告寫入錯誤回傳 `2`。Plex／legacy 若 SSH collection 失敗，仍會先發布帶有 `collection_errors` 的 bundle 與 CLI receipt，再回傳 `2`，讓排程器不會把不完整收集當成成功。輸出檔案的時間戳記以 UTC 秒為單位。

## Cron（每日 06:00）

建立只供排程帳號讀取的 `/etc/qnap-nas-cli/health.env`，由秘密管理流程寫入，不要把密碼放入 crontab 或 wrapper。Cron wrapper 載入環境後執行 CLI；crontab 命令中的 `%` 必須跳脫：

```cron
0 6 * * * /bin/bash -c 'set -a; . /etc/qnap-nas-cli/health.env; set +a; d=$(/usr/bin/date -u +\%Y\%m\%dT\%H\%M\%SZ); exec /usr/local/bin/qts report health --directory "/var/lib/qnap-nas-cli/reports/$d"' >> /var/log/qnap-nas-cli/health-report.log 2>&1
```

若要排程 Plex posture，可用另一個專屬日誌與每次新建的目錄：

```cron
15 6 * * * /bin/bash -c 'set -a; . /etc/qnap-nas-cli/health.env; set +a; d=$(/usr/bin/date -u +\%Y\%m\%dT\%H\%M\%SZ); exec /usr/local/bin/qts report plex2shell --directory "/var/lib/qnap-nas-cli/plex-reports/$d"' >> /var/log/qnap-nas-cli/plex-report.log 2>&1
```

若要排程 Qlocker／DeadBolt／QSnatch posture，請確保同一個環境檔含 QTS 密碼和 SSH 設定：

```cron
30 6 * * * /bin/bash -c 'set -a; . /etc/qnap-nas-cli/health.env; set +a; d=$(/usr/bin/date -u +\%Y\%m\%dT\%H\%M\%SZ); exec /usr/local/bin/qts report legacy-ransomware --directory "/var/lib/qnap-nas-cli/legacy-reports/$d"' >> /var/log/qnap-nas-cli/legacy-report.log 2>&1
```

Health report 需要 `QTS_PASSWORD`，並由 `QTS_CONFIG` 或預設設定路徑提供 NAS 連線設定。Plex report 使用 SSH，需設定 SSH 主機／帳號與 key；Legacy ransomware report 同時使用 QTS web 與 SSH，也需兩組連線方式。不要稱 SSH key 為「唯讀 key」：其有效權限由 QTS SSH 帳號及 NAS SSH daemon 決定，工具內 allowlist 只是 client-side 限制。需以真機確認非管理員 SSH 是否可用；確認之前按管理員級存取保管 SSH 金鑰，並在支援時用 `from=`／`restrict` 收斂 authorized_keys 權限。`pidof` 執行路徑與 QPKG 版本格式仍待 TS-431K fixture 驗證。process 探針是可選固定名稱 allowlist，不會列出程序表。若使用 webhook，可在此環境注入 `QTS_WEBHOOK_URL` 和選用的 `QTS_WEBHOOK_SECRET`。檔案權限應限制為排程帳號可讀；Cron wrapper 請引用秘密檔，不要複製秘密內容。

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

Webhook 仍預設關閉；`QTS_WEBHOOK_URL` 才會啟用符合既有政策的通知。Health `indeterminate` 使用 `QTS_WEBHOOK_ON_INDETERMINATE=1`、`true` 或 `yes` 控制。Plex／legacy 各使用 `QTS_WEBHOOK_ON_PLEX_INDETERMINATE`／`QTS_WEBHOOK_ON_LEGACY_RANSOMWARE_INDETERMINATE`，互不影響；legacy 嚴重 finding 即使 overall assessment 是 `indeterminate` 也會以 alert 通知。`--webhook`／`--no-webhook` 可覆寫本次執行。Scheduled reports 先發布完整本機 bundle，再嘗試 webhook；通知失敗不會改寫 report 或改變觀察 exit code，送達結果只在 command receipt。

2026-11-06 已在 TS-431K/QTS 5.2.8 實機驗證 `report health`：新目錄會產生 JSON、codes-only Markdown 與 `manifest.sha256`，兩個 payload 的雜湊均吻合；同一非空目錄重跑會以 exit 2 拒絕覆寫。Webhook 對本機 HTTPS 測試 sink 傳送的內容只有 allowlisted 裝置欄位與 finding/unknown codes，刻意讓 sink 無法連線時則回報 `connection_error`，但不改變 health observation 的 exit code。新增的 Plex／legacy 排程功能尚未在 TS-431K 驗證，不可沿用上述 live claim。

## 範圍

本功能只產生本機報告，不啟動 daemon 或程序內排程器。沒有雲端 relay、內建 SMTP email 或 NAS mutation；報告結果也不代表完整 storage coverage 或證明設備健康。
