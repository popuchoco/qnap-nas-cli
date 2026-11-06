# Security Policy

請勿在 issue、fixture 或 log 中提交 NAS 密碼、SID、qtoken、私鑰、公開 IP、序號或未遮蔽的完整 QTS 回應。

## Supported versions

目前只支援最新的 `main` 與最新 release。`0.x` 期間的 QTS compatibility 仍可能變動。

## Reporting

請使用 GitHub Security Advisory 私下回報安全問題。不要先建立公開 issue。

## Operational safety

- 優先建立權限受限的 QTS 管理帳號，不使用內建 `admin` 作為日常 automation 帳號。
- 使用可信 HTTPS 憑證；`--insecure` 只供隔離測試。
- 密碼與 2FA 驗證碼只在執行期間注入；詳見[憑證注入說明](docs/SECRETS.md)。
- SSH 使用金鑰與 `BatchMode`，不要在腳本中保存 SSH 密碼。
- SSH probe 不經 shell，且只允許程式內固定 argv；不要新增通用 command/package 參數。
- 執行任何未來的修復命令前，確認已有可登入的第二管理帳號與本地復原路徑。
- RAID rebuild、SMART repair、磁碟寫入與大幅防火牆修改不屬於早期受控修復範圍。
