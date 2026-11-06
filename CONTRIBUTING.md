# 貢獻指南

歡迎提交問題回報與 pull request。請先閱讀 [SECURITY.md](SECURITY.md)；安全問題請使用其中的私下回報方式，不要開公開 issue。

## 相容性資料

若要提供 QTS 回應樣本，請在受信任的管理電腦執行 `qts dump <directory>`，再檢查產生的檔案與 manifest：

```bash
qts dump qts-dump
qts fixture validate qts-dump --json
```

`dump` 會遮蔽已知欄位，但提交前仍須逐檔人工檢查，並確認沒有秘密或可識別資料。**禁止上傳 NAS 密碼、SID/qtoken、TOTP、私鑰、未遮蔽回應、公開或內部個資、帳號資訊、hostname、序號、IP、MAC、DNS 資料或客戶資料。**不要把秘密放進 issue、pull request、fixture、log 或 commit。請只提交必要且已審查的最小樣本；若無法確認已清除個資，請勿提交。

## 開發與 pull request

- 使用 Python 3.8+；執行期間僅使用 Python 標準函式庫，不新增第三方 runtime dependency。
- 不新增通用 shell、任意 QTS API 或未經審查的寫入操作；unknown 與沒有掃描命中都必須保留現有語義。
- PR 說明變更原因、相容性影響，以及測試結果。涉及輸出欄位時同步更新 schema、契約文件、測試與 `CHANGELOG.md`。
- 使用小而聚焦的 diff，避免包含 dump、設定檔或本機秘密。

## 執行檢查

```bash
python -m unittest discover -s tests -v
python -m compileall -q qnap_nas_cli
python -m qnap_nas_cli --help
```

套件建置亦可用 `python -m pip wheel . --no-deps -w dist/`。發布流程及 PyPI trusted publishing 設定見 [docs/PUBLISHING.md](docs/PUBLISHING.md)。
