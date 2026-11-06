# PyPI 發布流程（維護者）

`qnap-nas-cli` 的首次 `0.2.0` 發布已完成，套件目前可從 PyPI 安裝。本文件說明後續版本的發布流程。

## 一次性維護者設定

1. 確認 PyPI trusted publisher 綁定此 GitHub repository、workflow 檔 `.github/workflows/release.yml` 與 GitHub Environment `pypi`。
2. 確認 repository 已建立 `pypi` Environment，並設定 required reviewers 及部署分支／tag 限制。保護規則未通過前，publish job 不會開始。
3. 此 workflow 不使用 PyPI API token。**不要建立或提交 PyPI token、密碼、TOTP、SID 或其他憑證。**

## 後續版本發布檢查清單

1. 在 `pyproject.toml` 和 `qnap_nas_cli/__init__.py` 更新相同的新版本號；在 `CHANGELOG.md` 更新 `Unreleased` 與該版本的發布紀錄。檢查 schemas、支援機型說明與套件 metadata。
2. 執行 CI 檢查：`python -m unittest discover -s tests -v`、`python -m compileall -q qnap_nas_cli` 與 `python -m qnap_nas_cli --help`。正式發布前，在本機建置並檢查 wheel 與 sdist。
3. 完成 review、確認 release commit 位於預期分支且 CI 綠燈後，建立並推送相符的版本 tag，例如 `vX.Y.Z`。發布 workflow 由版本 tag 觸發。
4. Release workflow 會在 Python 3.8、3.12、3.13 重跑測試、建置 artifacts，並核對 tag、project version 與 changelog，之後等待 `pypi` Environment 核准。核准前先檢查 workflow 執行結果與 artifacts。
5. 核准後，workflow 會透過 OIDC 發布到 PyPI，並以該版本的 changelog 摘要建立 GitHub Release，同時附上 sdist 與 wheel。完成後檢查兩處發布結果與安裝 metadata。

## Dry run

Dry run 請在本機執行 `python -m build --sdist --wheel --outdir dist/`，檢查輸出檔案，不建立 tag。一般 branch push 與 pull request 不會觸發發布。
