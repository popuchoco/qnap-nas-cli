# PyPI 發布流程（維護者）

`qnap-nas-cli` 已完成套件建置準備，但尚未將 `0.2.0` 發布到 PyPI。Release workflow 會建置 wheel 與 source distribution，再於 GitHub Environment `pypi` 等待核准，最後透過 PyPI trusted publishing（OIDC）發布。

## 一次性維護者設定

1. 在 PyPI 為專案 `qnap-nas-cli` 設定 trusted publisher，指定此 GitHub repository、workflow 檔 `.github/workflows/release.yml` 與 Environment `pypi`。若專案尚未建立，可使用 PyPI pending publisher 流程。
2. 在 GitHub repository settings 建立名稱為 `pypi` 的 Environment，設定 required reviewers 及需要的部署分支／tag 限制。Environment 保護規則未通過前，publish job 不會開始。
3. 此 workflow 不使用 PyPI API token。**不要建立或提交 PyPI token、密碼、TOTP、SID 或其他憑證。**

## 發布檢查清單

1. 檢查 `CHANGELOG.md`、schemas、套件 metadata 與支援機型說明，確認 `pyproject.toml` 和 `qnap_nas_cli/__init__.py` 的版本一致。
2. 執行 CI 檢查：`python -m unittest discover -s tests -v`、`python -m compileall -q qnap_nas_cli` 與 `python -m qnap_nas_cli --help`。正式發布前，在本機建置並檢查 wheel 與 sdist。
3. 確認 release commit 位於預期分支且 CI 綠燈後，才建立並推送相符的版本 tag，例如 `v0.2.0`。完成 review 與相容性檢查前不要建立 tag。
4. Release workflow 會在 Python 3.8、3.12、3.13 重跑測試、建置 artifacts、核對 tag、project version 與 changelog，然後等待 `pypi` Environment 核准。核准前先檢查 workflow 執行結果與 artifacts。
5. 核准後，workflow 會透過 OIDC 發布到 PyPI，並以該版本的 changelog 摘要建立 GitHub Release，同時附上 sdist 與 wheel。完成後檢查兩處發布結果與安裝 metadata。

## Dry run 與首次發布

Dry run 請在本機執行 `python -m build --sdist --wheel --outdir dist/`，檢查輸出檔案，不建立 tag。首次正式發布不是 dry run；執行前請確認 PyPI trusted publisher 與 GitHub Environment 保護設定正確。一般 branch push 與 pull request 不會觸發發布。
