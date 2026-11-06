# 安裝

套件名稱是 `qnap-nas-cli`，命令列入口是 `qts`，需要 Python 3.8 以上。`0.2.0` 已發布到 PyPI；執行時只使用 Python 標準函式庫。

## 從 PyPI 安裝（建議）

使用 pipx 將 CLI 安裝在獨立環境：

```bash
pipx install qnap-nas-cli
qts --help
qts --version
```

也可先建立虛擬環境，再用 pip 安裝：

```bash
python3 -m venv .venv
. .venv/bin/activate
python -m pip install qnap-nas-cli
qts --help
qts --version
```

## 其他安裝來源

從 Git URL 安裝：

```bash
pipx install 'git+https://github.com/popuchoco/qnap-nas-cli.git'
```

或先 clone，再從本機 checkout 安裝；開發時可使用 editable 模式：

```bash
git clone https://github.com/popuchoco/qnap-nas-cli.git
cd qnap-nas-cli
python3 -m venv .venv
. .venv/bin/activate
python -m pip install -e .
qts --help
qts --version
```

在已有 checkout 的環境，也可用 `python -m pip install .` 一般安裝，或用 `pipx install .`。更多開發與建置說明見[貢獻指南](../CONTRIBUTING.md)。

## 隔離網路或離線 wheel

在可連網的電腦下載已發布的 wheel：

```bash
python -m pip download --only-binary=:all: --no-deps qnap-nas-cli -d dist/
```

也可從 checkout 建置 wheel：

```bash
python -m pip wheel . -w dist/
```

若已安裝 `build` 工具，也可執行 `python -m build --wheel --outdir dist/`。將產生的 `qnap_nas_cli-0.2.0-py3-none-any.whl` 複製到離線主機。在離線主機上，`DIR` 請換成 wheel 所在目錄：

```bash
python3 -m venv .venv
.venv/bin/python -m pip install --no-index --find-links=DIR qnap-nas-cli
.venv/bin/qts --help
.venv/bin/qts --version
```

若直接指定 wheel 路徑，也可執行 `.venv/bin/python -m pip install /path/to/qnap_nas_cli-0.2.0-py3-none-any.whl`。此套件沒有第三方 runtime dependencies。

## 憑證與設定

密碼及 2FA 驗證碼的注入方式、互動提示與安全注意事項見[憑證注入說明](SECRETS.md)。`qts setup` 只保存連線設定，不保存密碼。

## CLI 回傳碼

以下是 `qnap_nas_cli.cli.main()` 明確定義的回傳碼：

| 回傳碼 | 意義 |
| --- | --- |
| `0` | 成功；也包括有效的 `fixture validate`，以及未被拒絕的 `repair apply`。 |
| `2` | `QtsError`／`OSError`、無效的 `fixture validate`、一律拒絕的 `repair plan`，以及狀態為 `refused` 的 `repair apply`。 |

`main()` 只明確回傳 `0` 或 `2`。`argparse` 的用法錯誤也可能透過 `SystemExit` 以 `2` 結束程序。
