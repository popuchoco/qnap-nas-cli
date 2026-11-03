import json
import os
import stat
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Optional
from urllib.parse import urlparse

from .errors import QtsError


def default_config_path() -> Path:
    override = os.environ.get("QTS_CONFIG")
    if override:
        return Path(override).expanduser()
    base = Path(os.environ.get("XDG_CONFIG_HOME", Path.home() / ".config"))
    return base / "qnap-nas-cli" / "config.json"


@dataclass
class Config:
    origin: str
    username: str
    insecure: bool = False
    ssh_host: Optional[str] = None
    ssh_user: Optional[str] = None
    timeout: int = 15

    def validate(self) -> "Config":
        parsed = urlparse(self.origin)
        if parsed.scheme not in ("https", "http") or not parsed.netloc:
            raise QtsError("origin 必須是完整的 http(s) URL，例如 https://192.0.2.10:443")
        if parsed.scheme != "https" and parsed.hostname not in ("127.0.0.1", "localhost"):
            raise QtsError("遠端 QTS 連線必須使用 HTTPS；只有 localhost 可使用 HTTP")
        if not self.username.strip():
            raise QtsError("username 不可為空")
        if not 1 <= self.timeout <= 300:
            raise QtsError("timeout 必須介於 1 到 300 秒")
        self.origin = self.origin.rstrip("/")
        return self


def load_config(path: Optional[Path] = None) -> Config:
    target = path or default_config_path()
    try:
        raw = json.loads(target.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise QtsError("尚未設定 NAS；請先執行 qts setup") from exc
    except (OSError, ValueError) as exc:
        raise QtsError("無法讀取設定檔 {}：{}".format(target, exc)) from exc
    allowed = {"origin", "username", "insecure", "ssh_host", "ssh_user", "timeout"}
    return Config(**{key: value for key, value in raw.items() if key in allowed}).validate()


def save_config(config: Config, path: Optional[Path] = None) -> Path:
    target = path or default_config_path()
    config.validate()
    target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    temporary = target.with_suffix(".tmp")
    temporary.write_text(json.dumps(asdict(config), ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    if os.name != "nt":
        os.chmod(temporary, stat.S_IRUSR | stat.S_IWUSR)
    os.replace(str(temporary), str(target))
    return target


def password_from_environment() -> Optional[str]:
    return os.environ.get("QTS_PASSWORD")
