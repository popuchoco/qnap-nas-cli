import argparse
import getpass
import json
import os
import sys
from pathlib import Path
from typing import Any, Dict, Optional

from . import __version__
from .client import QtsClient
from .commands import dump, health, network, storage, sysinfo, tailscale, validate_dump
from .config import Config, default_config_path, load_config, password_from_environment, save_config
from .errors import QtsError
from .mcp import serve


def parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser(prog="qts", description="QNAP QTS safety-first diagnostics CLI")
    root.add_argument("--version", action="version", version="%(prog)s {}".format(__version__))
    root.add_argument("--config", type=Path, help="設定檔路徑（也可使用 QTS_CONFIG）")
    root.add_argument("--json", action="store_true", help="輸出 JSON")
    root.add_argument("--insecure", action="store_true", help="停用 TLS 憑證驗證（僅限受信任區網暫時使用）")
    subs = root.add_subparsers(dest="command", required=True)

    setup = subs.add_parser("setup", help="寫入連線設定；不儲存密碼")
    setup.add_argument("--origin", required=True)
    setup.add_argument("--user", required=True)
    setup.add_argument("--ssh-host")
    setup.add_argument("--ssh-user")
    setup.add_argument("--timeout", type=int, default=15)

    subs.add_parser("doctor", help="檢查本機設定與連線前置條件")
    subs.add_parser("whoami", help="登入並顯示目前帳號與 NAS")
    subs.add_parser("status", help="系統型號、韌體、負載、溫度與 uptime")
    subs.add_parser("health", help="唯讀磁碟與儲存健康稽核")
    subs.add_parser("storage", aliases=["disks", "volumes"], help="磁碟與儲存空間")
    subs.add_parser("network", help="網路介面與 DNS")
    subs.add_parser("tailscale", help="透過設定的免密 SSH 讀取 Tailscale")
    dump_parser = subs.add_parser("dump", help="匯出已遮蔽敏感資料的相容性樣本")
    dump_parser.add_argument("directory", nargs="?", type=Path, default=Path("qts-dump"))
    fixture_parser = subs.add_parser("fixture", help="驗證 dump/fixture 是否能安全解析")
    fixture_subs = fixture_parser.add_subparsers(dest="fixture_command", required=True)
    fixture_validate = fixture_subs.add_parser("validate", help="離線驗證已遮蔽的 dump")
    fixture_validate.add_argument("directory", type=Path)
    fixture_validate.add_argument("--json", action="store_true", default=argparse.SUPPRESS, help=argparse.SUPPRESS)
    subs.add_parser("mcp", help="啟動唯讀 stdio MCP server")
    seen = set()
    for command_parser in subs.choices.values():
        if id(command_parser) in seen:
            continue
        seen.add(id(command_parser))
        command_parser.add_argument("--json", action="store_true", default=argparse.SUPPRESS, help=argparse.SUPPRESS)
        command_parser.add_argument("--insecure", action="store_true", default=argparse.SUPPRESS, help=argparse.SUPPRESS)
        command_parser.add_argument("--config", type=Path, default=argparse.SUPPRESS, help=argparse.SUPPRESS)
    return root


def _config(args: argparse.Namespace) -> Config:
    config = load_config(args.config)
    if args.insecure:
        config.insecure = True
    return config


def _password() -> str:
    password = password_from_environment()
    if password is not None:
        return password
    if not sys.stdin.isatty():
        value = sys.stdin.readline().rstrip("\r\n")
        if value:
            return value
    return getpass.getpass("QTS password: ")


def _print(value: Any, json_output: bool) -> None:
    if json_output:
        print(json.dumps(value, ensure_ascii=False, indent=2))
        return
    if isinstance(value, dict):
        for key, item in value.items():
            if isinstance(item, (dict, list)):
                print("{}:".format(key))
                rendered = json.dumps(item, ensure_ascii=False, indent=2)
                print("\n".join("  " + line for line in rendered.splitlines()))
            elif item is not None:
                print("{:<20} {}".format(key, item))
    else:
        print(value)


def _doctor(config: Config, config_path: Optional[Path] = None) -> Dict[str, Any]:
    import shutil
    from urllib.parse import urlparse
    parsed = urlparse(config.origin)
    local_http = parsed.scheme == "http" and parsed.hostname in ("127.0.0.1", "localhost")
    return {
        "config": str(config_path or default_config_path()),
        "origin": config.origin,
        "username": config.username,
        "tls_verification": not config.insecure,
        "password_available": password_from_environment() is not None,
        "ssh_configured": bool(config.ssh_host and config.ssh_user),
        "ssh_executable": shutil.which("ssh") is not None,
        "safe": (config.origin.startswith("https://") and not config.insecure) or local_http,
    }


def main(argv: Optional[list] = None) -> int:
    args = parser().parse_args(argv)
    try:
        if args.command == "setup":
            target = save_config(Config(args.origin, args.user, args.insecure, args.ssh_host, args.ssh_user, args.timeout), args.config)
            _print({"saved": str(target), "password_saved": False}, args.json)
            return 0
        if args.command == "fixture":
            result = validate_dump(args.directory)
            _print(result, args.json)
            return 0 if result["valid"] else 2
        config = _config(args)
        if args.command == "doctor":
            _print(_doctor(config, args.config), args.json)
            return 0
        if args.command == "mcp":
            return serve(config)
        if args.command == "tailscale":
            _print(tailscale(config), args.json)
            return 0
        operations = {
            "status": sysinfo,
            "health": health,
            "storage": storage,
            "disks": storage,
            "volumes": storage,
            "network": network,
        }
        with QtsClient(config) as client:
            client.login(_password())
            if args.command == "whoami":
                data = sysinfo(client)
                value = {"username": config.username, "hostname": data.get("hostname"), "model": data.get("model"), "origin": config.origin}
            elif args.command == "dump":
                value = dump(client, args.directory)
            else:
                value = operations[args.command](client)
        _print(value, args.json)
        return 0
    except (QtsError, OSError) as exc:
        print("error: {}".format(exc), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
