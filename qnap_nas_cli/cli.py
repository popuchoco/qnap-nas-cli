import argparse
import getpass
import json
import os
import sys
from pathlib import Path
from typing import Any, Dict, Optional

from . import __version__
from .client import QtsClient
from .commands import disks_ssh, dump, health, incident_report, network, raid, services, smart_details, storage, sysinfo, tailscale, validate_dump
from .config import Config, default_config_path, load_config, password_from_environment, save_config
from .errors import QtsError, TwoFactorRequired
from .mcp import serve
from .incident import DEFAULT_MAX_ITEMS, MAX_MAX_ITEMS, response_plan, write_evidence_bundle
from .remediation import apply_plan, unavailable_plan
from .webhook import maybe_notify_health, maybe_notify_incident, webhook_enabled


def parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser(prog="qts", description="QNAP QTS safety-first diagnostics CLI")
    root.add_argument("--version", action="version", version="%(prog)s {}".format(__version__))
    root.add_argument("--config", type=Path, help="設定檔路徑（也可使用 QTS_CONFIG）")
    root.add_argument("--json", action="store_true", help="輸出 JSON")
    root.add_argument("--insecure", action="store_true", help="停用 TLS 憑證驗證（僅限受信任區網暫時使用）")
    webhook_flags = root.add_mutually_exclusive_group()
    webhook_flags.add_argument("--webhook", dest="webhook", action="store_true", help="強制啟用符合條件的 webhook 通知")
    webhook_flags.add_argument("--no-webhook", dest="webhook", action="store_false", help="停用 webhook 通知")
    root.set_defaults(webhook=None)
    subs = root.add_subparsers(dest="command", required=True)

    setup = subs.add_parser("setup", help="寫入連線設定；不儲存密碼")
    setup.add_argument("--origin", required=True)
    setup.add_argument("--user", required=True)
    setup.add_argument("--ssh-host")
    setup.add_argument("--ssh-user")
    setup.add_argument("--ssh-identity-file")
    setup.add_argument("--timeout", type=int, default=15)

    subs.add_parser("doctor", help="檢查本機設定與連線前置條件")
    subs.add_parser("whoami", help="登入並顯示目前帳號與 NAS")
    subs.add_parser("status", help="系統型號、韌體、負載、溫度與 uptime")
    health_parser = subs.add_parser("health", help="唯讀磁碟與儲存健康稽核")
    health_parser.add_argument("--volume-index", type=int, action="append", help="額外查詢指定 volume index，可重複指定；預設 1")
    storage_parser = subs.add_parser("storage", aliases=["disks", "volumes"], help="磁碟與儲存空間")
    storage_parser.add_argument("--volume-index", type=int, action="append", help="額外查詢指定 volume index，可重複指定；預設 1")
    subs.add_parser("network", help="網路介面與 DNS")
    subs.add_parser("tailscale", help="透過設定的免密 SSH 讀取 Tailscale")
    subs.add_parser("raid", help="透過免密 SSH 唯讀解析 /proc/mdstat")
    smart_parser = subs.add_parser("smart-details", help="透過免密 SSH 讀取指定 bay 的 SMART attributes")
    smart_parser.add_argument("disk", type=int)
    subs.add_parser("disk-topology", help="透過唯讀 SSH 讀取實體磁碟 bay、角色與型號")
    subs.add_parser("services", help="唯讀檢查 Container Station 與 Tailscale QPKG 狀態")
    dump_parser = subs.add_parser("dump", help="匯出已遮蔽敏感資料的相容性樣本")
    dump_parser.add_argument("directory", nargs="?", type=Path, default=Path("qts-dump"))
    dump_parser.add_argument("--filestation", action="store_true", help="額外擷取已遮蔽的 File Station share root 與各 share 首頁")
    fixture_parser = subs.add_parser("fixture", help="驗證 dump/fixture 是否能安全解析")
    fixture_subs = fixture_parser.add_subparsers(dest="fixture_command", required=True)
    fixture_validate = fixture_subs.add_parser("validate", help="離線驗證已遮蔽的 dump")
    fixture_validate.add_argument("directory", type=Path)
    fixture_validate.add_argument("--json", action="store_true", default=argparse.SUPPRESS, help=argparse.SUPPRESS)
    subs.add_parser("mcp", help="啟動唯讀 stdio MCP server")
    incident_parser = subs.add_parser("incident", help="勒索事件唯讀盤點、人工 containment/evidence/rescue 工作流")
    incident_subs = incident_parser.add_subparsers(dest="incident_command", required=True)
    incident_scan = incident_subs.add_parser("scan", help="掃描有限、已知勒索指標並彙整健康/RAID evidence")
    incident_scan.add_argument("--max-items", type=int, default=DEFAULT_MAX_ITEMS, help="最多掃描的檔案/資料夾項目數，1..{}".format(MAX_MAX_ITEMS))
    incident_scan.add_argument("--evidence-dir", type=Path, help="可選：建立新的本機 evidence bundle 目錄")
    incident_contain = incident_subs.add_parser("contain", help="從 incident report 產生人工 containment 清單；不修改 NAS")
    incident_contain.add_argument("report", type=Path)
    incident_evidence = incident_subs.add_parser("evidence", help="將既有 incident report 封存並建立 SHA-256 manifest")
    incident_evidence.add_argument("report", type=Path)
    incident_evidence.add_argument("directory", type=Path)
    incident_rescue = incident_subs.add_parser("rescue", help="從 incident report 產生離線備份復原計畫；不覆寫 NAS")
    incident_rescue.add_argument("report", type=Path)
    incident_rescue.add_argument("--candidate-path", help="僅可指定本次 report 已列出的 indicator 範例，匯出一份唯讀本機樣本")
    incident_rescue.add_argument("--directory", type=Path, help="建立新的本機隔離 evidence 目錄；搭配 --candidate-path 使用")
    incident_rescue.add_argument("--max-bytes", type=int, default=100 * 1024 * 1024)
    repair = subs.add_parser("repair", help="一般修復的 plan/apply 閘門；尚無已驗證的 NAS 寫入 adapter")
    repair_subs = repair.add_subparsers(dest="repair_command", required=True)
    repair_plan = repair_subs.add_parser("plan", help="讀取設備身分並輸出明確拒絕執行的 dry-run plan")
    repair_plan.add_argument("--action", required=True, choices=["service-start", "service-stop", "notification-change", "firmware-update", "raid-rebuild", "smart-repair"])
    repair_plan.add_argument("--output", type=Path, default=Path("qts-repair-plan.json"))
    repair_apply = repair_subs.add_parser("apply", help="驗證 plan 與確認碼；未註冊的 mutation adapter 一律拒絕")
    repair_apply.add_argument("plan_file", type=Path)
    repair_apply.add_argument("--confirm", required=True, help="逐字輸入 plan_id；拒絕未驗證操作")
    nested_parsers = (incident_scan, incident_contain, incident_evidence, incident_rescue, repair_plan, repair_apply)
    for command_parser in nested_parsers:
        command_parser.add_argument("--json", action="store_true", default=argparse.SUPPRESS, help=argparse.SUPPRESS)
        command_parser.add_argument("--insecure", action="store_true", default=argparse.SUPPRESS, help=argparse.SUPPRESS)
        command_parser.add_argument("--config", type=Path, default=argparse.SUPPRESS, help=argparse.SUPPRESS)
        command_webhook_flags = command_parser.add_mutually_exclusive_group()
        command_webhook_flags.add_argument("--webhook", dest="webhook", action="store_true", help="強制啟用符合條件的 webhook 通知")
        command_webhook_flags.add_argument("--no-webhook", dest="webhook", action="store_false", help="停用 webhook 通知")
        command_webhook_flags.set_defaults(webhook=argparse.SUPPRESS)
    seen = set()
    for command_parser in subs.choices.values():
        if id(command_parser) in seen:
            continue
        seen.add(id(command_parser))
        command_parser.add_argument("--json", action="store_true", default=argparse.SUPPRESS, help=argparse.SUPPRESS)
        command_parser.add_argument("--insecure", action="store_true", default=argparse.SUPPRESS, help=argparse.SUPPRESS)
        command_parser.add_argument("--config", type=Path, default=argparse.SUPPRESS, help=argparse.SUPPRESS)
        command_webhook_flags = command_parser.add_mutually_exclusive_group()
        command_webhook_flags.add_argument("--webhook", dest="webhook", action="store_true", help="強制啟用符合條件的 webhook 通知")
        command_webhook_flags.add_argument("--no-webhook", dest="webhook", action="store_false", help="停用 webhook 通知")
        command_webhook_flags.set_defaults(webhook=argparse.SUPPRESS)
    return root


def _add_webhook_result(value: Dict[str, Any], args: argparse.Namespace, delivery: Any) -> None:
    if delivery is not None:
        value["webhook"] = delivery
        if delivery.get("status") in ("error", "rejected"):
            detail = delivery.get("error") or delivery.get("status")
            status = delivery.get("http_status")
            suffix = " (HTTP {})".format(status) if status is not None else ""
            print("webhook warning: {}{}".format(detail, suffix), file=sys.stderr)
    elif args.webhook is not None:
        value["webhook"] = {"status": "disabled", "http_status": None, "error": None}


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


def _security_code() -> Optional[str]:
    value = os.environ.get("QTS_SECURITY_CODE")
    if value is None:
        return None
    value = value.replace(" ", "").strip()
    return value or None


def _prompt_security_code() -> str:
    if not sys.stdin.isatty():
        raise TwoFactorRequired("QTS 帳號需要 2FA；非互動模式請設定當下的 QTS_SECURITY_CODE")
    value = getpass.getpass("QTS security code: ").replace(" ", "").strip()
    if not value:
        raise TwoFactorRequired("QTS 2FA 驗證碼不可為空")
    return value


def _login(client: QtsClient) -> None:
    password = _password()
    try:
        client.login(password, _security_code())
    except TwoFactorRequired:
        client.login(password, _prompt_security_code())


def _read_json(path: Path) -> Dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise QtsError("無法讀取 JSON 檔案：{}".format(exc)) from exc
    if not isinstance(value, dict):
        raise QtsError("JSON 根節點必須是 object")
    return value


def _save_new_json(path: Path, value: Dict[str, Any]) -> None:
    try:
        with path.open("x", encoding="utf-8") as stream:
            json.dump(value, stream, ensure_ascii=False, indent=2)
            stream.write("\n")
    except FileExistsError as exc:
        raise QtsError("輸出檔已存在，為避免覆寫 evidence/plan 已拒絕：{}".format(path)) from exc


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
        "password_available": bool(password_from_environment()),
        "ssh_configured": bool(config.ssh_host and config.ssh_user),
        "ssh_executable": shutil.which("ssh") is not None,
        "safe": (config.origin.startswith("https://") and not config.insecure) or local_http,
    }


def main(argv: Optional[list] = None) -> int:
    args = parser().parse_args(argv)
    try:
        if args.command == "setup":
            target = save_config(Config(args.origin, args.user, args.insecure, args.ssh_host, args.ssh_user, args.timeout, args.ssh_identity_file), args.config)
            _print({"saved": str(target), "password_saved": False}, args.json)
            return 0
        if args.command == "fixture":
            result = validate_dump(args.directory)
            _print(result, args.json)
            return 0 if result["valid"] else 2
        offline_incident = args.command == "incident" and args.incident_command in ("contain", "evidence", "rescue")
        if offline_incident and not (args.incident_command == "rescue" and args.candidate_path):
            report = _read_json(args.report)
            if args.incident_command == "evidence":
                value = write_evidence_bundle(args.directory, report)
            else:
                scan = report.get("ransomware_scan")
                if not isinstance(scan, dict):
                    raise QtsError("report 缺少 ransomware_scan")
                if args.incident_command == "contain":
                    value = response_plan(scan)
                else:
                    value = {
                        "status": "manual_rescue_plan_only",
                        "actions_applied": [],
                        "steps": [
                            "在隔離的復原環境使用已驗證的離線／不可變備份；不要把備份直接覆寫到疑似受感染的 NAS。",
                            "先完成遏止、可信任重建與漏洞修補；再抽樣驗證檔案雜湊、權限、時間戳及應用可讀性。",
                            "分批恢復至新位置並保留原始加密資料與證據；由資料擁有者簽核後才切換服務。",
                        ],
                        "why": "本工具不會對原 NAS 寫檔、解密、刪除或覆寫；恢復來源與完整性需由管理者確認。",
                    }
            _print(value, args.json)
            return 0
        if args.command == "repair" and args.repair_command == "apply":
            plan = _read_json(args.plan_file)
            result = apply_plan(plan, args.confirm, handlers={})
            _print(result, args.json)
            return 2 if result["status"] == "refused" else 0
        config = _config(args)
        if args.command == "doctor":
            _print(_doctor(config, args.config), args.json)
            return 0
        if args.command == "mcp":
            return serve(config)
        if args.command == "incident":
            if args.incident_command == "rescue":
                report = _read_json(args.report)
                scan = report.get("ransomware_scan")
                if not isinstance(scan, dict):
                    raise QtsError("report 缺少 ransomware_scan")
                if not args.candidate_path:
                    raise QtsError("請提供 --candidate-path，或只產生離線 rescue plan")
                candidates = [example for indicator in scan.get("indicators", []) for example in indicator.get("examples", [])]
                if args.candidate_path not in candidates:
                    raise QtsError("只能匯出本 report 列出的 indicator 範例路徑")
                if not args.directory:
                    raise QtsError("匯出本機樣本時必須指定新的 --directory")
                if not 1 <= args.max_bytes <= 1024 * 1024 * 1024:
                    raise QtsError("max-bytes 必須介於 1 byte 與 1 GiB")
                source_path, _, filename = args.candidate_path.rpartition("/")
                if not source_path or not filename:
                    raise QtsError("candidate-path 格式無效")
                report_manifest = write_evidence_bundle(args.directory, report)
                with QtsClient(config) as client:
                    _login(client)
                    sample = client.download_file(source_path, filename, args.directory / filename, args.max_bytes)
                value = {
                    "status": "sample_exported_not_restored",
                    "actions_applied": [],
                    "source": args.candidate_path,
                    "sample": sample,
                    "report_manifest": report_manifest,
                    "note": "已唯讀匯出到新本機目錄；這不是 NAS 復原，也不會執行或解密樣本。",
                }
                _save_new_json(args.directory / "rescue-manifest.json", value)
                _print(value, args.json)
                return 0
            if not 1 <= args.max_items <= MAX_MAX_ITEMS:
                raise QtsError("max-items 必須介於 1 到 {}".format(MAX_MAX_ITEMS))
            with QtsClient(config) as client:
                _login(client)
                value = incident_report(client, config, args.max_items)
            if args.evidence_dir:
                value["evidence_bundle"] = write_evidence_bundle(args.evidence_dir, value)
            delivery = maybe_notify_incident(value, force=args.webhook)
            if delivery is not None or args.webhook is not None or webhook_enabled():
                _add_webhook_result(value, args, delivery)
            _print(value, args.json)
            return 0
        if args.command == "repair":
            with QtsClient(config) as client:
                _login(client)
                identity = sysinfo(client)
            device = {"origin": config.origin, "model": identity.get("model"), "firmware": identity.get("firmware"), "build": identity.get("build")}
            plan = unavailable_plan(device, args.action)
            _save_new_json(args.output, plan)
            _print({"plan": str(args.output), "plan_id": plan["plan_id"], "status": plan["status"], "refusal_reason": plan["refusal_reason"]}, args.json)
            return 2
        if args.command in ("tailscale", "raid", "disk-topology", "smart-details", "services"):
            ssh_operations = {
                "tailscale": lambda: tailscale(config),
                "raid": lambda: raid(config),
                "disk-topology": lambda: disks_ssh(config),
                "smart-details": lambda: smart_details(config, args.disk),
                "services": lambda: services(config),
            }
            _print(ssh_operations[args.command](), args.json)
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
            _login(client)
            if args.command == "whoami":
                data = sysinfo(client)
                value = {"username": config.username, "hostname": data.get("hostname"), "model": data.get("model"), "origin": config.origin}
            elif args.command == "dump":
                value = dump(client, args.directory, filestation=args.filestation)
            else:
                if args.command in ("storage", "disks", "volumes", "health"):
                    indices = getattr(args, "volume_index", None)
                    value = health(client, indices) if args.command == "health" else storage(client, indices)
                else:
                    value = operations[args.command](client)
        if args.command == "health":
            delivery = maybe_notify_health(value, force=args.webhook)
            if delivery is not None or args.webhook is not None or webhook_enabled():
                _add_webhook_result(value, args, delivery)
        _print(value, args.json)
        return 0
    except (QtsError, OSError) as exc:
        print("error: {}".format(exc), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
