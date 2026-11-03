import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict

from .client import QtsClient
from .config import Config
from .parsers import parse_network, parse_storage, parse_system
from .redaction import redact_xml
from .ssh_backend import tailscale_status


SYSINFO_PATH = "/cgi-bin/management/manaRequest.cgi"
DISK_PATH = "/cgi-bin/disk/disk_manage.cgi"


def sysinfo(client: QtsClient) -> Dict[str, Any]:
    return parse_system(client.get_xml(SYSINFO_PATH, {"subfunc": "sysinfo"}))


def network(client: QtsClient) -> Dict[str, Any]:
    return parse_network(client.get_xml(SYSINFO_PATH, {"subfunc": "sysinfo"}))


def storage(client: QtsClient) -> Dict[str, Any]:
    return parse_storage(client.get_xml(DISK_PATH, {"func": "extra_get", "extra_vol_index": "1"}))


def health(client: QtsClient) -> Dict[str, Any]:
    system = sysinfo(client)
    result = storage(client)
    findings = []
    temp = system.get("temperature_c")
    if isinstance(temp, (int, float)) and temp >= 70:
        findings.append({"severity": "warning", "code": "system_temperature", "message": "系統溫度偏高：{} °C".format(temp)})
    for disk in result["disks"]:
        status = str(disk.get("smart") or "").lower()
        if status and status not in ("0", "good", "ready", "normal", "ok"):
            findings.append({"severity": "warning", "code": "disk_health", "disk": disk.get("disk"), "message": "磁碟健康狀態需要確認：{}".format(disk.get("smart"))})
        disk_temp = disk.get("temperature_c")
        if isinstance(disk_temp, (int, float)) and disk_temp >= 55:
            findings.append({"severity": "warning", "code": "disk_temperature", "disk": disk.get("disk"), "message": "磁碟溫度偏高：{} °C".format(disk_temp)})
    for volume in result["volumes"]:
        if volume.get("status") not in ("ready", "unknown"):
            findings.append({"severity": "critical", "code": "volume_status", "volume": volume.get("name"), "message": "儲存空間狀態：{}".format(volume.get("status"))})
    return {
        "healthy": not findings,
        "checked_at": datetime.now(timezone.utc).isoformat(),
        "system": system,
        "storage": result,
        "findings": findings,
        "note": "QTS CGI 欄位會因機型與韌體不同；unknown 不等於健康。",
    }


def dump(client: QtsClient, directory: Path) -> Dict[str, Any]:
    directory.mkdir(parents=True, exist_ok=True)
    responses = {
        "sysinfo.xml": client.get(SYSINFO_PATH, {"subfunc": "sysinfo"}),
        "storage.xml": client.get(DISK_PATH, {"func": "extra_get", "extra_vol_index": "1"}),
    }
    saved = []
    for filename, raw in responses.items():
        target = directory / filename
        target.write_text(redact_xml(raw), encoding="utf-8")
        saved.append(str(target))
    manifest = {"generated_at": datetime.now(timezone.utc).isoformat(), "redacted": True, "files": saved}
    (directory / "manifest.json").write_text(json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return manifest


def tailscale(config: Config) -> Dict[str, Any]:
    return tailscale_status(config)
