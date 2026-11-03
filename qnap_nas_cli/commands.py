import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict

from .client import QtsClient
from .config import Config
from .parsers import merge_storage, parse_network, parse_storage, parse_system
from .redaction import redact_xml
from .ssh_backend import disk_topology, raid_status, service_status, smart_attributes, tailscale_status


SYSINFO_PATH = "/cgi-bin/management/manaRequest.cgi"
DISK_PATH = "/cgi-bin/disk/disk_manage.cgi"
SMART_PATH = "/cgi-bin/disk/qsmart.cgi"


def sysinfo(client: QtsClient) -> Dict[str, Any]:
    return parse_system(client.get_xml(SYSINFO_PATH, {"subfunc": "sysinfo"}))


def network(client: QtsClient) -> Dict[str, Any]:
    return parse_network(client.get_xml(SYSINFO_PATH, {"subfunc": "sysinfo"}))


def storage(client: QtsClient) -> Dict[str, Any]:
    result = merge_storage(
        parse_storage(client.get_xml(DISK_PATH, {"func": "extra_get", "extra_vol_index": "1"})),
        parse_storage(client.get_xml(SYSINFO_PATH, {"subfunc": "sysinfo"})),
        parse_storage(client.get_xml(SMART_PATH, {"func": "all_hd_data"})),
    )
    result["source"] = {
        "endpoint": DISK_PATH,
        "func": "extra_get",
        "extra_vol_index": 1,
        "coverage": "unverified",
        "additional_endpoints": [SYSINFO_PATH, SMART_PATH],
    }
    result["limitations"] = [
        "extra_vol_index=1 尚未證明涵蓋全部 pool/volume；不能據此宣告 Storage healthy",
        "qsmart.cgi 只提供頂層 Health；不涵蓋完整 SMART attributes 與歷史 I/O errors",
    ]
    return result


def health(client: QtsClient) -> Dict[str, Any]:
    system = sysinfo(client)
    result = storage(client)
    findings = []
    unknowns = []
    if result.get("source", {}).get("coverage") != "verified":
        unknowns.append({
            "code": "storage_scope_unverified",
            "message": "extra_vol_index=1 的回應尚未經實機對照證明涵蓋全部 Storage",
        })
    temp = system.get("temperature_c")
    if isinstance(temp, (int, float)) and temp >= 70:
        findings.append({"severity": "warning", "code": "system_temperature", "message": "系統溫度偏高：{} °C".format(temp)})
    for disk in result["disks"]:
        status = str(disk.get("smart") or "").lower()
        if status and status not in ("0", "good", "ready", "normal", "ok"):
            findings.append({"severity": "warning", "code": "disk_health", "disk": disk.get("disk"), "message": "磁碟健康狀態需要確認：{}".format(disk.get("smart"))})
        elif not status:
            unknowns.append({"code": "disk_health_unknown", "disk": disk.get("disk"), "message": "QTS 回應未提供可判讀的磁碟健康狀態"})
        disk_temp = disk.get("temperature_c")
        if isinstance(disk_temp, (int, float)) and disk_temp >= 55:
            findings.append({"severity": "warning", "code": "disk_temperature", "disk": disk.get("disk"), "message": "磁碟溫度偏高：{} °C".format(disk_temp)})
    for volume in result["volumes"]:
        if volume.get("status_semantics") == "known_bad":
            findings.append({"severity": "critical", "code": "volume_status", "volume": volume.get("name"), "message": "儲存空間狀態：{}".format(volume.get("status"))})
        elif volume.get("status_semantics") != "known_good":
            unknowns.append({
                "code": "volume_status_unknown",
                "volume": volume.get("name"),
                "status_code": volume.get("status_code"),
                "message": "儲存空間狀態未知；不能據此判定健康",
            })
    for warning in result.get("parser_warnings", []):
        unknowns.append({"code": warning, "message": "Storage 回應缺少預期資料：{}".format(warning)})
    if findings:
        overall_status = "unhealthy"
        healthy = False
    elif unknowns:
        overall_status = "indeterminate"
        healthy = None
    else:
        overall_status = "healthy"
        healthy = True
    return {
        "status": overall_status,
        "healthy": healthy,
        "data_completeness": "partial" if unknowns else "complete",
        "checked_at": datetime.now(timezone.utc).isoformat(),
        "system": system,
        "storage": result,
        "findings": findings,
        "unknowns": unknowns,
        "note": "healthy 只代表已觀察欄位沒有異常且必要狀態完整；indeterminate 代表資料不足。",
        "healthy_claim": "not_permitted" if unknowns else "permitted",
    }


def dump(client: QtsClient, directory: Path) -> Dict[str, Any]:
    directory.mkdir(parents=True, exist_ok=True)
    responses = {
        "sysinfo.xml": client.get(SYSINFO_PATH, {"subfunc": "sysinfo"}),
        "storage.xml": client.get(DISK_PATH, {"func": "extra_get", "extra_vol_index": "1"}),
        "smart.xml": client.get(SMART_PATH, {"func": "all_hd_data"}),
    }
    saved = []
    for filename, raw in responses.items():
        target = directory / filename
        target.write_text(redact_xml(raw), encoding="utf-8")
        saved.append(filename)
    manifest = {
        "format_version": 2,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "redacted": True,
        "files": saved,
        "validation": validate_dump(directory),
    }
    (directory / "manifest.json").write_text(json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return manifest


def validate_dump(directory: Path) -> Dict[str, Any]:
    import xml.etree.ElementTree as ET
    required = {"sysinfo.xml", "storage.xml"}
    present = {path.name for path in directory.iterdir()} if directory.is_dir() else set()
    missing = sorted(required - present)
    errors = []
    observations = {}
    if "sysinfo.xml" in present:
        try:
            observations["system"] = parse_system(ET.parse(str(directory / "sysinfo.xml")).getroot())
        except (OSError, ET.ParseError) as exc:
            errors.append("sysinfo.xml: {}".format(exc))
    if "storage.xml" in present:
        try:
            storage_reports = [parse_storage(ET.parse(str(directory / "storage.xml")).getroot())]
            if "sysinfo.xml" in present:
                storage_reports.append(parse_storage(ET.parse(str(directory / "sysinfo.xml")).getroot()))
            if "smart.xml" in present:
                storage_reports.append(parse_storage(ET.parse(str(directory / "smart.xml")).getroot()))
            observations["storage"] = merge_storage(*storage_reports)
        except (OSError, ET.ParseError) as exc:
            errors.append("storage.xml: {}".format(exc))
    storage_data = observations.get("storage", {})
    warnings = list(storage_data.get("parser_warnings", []))
    if storage_data:
        warnings.append("storage_query_scope_unverified")
    for volume in storage_data.get("volumes", []):
        if volume.get("status_semantics") == "unknown":
            warnings.append("unknown_volume_status:{}".format(volume.get("status_code")))
    return {
        "valid": not missing and not errors,
        "missing": missing,
        "errors": errors,
        "warnings": warnings,
        "observations": observations,
    }


def tailscale(config: Config) -> Dict[str, Any]:
    return tailscale_status(config)


def raid(config: Config) -> Dict[str, Any]:
    return raid_status(config)


def smart_details(config: Config, disk: int) -> Dict[str, Any]:
    return smart_attributes(config, disk)


def disks_ssh(config: Config) -> Dict[str, Any]:
    return disk_topology(config)


def services(config: Config) -> Dict[str, Any]:
    return service_status(config)
