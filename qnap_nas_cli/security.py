"""Read-only security posture assessment helpers.

These rules classify observed Plex QPKG version metadata. They do not detect
compromise, determine network reachability, or perform remediation.
"""

import re
from datetime import datetime, timezone
from typing import Any, Dict, Optional, Tuple

from .ssh_backend import PLEX_KNOWN_PROCESS_IOCS


RULE_ID = "plex2shell-qnap-2026-11"
PATCHED_BASELINE = (1, 43, 3, 10861)
QNAP_ADVISORY = "https://www.qnap.com/zh-tw/how-to/faq/article/plex2shell-check-and-remediation-faq-for-qnap-nas-users"
PLEX_ADVISORY = "https://forums.plex.tv/t/important-security-update-for-plex-media-server-v1-43-2-and-earlier/942319/1"
_VERSION_RE = re.compile(r"^\s*(\d+)\.(\d+)\.(\d+)(?:\.(\d+))?\s*$")
IOC_FIELDS = {
    "unknown_plex_process": "是否發現 Plex 啟動、但無法辨識的程序（包含 QNAP 列出的程序名稱指標）。",
    "unfamiliar_codecs_files": "是否在 Plex Codecs 資料夾發現不熟悉的 .so 或 .dll 檔案。",
    "proxystream_st_connection": "是否觀察到對 proxystream.st 的外連。",
    "sustained_idle_cpu": "是否在沒有播放內容時持續出現高 CPU 使用率。",
    "malware_remover_detection": "Malware Remover 是否報告 Plex 相關偵測（例如 MR2104）。",
}


def parse_plex_version(value: Any) -> Optional[Tuple[int, int, int, int]]:
    """Parse three- or four-component QPKG/Plex versions; unknown stays None."""
    if not isinstance(value, str):
        return None
    match = _VERSION_RE.match(value)
    if not match:
        return None
    major, minor, patch, build = match.groups()
    return (int(major), int(minor), int(patch), int(build or 0))


def is_patched_version(value: Any) -> Optional[bool]:
    """Return baseline comparison, using QNAP's displayed 1.43.3 as patched."""
    parsed = parse_plex_version(value)
    if parsed is None:
        return None
    # QNAP App Center may expose only the three-part label for the fixed build.
    if parsed[:3] == PATCHED_BASELINE[:3] and parsed[3] == 0:
        return True
    return parsed >= PATCHED_BASELINE


def _exposure(value: Any, field: str) -> Optional[str]:
    if value is None:
        return None
    if value not in ("yes", "no"):
        raise ValueError("{} must be 'yes', 'no', or None".format(field))
    return value


def _normalize_iocs(values: Any) -> Dict[str, Optional[str]]:
    if values is None:
        values = {}
    if not isinstance(values, dict) or set(values) - set(IOC_FIELDS):
        raise ValueError("indicators must contain only documented Plex IOC fields")
    return {name: _exposure(values.get(name), name) for name in IOC_FIELDS}


def _normalize_runtime_iocs(value: Any) -> Dict[str, Any]:
    if value is None:
        return {
            "status": "not_requested",
            "scope": "Optional exact-name process probes were not requested.",
            "results": [{"name": name, "status": "not_requested", "match_count": None} for name in PLEX_KNOWN_PROCESS_IOCS],
        }
    if not isinstance(value, dict) or not isinstance(value.get("results"), list):
        raise ValueError("runtime_iocs must be a normalized process probe result")
    supplied = {}
    for item in value["results"]:
        if not isinstance(item, dict) or item.get("name") not in PLEX_KNOWN_PROCESS_IOCS:
            continue
        supplied[item["name"]] = item
    results = []
    for name in PLEX_KNOWN_PROCESS_IOCS:
        item = supplied.get(name, {})
        status = item.get("status")
        if status not in ("found", "not_found", "unavailable", "not_attempted"):
            status = "unavailable"
        count = item.get("match_count") if type(item.get("match_count")) is int and item.get("match_count") >= 0 else None
        if status != "found":
            count = 0 if status == "not_found" else None
        results.append({"name": name, "status": status, "match_count": count})
    partial = any(item["status"] in ("unavailable", "not_attempted") for item in results)
    return {
        "status": "partial" if partial else "exact_names_checked",
        "scope": "Only exact QNAP-listed process names are checked at collection time; no process table, parent/child relation, or command line is read.",
        "results": results,
    }


def assess_plex2shell(
    package: Dict[str, Any],
    exposure_during_vulnerable_version: Any = None,
    current_exposure: Any = None,
    indicators: Any = None,
    runtime_iocs: Any = None,
    checked_at: Optional[str] = None,
) -> Dict[str, Any]:
    """Build a conservative, non-forensic Plex2Shell posture observation."""
    historical = _exposure(exposure_during_vulnerable_version, "exposure_during_vulnerable_version")
    current = _exposure(current_exposure, "current_exposure")
    ioc_values = _normalize_iocs(indicators)
    runtime_probe = _normalize_runtime_iocs(runtime_iocs)
    reported_iocs = [name for name, value in ioc_values.items() if value == "yes"]
    runtime_hits = [item["name"] for item in runtime_probe["results"] if item["status"] == "found"]
    installed_value = package.get("installed")
    installed = installed_value is True
    version = package.get("version")
    patched = is_patched_version(version)
    findings = []
    unknowns = []

    if historical == "yes":
        assessment = "potentially_compromised"
        findings.append({
            "severity": "critical",
            "code": "historical_exposure_while_vulnerable",
            "message": "操作人員回報 Plex 在易受影響版本期間曾可從外部連線；更新版本不能排除既有入侵。",
        })
    elif installed_value is False:
        assessment = "not_installed"
        unknowns.append({"code": "plex_not_installed", "message": "未觀察到 Plex QPKG；不代表 NAS 沒有其他 Plex 安裝方式。"})
    elif installed_value is not True:
        assessment = "indeterminate"
        unknowns.append({"code": "plex_installation_status_unknown", "message": "無法確認 Plex QPKG 是否安裝；不可將連線或收集失敗解讀為未安裝。"})
    elif patched is None:
        assessment = "indeterminate"
        unknowns.append({"code": "plex_version_unknown", "message": "QPKG 版本缺失或格式無法解析，不能判斷修補狀態。"})
    else:
        vulnerable = not patched
        if vulnerable and current == "yes":
            assessment = "vulnerable_exposed"
            findings.append({
                "severity": "critical",
                "code": "vulnerable_version_currently_exposed",
                "message": "操作人員回報 Plex 目前可從外部連線，且觀察到的版本低於修補基線。",
            })
        elif vulnerable:
            assessment = "vulnerable"
            findings.append({
                "severity": "high",
                "code": "plex_version_below_patched_baseline",
                "message": "觀察到的 Plex QPKG 版本低於 QNAP 公布的修補基線。",
            })
        elif current == "yes":
            assessment = "patched_but_exposed"
            findings.append({
                "severity": "warning",
                "code": "patched_service_currently_exposed",
                "message": "版本達修補基線，但操作人員回報 Plex 目前仍可從外部連線；建議縮小暴露面。",
            })
        else:
            assessment = "patched"

    if current == "yes" and (not installed or patched is None):
        findings.append({
            "severity": "high",
            "code": "external_exposure_with_unknown_patch_state",
            "message": "操作人員回報 Plex 目前可從外部連線，但此觀察無法確認 Plex 修補狀態。",
        })

    for name in reported_iocs:
        findings.append({
            "severity": "critical" if name == "malware_remover_detection" else "high",
            "code": "plex_ioc_{}".format(name),
            "message": "操作人員回報觀察到 Plex 事件指標：{}".format(IOC_FIELDS[name]),
            "source": "operator_reported",
        })
    for name in runtime_hits:
        findings.append({
            "severity": "high",
            "code": "plex_ioc_known_process_{}".format(name),
            "message": "只讀精確名稱探測在收集當下找到 QNAP 公布的 Plex 可疑程序名稱：{}。".format(name),
            "source": "runtime_probe",
        })
    if (reported_iocs or runtime_hits) and historical != "yes":
        assessment = "suspected"

    if current is None:
        unknowns.append({"code": "current_exposure_not_collected", "message": "外部可達性未由此工具檢查；路由器、UPnP、myQNAPcloud 與防火牆狀態未知。"})
    if historical is None:
        unknowns.append({"code": "historical_exposure_not_collected", "message": "易受影響版本期間的歷史外部可達性未由此工具檢查。"})
    for name, value in ioc_values.items():
        if value is None:
            unknowns.append({"code": "ioc_{}_not_collected".format(name), "message": IOC_FIELDS[name] + " 由管理者檢查後回報；未回報維持 unknown。"})
    if runtime_probe["status"] != "not_requested":
        unknowns.append({"code": "runtime_process_probe_scope_limited", "message": "僅比對三個精確程序名稱與單次快照；未檢查其他程序、父子關係、命令列、持久化、檔案或網路指標。"})
        for item in runtime_probe["results"]:
            if item["status"] in ("unavailable", "not_attempted"):
                unknowns.append({"code": "runtime_process_probe_{}_{}".format(item["name"], item["status"]), "message": "精確名稱程序探測無法完成；結果維持 unknown。"})
    if installed:
        unknowns.append({"code": "runtime_and_compromise_not_checked", "message": "未檢查完整 process tree、Codecs、日誌、其餘網路連線或檔案系統；此結果不是完整惡意程式掃描或未受害證明。"})

    return {
        "report_type": "qnap_plex2shell_posture",
        "format_version": 1,
        "checked_at": checked_at or datetime.now(timezone.utc).isoformat(),
        "rule_id": RULE_ID,
        "assessment": assessment,
        "patch_status": "patched" if patched is True else "vulnerable" if patched is False else "unknown",
        "package": package,
        "exposure": {
            "current": current or "unknown",
            "during_vulnerable_version": historical or "unknown",
            "source": "operator_reported" if current is not None or historical is not None else "not_collected",
        },
        "ioc_observations": {
            name: {"value": value or "unknown", "source": "operator_reported" if value is not None else "not_collected"}
            for name, value in ioc_values.items()
        },
        "runtime_ioc_probes": runtime_probe,
        "findings": findings,
        "unknowns": unknowns,
        "recommended_actions": _recommendations(assessment, current, patched),
        "references": [QNAP_ADVISORY, PLEX_ADVISORY],
        "automation_supported": False,
        "scope": "只讀 QPKG 版本與操作人員回報的外部暴露/IOC 指標；選用 runtime 探測也只比對三個固定程序名，不是入侵確診、完整惡意程式掃描或完整資產盤點。",
    }


def _recommendations(assessment: str, current_exposure: Optional[str], patched: Optional[bool]) -> list:
    actions = []
    if assessment in ("potentially_compromised", "suspected"):
        actions.extend([
            "先保存 Plex 日誌與可疑檔案清單，再依 QNAP 事件指引聯絡支援；不要先卸載 Plex 或清理檔案以免覆蓋證據。",
            "保存必要證據後，由管理者關閉不必要的 Plex Remote Access、TCP 32400、UPnP 與 myQNAPcloud 外部轉發；遠端存取優先使用 VPN。",
            "依 QNAP 指引進行可信任的清潔重新安裝，不重用舊 Codecs；之後登出 Plex 裝置並重設 Plex/NAS 與 NAS 儲存的憑證。此工具不會自動執行。",
        ])
    elif patched is False:
        actions.append("在 QNAP App Center 更新到 QNAP 公布的 Plex 修補版本（1.43.3；如有完整 build，至少 1.43.3.10861），再重新查核版本。")
        if current_exposure == "yes":
            actions.append("由管理者關閉不必要的 Plex Remote Access、TCP 32400、UPnP 與 myQNAPcloud 外部轉發；需要遠端存取時優先使用 VPN。")
    elif current_exposure == "yes":
        actions.append("由管理者檢查並關閉不必要的 Plex Remote Access、TCP 32400、UPnP 與 myQNAPcloud 外部轉發；需要遠端存取時優先使用 VPN。")
    elif patched is None and assessment == "indeterminate":
        actions.append("在 QNAP App Center 直接確認 Plex 完整版本與 build；無法讀取或解析的版本不可視為已修補。")
    if not actions:
        actions.append("維持 Plex 更新，並由管理者確認外部暴露及歷史可達性；本工具的未知欄位不代表安全。")
    return actions
