"""Read-only package posture for QNAP's Qlocker, DeadBolt, and QSnatch advisories.

The checks intentionally evaluate only firmware branches with published fixed
package thresholds. An unknown branch/version remains unknown; package metadata
does not prove runtime state or absence of compromise.
"""

import re
from datetime import datetime, timezone
from typing import Any, Dict, Optional, Tuple


QSA_21_13 = "https://www.qnap.com/en-as/security-advisory/qsa-21-13"
QSA_22_24 = "https://www.qnap.com/zh-tw/security-advisory/qsa-22-24"
QSNATCH_ADVISORY = "https://www.qnap.com/zh-tw/security-advisory/nas-201911-01"
QSNATCH_NEWS = "https://www.qnap.com/zh-tw/security-news/2020/回應-qsnatch-攻擊事件惡意軟體無變種受影響用戶數持續縮減"
QLOCKER_RESPONSE = "https://www.qnap.com/static/landing/2021/qlocker/response/zh-hk/"
QLOCKER_SECONDARY = "https://ess.site.nthu.edu.tw/p/406-1351-205347,r1602.php?Lang=zh-tw"
PHOTOSTATION_EOL = "https://www.qnap.com/en/product/status?category=software"

_VERSION_RE = re.compile(r"^\s*(\d+(?:\.\d+){1,3})\s*$")

# Thresholds from QSA-21-13. No extrapolation to an unlisted OS branch.
_HBS_FIXED: Dict[Tuple[str, str], Tuple[int, ...]] = {
    ("QTS", "4.5.2"): (16, 0, 415),
    ("QTS", "4.3.6"): (3, 0, 210412),
    ("QTS", "4.3.3"): (3, 0, 210411),
    ("QTS", "4.3.4"): (3, 0, 210411),
    ("QuTS hero", "4.5.1"): (16, 0, 419),
}

# Thresholds from QSA-22-24. Firmware versions outside these exact families
# remain unverified rather than inheriting a nearby branch's baseline.
_PHOTO_FIXED: Dict[Tuple[str, str], Tuple[int, ...]] = {
    ("QTS", "5.0.1"): (6, 1, 2),
    ("QTS", "5.0.0"): (6, 0, 22),
    ("QTS", "4.5.x"): (6, 0, 22),
    ("QTS", "4.3.6"): (5, 7, 18),
    ("QTS", "4.3.3"): (5, 4, 15),
    ("QTS", "4.2.6"): (5, 2, 14),
}

# Operator-confirmed controls derived from NAS-201911-01. None can be inferred
# from QPKG metadata alone, so every omitted control remains explicitly unknown.
QSNATCH_CONTROLS = {
    "qts_latest": "QTS 已更新至此機型可用的最新版本",
    "apps_latest": "已安裝的 QTS 應用程式已更新",
    "malware_remover_updated_and_scan_run": "Malware Remover 已更新定義並完成掃描",
    "security_counselor_updated_and_scan_run": "Security Counselor（若機型支援）已更新並完成掃描",
    "credentials_rotated": "已輪替管理員、使用者、QNAP ID 與適用的資料庫管理憑證",
    "accounts_reviewed": "已審查帳號並移除未知／可疑帳號",
    "access_protection_enabled": "已啟用 IP 與帳號存取保護",
    "unused_services_disabled": "已停用未使用的 SSH、Telnet、Web Server、SQL Server/phpMyAdmin",
    "external_access_hardened": "已檢查非預設管理埠、UPnP/Auto Router Configuration、已發佈服務及 myQNAPcloud 存取控制",
}


def parse_qsnatch_control(value: str) -> Tuple[str, str]:
    """Parse a CLI operator assertion in the form CONTROL=yes|no."""
    if not isinstance(value, str) or "=" not in value:
        raise ValueError("QSnatch control must use CONTROL=yes|no")
    name, status = value.split("=", 1)
    if name not in QSNATCH_CONTROLS or status not in ("yes", "no"):
        raise ValueError("unknown QSnatch control or invalid status; use a documented control with yes/no")
    return name, status


def parse_version(value: Any) -> Optional[Tuple[int, ...]]:
    if not isinstance(value, str):
        return None
    match = _VERSION_RE.fullmatch(value)
    if not match:
        return None
    return tuple(int(part) for part in match.group(1).split("."))


def _padded(value: Tuple[int, ...]) -> Tuple[int, int, int, int]:
    return (value + (0, 0, 0, 0))[:4]


def _photo_profile(product: Any, firmware: Any) -> Optional[Tuple[int, ...]]:
    if product != "QTS" or not isinstance(firmware, str):
        return None
    match = re.fullmatch(r"(\d+\.\d+\.\d+)(?:\..*)?", firmware.strip())
    if not match:
        return None
    version = match.group(1)
    if version.startswith("4.5."):
        return _PHOTO_FIXED[("QTS", "4.5.x")]
    return _PHOTO_FIXED.get(("QTS", version))


def _hbs_profile(product: Any, firmware: Any) -> Optional[Tuple[int, ...]]:
    if product not in ("QTS", "QuTS hero", "QuTScloud") or not isinstance(firmware, str):
        return None
    prefix = {"QuTS hero": "h?", "QuTScloud": "c?"}.get(product, "")
    match = re.fullmatch(prefix + r"(\d+\.\d+\.\d+)(?:\..*)?", firmware.strip())
    if not match:
        return None
    version = match.group(1)
    if product == "QuTScloud" and version in ("4.5.1", "4.5.2", "4.5.3", "4.5.4"):
        return (16, 0, 419)
    return _HBS_FIXED.get((product, version))


def _package_assessment(package: Any, baseline: Optional[Tuple[int, ...]]) -> Dict[str, Any]:
    if not isinstance(package, dict):
        package = {}
    installed_value = package.get("installed")
    version = package.get("version") if isinstance(package.get("version"), str) else None
    if installed_value is False:
        return {"status": "not_installed", "version": version, "baseline": None, "installed": False}
    if installed_value is not True:
        return {"status": "unknown", "version": version, "baseline": None, "installed": None}
    parsed = parse_version(version)
    if baseline is None or parsed is None:
        return {
            "status": "unknown", "version": version,
            "baseline": ".".join(str(part) for part in baseline) if baseline else None,
            "installed": True,
        }
    return {
        "status": "patched" if _padded(parsed) >= _padded(baseline) else "vulnerable",
        "version": version,
        "baseline": ".".join(str(part) for part in baseline),
        "installed": True,
    }


def assess_legacy_ransomware(
    system: Dict[str, Any],
    packages: Dict[str, Any],
    historical_exposure: Any = None,
    current_exposure: Any = None,
    qsnatch_controls: Optional[Dict[str, Any]] = None,
    checked_at: Optional[str] = None,
) -> Dict[str, Any]:
    """Assess published legacy-advisory package posture without declaring clean."""
    for name, value in (("historical_exposure", historical_exposure), ("current_exposure", current_exposure)):
        if value not in (None, "yes", "no"):
            raise ValueError("{} must be 'yes', 'no', or None".format(name))
    qsnatch_controls = {} if qsnatch_controls is None else qsnatch_controls
    if not isinstance(qsnatch_controls, dict) or set(qsnatch_controls) - set(QSNATCH_CONTROLS):
        raise ValueError("qsnatch_controls must contain only documented controls")
    if any(value not in ("yes", "no") for value in qsnatch_controls.values()):
        raise ValueError("QSnatch control values must be 'yes' or 'no'")

    firmware_product = system.get("firmware_product")
    firmware = system.get("firmware")
    hbs = _package_assessment(packages.get("hbs3"), _hbs_profile(firmware_product, firmware))
    photo = _package_assessment(packages.get("photo_station"), _photo_profile(firmware_product, firmware))
    malware_remover = packages.get("malware_remover") if isinstance(packages.get("malware_remover"), dict) else {}
    security_center = packages.get("security_center") if isinstance(packages.get("security_center"), dict) else {}
    security_counselor = packages.get("security_counselor") if isinstance(packages.get("security_counselor"), dict) else {}
    findings = []
    unknowns = []
    normalized_controls = {}
    for control, label in QSNATCH_CONTROLS.items():
        status = qsnatch_controls.get(control, "unknown")
        normalized_controls[control] = {"status": status, "label": label}
        if status == "no":
            findings.append({
                "severity": "warning",
                "code": "qsnatch_control_not_confirmed_{}".format(control),
                "message": "NAS-201911-01 建議措施未完成或未確認：{}。".format(label),
            })
        elif status == "unknown":
            unknowns.append({
                "code": "qsnatch_control_unknown_{}".format(control),
                "message": "未由唯讀探針驗證 NAS-201911-01 控制項：{}；請由管理者人工確認。".format(label),
            })
    for package_name, result, advisory in (("hbs3", hbs, "QSA-21-13"), ("photo_station", photo, "QSA-22-24")):
        if result["status"] == "vulnerable":
            findings.append({
                "severity": "critical" if historical_exposure == "yes" else "high",
                "code": "{}_below_fixed_baseline".format(package_name),
                "message": "{} 觀察版本低於可比對的 {} 修補基線。".format(package_name, advisory),
            })
        elif result["status"] == "unknown" and result["installed"]:
            unknowns.append({
                "code": "{}_patch_status_unknown".format(package_name),
                "message": "{} 已安裝，但韌體分支或版本格式沒有足夠的已發布基線可比對。".format(package_name),
            })

    if photo["installed"]:
        findings.append({
            "severity": "warning",
            "code": "photo_station_end_of_service",
            "message": "Photo Station 已停止更新；QNAP 不保證未來安全性與相容性。",
        })

    for package, display_name, code_prefix in (
        (malware_remover, "Malware Remover", "malware_remover"),
        (security_center, "Security Center", "security_center"),
        (security_counselor, "Security Counselor", "security_counselor"),
    ):
        if package.get("installed") is not True:
            unknowns.append({
                "code": "{}_availability_unconfirmed".format(code_prefix),
                "message": "{} 的安裝／相容性／啟用狀態尚未確認；本工具不會安裝或啟用。".format(display_name),
            })
        else:
            if package.get("enabled") is False:
                findings.append({
                    "severity": "warning",
                    "code": "{}_disabled".format(code_prefix),
                    "message": "{} 的 QPKG metadata 顯示為 disabled；這不表示套件已移除。".format(display_name),
                })
            if not package.get("version"):
                unknowns.append({
                    "code": "{}_version_unavailable".format(code_prefix),
                    "message": "{} 已觀察到，但 QPKG 版本資料不可用；無法判斷是否為最新定義或最新版本。".format(display_name),
                })
            else:
                unknowns.append({
                    "code": "{}_freshness_unverified".format(code_prefix),
                    "message": "已讀取 {} QPKG 版本，但未連線 App Center／檢查定義日期，也未確認掃描完成。".format(display_name),
                })

    if historical_exposure is None:
        unknowns.append({"code": "historical_internet_exposure_unknown", "message": "HBS／Photo Station 易受影響版本期間的 Internet 可達性由管理者確認；未回報維持 unknown。"})
    if current_exposure is None:
        unknowns.append({"code": "current_internet_exposure_unknown", "message": "路由器 port forwarding、UPnP、myQNAPcloud 與服務發佈狀態未由本工具檢查。"})

    affected = any(item["status"] == "vulnerable" for item in (hbs, photo))
    if historical_exposure == "yes" and affected:
        assessment = "potentially_compromised"
        findings.insert(0, {
            "severity": "critical",
            "code": "legacy_vulnerable_package_historically_exposed",
            "message": "管理者回報易受影響版本曾暴露於 Internet；修補目前版本不能排除既有入侵。",
        })
    elif historical_exposure == "yes" and any(item["installed"] is True for item in (hbs, photo)):
        assessment = "indeterminate"
    elif affected and current_exposure == "yes":
        assessment = "vulnerable_exposed"
    elif affected:
        assessment = "vulnerable"
    elif any(item["status"] == "unknown" and item["installed"] is not False for item in (hbs, photo)):
        assessment = "indeterminate"
    elif not hbs["installed"] and not photo["installed"]:
        assessment = "indeterminate"
        unknowns.append({"code": "legacy_packages_not_observed", "message": "未觀察到 HBS 3／Photo Station QPKG；不代表不存在其他安裝方式，也不涵蓋 QSnatch 對 NAS 本身的風險。"})
    else:
        # A patched package alone does not establish exposure history, QSnatch controls, or a clean verdict.
        assessment = "patched" if (
            historical_exposure == "no"
            and current_exposure == "no"
            and all(item["status"] == "yes" for item in normalized_controls.values())
        ) else "indeterminate"

    if photo["installed"] and current_exposure == "yes" and assessment not in ("vulnerable_exposed", "potentially_compromised"):
        findings.append({
            "severity": "high",
            "code": "legacy_photo_station_currently_exposed",
            "message": "管理者回報已停止更新的 Photo Station 目前可從 Internet 存取。",
        })

    if historical_exposure == "yes" and not affected:
        unknowns.append({"code": "historical_exposure_package_history_missing", "message": "歷史暴露已回報，但目前 QPKG 版本不能重建當時版本；仍需人工事件檢視。"})

    actions = [
        "依 QNAP QSnatch 公告 NAS-201911-01 逐項確認韌體／應用程式更新、Malware Remover／Security Counselor 定義與掃描、密碼輪替、帳號審查、登入保護及未使用服務；未傳入 --qsnatch-control 的項目維持 unknown。",
        "人工確認管理埠、UPnP／Auto Router Configuration、已發佈服務與 myQNAPcloud 存取控制；本工具不探測路由器，也不修改 NAS 網路設定。",
        "執行 qts incident scan 檢查有限的 Qlocker／DeadBolt 檔名 IOC；coverage partial 或無命中均不代表乾淨。",
    ]
    if hbs["status"] == "vulnerable":
        actions.insert(0, "在 App Center 將 HBS 3 更新到目前 QNAP 支援版本，並重新查核；若曾對外暴露，先保留證據並依事件流程評估，不要只以更新視為清除。")
    if photo["installed"]:
        actions.insert(0, "Photo Station 已於 2025-06-30 結束服務；遷移至受支援的相片管理方案，並由管理者移除不必要外部可達性。不要由 CLI 自動移除應用程式或資料。")
    if historical_exposure == "yes" or assessment in ("potentially_compromised", "suspected"):
        actions.insert(0, "先保存事件時間、QTS／Malware Remover 告警及必要日誌，再依 QNAP 指引聯絡支援並評估憑證輪替與可信任重建；此工具不清除惡意程式。")

    return {
        "report_type": "qnap_legacy_ransomware_posture",
        "format_version": 1,
        "checked_at": checked_at or datetime.now(timezone.utc).isoformat(),
        "rule_id": "qnap-legacy-ransomware-2026-11",
        "assessment": assessment,
        "system": {
            "model": system.get("model"),
            "firmware_product": firmware_product,
            "firmware": firmware,
            "build": system.get("build"),
        },
        "exposure": {
            "historical_during_affected_package_version": historical_exposure or "unknown",
            "current_internet_exposure": current_exposure or "unknown",
            "source": "operator_reported" if historical_exposure is not None or current_exposure is not None else "not_collected",
        },
        "package_posture": {"hbs3": hbs, "photo_station": photo},
        "security_apps": {
            "malware_remover": {key: malware_remover.get(key) for key in ("installed", "version", "enabled", "qpkg_status")},
            "security_center": {key: security_center.get(key) for key in ("installed", "version", "enabled", "qpkg_status")},
            "security_counselor": {key: security_counselor.get(key) for key in ("installed", "version", "enabled", "qpkg_status")},
            "freshness": "unknown",
            "scan_completed": "unknown",
        },
        "qsnatch_security_controls": {
            "source": "operator_reported" if qsnatch_controls else "not_collected",
            "controls": normalized_controls,
        },
        "findings": findings,
        "unknowns": unknowns,
        "recommended_actions": actions,
        "references": [QSA_21_13, QSA_22_24, QSNATCH_ADVISORY, QSNATCH_NEWS, QLOCKER_RESPONSE, QLOCKER_SECONDARY, PHOTOSTATION_EOL],
        "automation_supported": False,
        "scope": "唯讀 QPKG package version metadata 與已知 firmware-branch advisory baseline；外部暴露、Malware Remover 定義新鮮度/掃描結果、QTS 設定及感染狀態未由此工具確認。不是完整惡意程式掃描或 clean verdict。",
    }
