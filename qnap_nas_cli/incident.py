"""Read-only, bounded ransomware triage for known QNAP campaign artifacts.

This is deliberately not a general malware detector. It inventories visible
File Station shares and reports a small set of campaign-specific indicators.
"""

import posixpath
from collections import deque
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from .errors import CompatibilityError, QtsError


FILE_STATION_PATH = "/cgi-bin/filemanager/utilRequest.cgi"
DEFAULT_MAX_ITEMS = 10000
MAX_MAX_ITEMS = 100000
MAX_DEPTH = 12
MAX_FOLDERS = 5000
MAX_EXAMPLES = 25


def _rows(payload: Any, key: Optional[str] = None) -> List[Dict[str, Any]]:
    if isinstance(payload, list):
        rows = payload
    elif isinstance(payload, dict):
        if payload.get("status") not in (None, 1, "1"):
            raise QtsError("File Station 回報 status={}".format(payload.get("status")))
        if key:
            rows = payload.get(key)
        else:
            rows = next((payload.get(name) for name in ("datas", "shares", "tree", "items") if isinstance(payload.get(name), list)), None)
    else:
        rows = None
    if not isinstance(rows, list) or any(not isinstance(row, dict) for row in rows):
        raise CompatibilityError("File Station 回應格式未知；不把它視為掃描完成")
    return rows


def _share_path(row: Dict[str, Any]) -> Optional[str]:
    raw = row.get("id")
    if isinstance(raw, str) and raw.startswith(("/", "\\")):
        candidate = raw.replace("\\", "/")
    else:
        name = row.get("text")
        if not isinstance(name, str) or not name or name in (".", "..") or "/" in name or "\\" in name:
            return None
        candidate = "/" + name
    if any(part in (".", "..") for part in candidate.replace("\\", "/").split("/")):
        return None
    candidate = "/" + candidate.lstrip("/")
    normalized = posixpath.normpath(candidate)
    if not normalized.startswith("/") or normalized == "/" or "/../" in normalized + "/":
        return None
    return normalized


def _filename(value: Any) -> Optional[str]:
    if not isinstance(value, str) or not value or value in (".", ".."):
        return None
    if "/" in value or "\\" in value or "\x00" in value:
        return None
    return value


def _int_field(value: Any) -> Optional[int]:
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        return None
    return parsed if parsed >= 0 else None


def _example_add(target: List[str], value: str) -> None:
    if len(target) < MAX_EXAMPLES:
        target.append(value)


def scan_ransomware_artifacts(client: Any, max_items: int = DEFAULT_MAX_ITEMS) -> Dict[str, Any]:
    """Scan visible shared-file names with hard item/depth bounds; never writes to NAS."""
    if type(max_items) is not int or not 1 <= max_items <= MAX_MAX_ITEMS:
        raise ValueError("max_items 必須介於 1 到 {}".format(MAX_MAX_ITEMS))

    scanned = 0
    files_scanned = 0
    folders_scanned = 0
    issues = []  # type: List[Dict[str, str]]
    truncated = False
    depth_limited = False
    truncation_reasons = []  # type: List[str]

    def mark_truncated(reason: str) -> None:
        nonlocal truncated
        truncated = True
        if reason not in truncation_reasons:
            truncation_reasons.append(reason)

    deadbolt_examples = []  # type: List[str]
    qlocker_note_examples = []  # type: List[str]
    archive_examples = []  # type: List[str]
    deadbolt_count = 0
    qlocker_note_count = 0
    archive_count = 0

    try:
        shares_payload = client.get_json(FILE_STATION_PATH, {
            "func": "get_tree", "node": "share_root", "is_iso": "0",
            "hidden_file": "1", "recycle": "0", "check_acl": "1",
        })
        shares = _rows(shares_payload)
    except QtsError as exc:
        return _empty_scan(max_items, "share_listing_failed", str(exc))

    queue = deque()
    seen_paths = set()
    for share in shares:
        path = _share_path(share)
        if path and path not in seen_paths:
            seen_paths.add(path)
            queue.append((path, 0))
    if not queue:
        issues.append({"source": "share_root", "error": "no_parseable_shares"})

    while queue and scanned < max_items and folders_scanned < MAX_FOLDERS:
        folder_path, depth = queue.popleft()
        folders_scanned += 1
        start = 0
        while scanned < max_items:
            limit = min(200, max_items - scanned)
            try:
                payload = client.get_json(FILE_STATION_PATH, {
                    "func": "get_list", "path": folder_path, "dir": "ASC",
                    "limit": str(limit), "sort": "filename", "start": str(start),
                    "list_mode": "all", "hidden_file": "1", "is_iso": "0", "v": "1",
                })
                entries = _rows(payload, "datas")
            except QtsError as exc:
                issues.append({"source": folder_path, "error": str(exc)})
                break

            total = _int_field(payload.get("real_total", payload.get("total"))) if isinstance(payload, dict) else None
            if not entries:
                if total is not None and start < total:
                    issues.append({"source": folder_path, "error": "short_page_before_reported_total"})
                break

            for entry in entries:
                if scanned >= max_items:
                    mark_truncated("item_limit")
                    break
                scanned += 1
                name = _filename(entry.get("filename"))
                if name is None:
                    issues.append({"source": folder_path, "error": "entry_without_safe_filename"})
                    continue
                full_path = posixpath.join(folder_path, name)
                is_folder = entry.get("isfolder") is True or entry.get("isfolder") in (1, "1")
                if is_folder:
                    if depth >= MAX_DEPTH:
                        depth_limited = True
                        mark_truncated("depth_limit")
                        issues.append({"source": full_path, "error": "max_depth_reached"})
                    elif full_path not in seen_paths:
                        seen_paths.add(full_path)
                        queue.append((full_path, depth + 1))
                    continue

                files_scanned += 1
                lowered = name.lower()
                if lowered.endswith(".deadbolt"):
                    deadbolt_count += 1
                    _example_add(deadbolt_examples, full_path)
                if lowered == "!!!read_me.txt":
                    qlocker_note_count += 1
                    _example_add(qlocker_note_examples, full_path)
                if lowered.endswith(".7z"):
                    archive_count += 1
                    _example_add(archive_examples, full_path)

            if truncated:
                break
            if total is None:
                # Some firmware responses omit totals. A short page looks done,
                # but cannot prove that pagination/visibility was complete.
                if len(entries) < limit:
                    issues.append({"source": folder_path, "error": "total_count_not_reported"})
                    break
            elif start + len(entries) >= total:
                break
            if scanned >= max_items:
                # If the provider returned its total and it equals the number
                # seen, this cap is exact rather than truncated.
                if total is None or start + len(entries) < total:
                    mark_truncated("item_limit")
                break
            if len(entries) < limit and total is not None:
                issues.append({"source": folder_path, "error": "short_page_before_reported_total"})
                break
            start += len(entries)

    if queue:
        if scanned >= max_items:
            mark_truncated("item_limit")
        elif folders_scanned >= MAX_FOLDERS:
            mark_truncated("folder_limit")

    indicators = []
    if deadbolt_examples:
        indicators.append({"code": "deadbolt_extension", "family": "DeadBolt", "confidence": "high", "count": deadbolt_count, "examples": deadbolt_examples})
    if qlocker_note_examples:
        indicators.append({"code": "qlocker_ransom_note", "family": "Qlocker", "confidence": "high", "count": qlocker_note_count, "examples": qlocker_note_examples})
    if archive_count >= 10:
        indicators.append({
            "code": "qlocker_archive_cluster", "family": "Qlocker-like", "confidence": "low",
            "count": archive_count, "examples": archive_examples, "requires_corroboration": True,
            "interpretation": "低信心：大量 .7z 也可能是正常備份；單獨不升級為 suspected，需與 !!!READ_ME.txt、DeadBolt 指標、QTS 告警或其他獨立異常證據交叉比對。",
        })

    assessment = "suspected" if any(item["confidence"] in ("high", "medium") for item in indicators) else "indeterminate"
    if not indicators and archive_count:
        indicators.append({"code": "archive_extension_observed", "family": "unknown", "confidence": "informational", "count": archive_count, "examples": archive_examples})
    complete = not issues and not truncated and bool(shares)
    return {
        "assessment": assessment,
        "checked_at": datetime.now(timezone.utc).isoformat(),
        "coverage": {
            "status": "bounded_complete_for_visible_shares" if complete else "partial",
            "shares_seen": len(shares), "folders_scanned": folders_scanned,
            "entries_scanned": scanned, "files_scanned": files_scanned,
            "max_items": max_items, "max_depth": MAX_DEPTH,
            "truncated": truncated, "depth_limited": depth_limited,
            "truncation_reasons": truncation_reasons, "issues": issues,
            "scope": "File Station visible shared folders and names only; not process behavior, file contents, QTS logs, inaccessible paths, or all ransomware families",
        },
        "indicators": indicators,
        "note": "沒有命中只代表此有限名稱規則未命中；永遠不等同確認 NAS 無感染。大量 .7z 群聚是低信心線索，單獨不會升級為 suspected，需其他證據佐證。",
    }


def _empty_scan(max_items: int, code: str, message: str) -> Dict[str, Any]:
    return {
        "assessment": "indeterminate",
        "checked_at": datetime.now(timezone.utc).isoformat(),
        "coverage": {"status": "partial", "shares_seen": 0, "folders_scanned": 0, "entries_scanned": 0,
                     "files_scanned": 0, "max_items": max_items, "max_depth": MAX_DEPTH,
                     "truncated": False, "depth_limited": False, "truncation_reasons": [],
                     "issues": [{"source": code, "error": message}],
                     "scope": "File Station scan did not obtain a complete visible-share inventory"},
        "indicators": [],
        "note": "沒有命中只代表此有限名稱規則未命中；永遠不等同確認 NAS 無感染。",
    }


def response_plan(scan: Dict[str, Any]) -> Dict[str, Any]:
    """Return a manual response checklist; this function never executes it."""
    suspected = scan.get("assessment") == "suspected"
    raw_indicators = scan.get("indicators", [])
    families = {item.get("family") for item in raw_indicators if isinstance(item, dict)} if isinstance(raw_indicators, list) else set()
    if suspected:
        steps = [
            {"step": 1, "action": "保留本次報告、QTS 畫面截圖、告警時間與管理登入紀錄；不要刪除或重新命名可疑檔案。", "mode": "manual"},
            {"step": 2, "action": "由網路管理設備限制 NAS 對外及不必要的用戶端連線，同時保留一條受控管理／取證路徑；不要直接套用未審核的 NAS 防火牆規則。", "mode": "manual_external_containment"},
            {"step": 3, "action": "比對 QNAP 官方安全公告與 Malware Remover 更新，並聯絡 QNAP 支援；不要把本工具的 IOC 命中當成清除完成。", "mode": "manual_vendor_response"},
            {"step": 4, "action": "確認事件已遏止並完成乾淨重建／修補後，從離線或不可變更備份恢復到隔離位置；先驗證抽樣與權限，再切回正式服務。", "mode": "manual_recovery"},
        ]
    else:
        steps = [
            {"step": 1, "action": "先檢視 coverage issues、item/depth cap 與帳號可見範圍；本次未命中不代表乾淨。", "mode": "manual_triage"},
            {"step": 2, "action": "對照 QTS 系統／安全告警與 QNAP Malware Remover；若有大量改名、加密副檔名、勒索頁或異常寫入跡象，升級為事件並執行 contain。", "mode": "manual_triage"},
            {"step": 3, "action": "確認離線／不可變更備份可用並完成定期還原演練；未確認前不要將此報告標記為 clean。", "mode": "manual_readiness"},
        ]
    if suspected:
        steps.insert(0, {"step": 0, "action": "高度優先：停止一般使用者寫入並保留證據；不要用此 CLI 終止程序或重啟 NAS。若懷疑仍在加密，依 QNAP 對應家族公告處置並先聯絡支援。", "mode": "manual"})
    if "Qlocker" in families:
        steps.insert(1 if suspected else 0, {"step": 0, "action": "Qlocker 家族特定：若加密／壓縮仍在進行，QNAP 公告指示不要關機或重新啟動；先依當前 QNAP 支援指引處理並聯絡支援。這不是對其他家族的通用規則。", "mode": "family_specific_manual"})
    for index, step in enumerate(steps, 1):
        step["step"] = index
    return {
        "status": "manual_response_required" if suspected else "no_automatic_repair",
        "actions_applied": [],
        "automation_supported": False,
        "why": "本專案尚無經此型號／韌體驗證的 containment、清除或 restore adapter；自動停止服務、刪除檔案或在原機覆寫恢復會破壞證據或造成額外損害。",
        "steps": steps,
    }


def write_evidence_bundle(directory: Path, report: Dict[str, Any], **options: Any) -> Dict[str, Any]:
    """Backward-compatible entry point for the shared atomic capsule writer."""
    from .evidence_capsule import write_evidence_capsule

    return write_evidence_capsule(directory, report, **options)
