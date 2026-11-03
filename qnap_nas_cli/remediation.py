"""Fail-closed plan/apply primitives for future verified QTS mutations.

Production currently registers no mutating adapters. This module defines the
contract and can be exercised with test adapters, but cannot change a NAS by
itself.
"""

import hashlib
import json
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Mapping, Optional

from .errors import QtsError


PLAN_FORMAT_VERSION = 1
PLAN_TTL_SECONDS = 900


def _canonical(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")


def _digest(payload: Dict[str, Any]) -> str:
    return hashlib.sha256(_canonical(payload)).hexdigest()


def create_plan(device: Dict[str, Any], action: str, operations: list,
                preconditions: Optional[list] = None, recovery: Optional[list] = None,
                refusal_reason: Optional[str] = None, manual_steps: Optional[list] = None) -> Dict[str, Any]:
    """Create a confirmation-bound plan. Secrets must never be placed in it."""
    now = datetime.now(timezone.utc)
    plan = {
        "format_version": PLAN_FORMAT_VERSION,
        "created_at": now.isoformat(),
        "expires_at": (now + timedelta(seconds=PLAN_TTL_SECONDS)).isoformat(),
        "device": device,
        "action": action,
        "status": "refused" if refusal_reason else "ready",
        "operations": operations,
        "preconditions": preconditions or [],
        "recovery": recovery or [],
        "manual_steps": manual_steps or [],
        "refusal_reason": refusal_reason,
    }
    plan["plan_id"] = _digest(plan)
    return plan


def validate_plan(plan: Dict[str, Any], now: Optional[datetime] = None) -> None:
    if not isinstance(plan, dict) or plan.get("format_version") != PLAN_FORMAT_VERSION:
        raise QtsError("不支援的 repair plan 格式")
    supplied_id = plan.get("plan_id")
    payload = {key: value for key, value in plan.items() if key != "plan_id"}
    if not isinstance(supplied_id, str) or supplied_id != _digest(payload):
        raise QtsError("repair plan 完整性驗證失敗；重新產生 plan")
    try:
        expires_at = datetime.fromisoformat(plan["expires_at"])
    except (KeyError, TypeError, ValueError) as exc:
        raise QtsError("repair plan 缺少有效期限") from exc
    now = now or datetime.now(timezone.utc)
    if expires_at.tzinfo is None:
        raise QtsError("repair plan 時間必須含時區")
    if now.astimezone(timezone.utc) >= expires_at.astimezone(timezone.utc):
        raise QtsError("repair plan 已過期；重新讀取 NAS 狀態並產生新 plan")
    if not isinstance(plan.get("operations"), list) or not isinstance(plan.get("device"), dict):
        raise QtsError("repair plan 結構不完整")
    for operation in plan["operations"]:
        if not isinstance(operation, dict) or not isinstance(operation.get("operation"), str) or "before" not in operation or "after" not in operation:
            raise QtsError("repair plan operation 必須包含 operation/before/after")


def apply_plan(plan: Dict[str, Any], confirmation: str, handlers: Mapping[str, Any],
               context: Any = None, now: Optional[datetime] = None,
               device_reader: Any = None, precondition_checker: Any = None) -> Dict[str, Any]:
    """Apply only pre-registered operations; re-read before/after every step.

    A handler must implement read(operation, context), apply(operation,
    context), and verify(operation, observed, context). A failed verification
    halts later steps; the engine never guesses a rollback.
    """
    validate_plan(plan, now)
    if plan.get("status") != "ready" or not plan["operations"]:
        return {"status": "refused", "plan_id": plan["plan_id"], "reason": plan.get("refusal_reason") or "plan_has_no_executable_operations", "steps": []}
    if confirmation != plan["plan_id"]:
        raise QtsError("確認碼不符；請逐字提供目前 plan_id")
    missing = [op.get("operation") for op in plan["operations"] if op.get("operation") not in handlers]
    if missing:
        return {"status": "refused", "plan_id": plan["plan_id"], "reason": "no_verified_adapter", "missing_adapters": missing, "steps": []}
    if not callable(device_reader):
        return {"status": "refused", "plan_id": plan["plan_id"], "reason": "no_device_identity_verifier", "steps": []}
    try:
        current_device = device_reader(context)
    except Exception:
        return {"status": "refused", "plan_id": plan["plan_id"], "reason": "device_identity_read_failed", "steps": []}
    if _canonical(current_device) != _canonical(plan["device"]):
        return {"status": "stale_plan", "plan_id": plan["plan_id"], "reason": "device_identity_changed", "steps": []}
    try:
        preconditions_ok = callable(precondition_checker) and bool(precondition_checker(plan, context))
    except Exception:
        preconditions_ok = False
    if not preconditions_ok:
        return {"status": "refused", "plan_id": plan["plan_id"], "reason": "preconditions_not_verified", "steps": []}

    results = []
    for index, operation in enumerate(plan["operations"], 1):
        handler = handlers[operation["operation"]]
        try:
            before = handler.read(operation, context)
        except Exception:
            results.append({"index": index, "status": "read_failed_before_apply", "operation": operation["operation"]})
            return {"status": "stale_plan", "plan_id": plan["plan_id"], "steps": results}
        if _canonical(before) != _canonical(operation.get("before")):
            results.append({"index": index, "status": "stale", "expected_before": operation.get("before"), "observed_before": before})
            return {"status": "stale_plan", "plan_id": plan["plan_id"], "steps": results}
        try:
            applied = handler.apply(operation, context)
        except Exception as exc:
            try:
                after = handler.read(operation, context)
            except Exception:
                after = None
            results.append({"index": index, "status": "operation_error", "operation": operation["operation"], "error_type": type(exc).__name__, "observed_after": after})
            return {"status": "partial_failure", "plan_id": plan["plan_id"], "steps": results, "recovery": plan.get("recovery", [])}
        try:
            after = handler.read(operation, context)
            verified = bool(handler.verify(operation, after, context))
        except Exception as exc:
            after = None
            verified = False
            verification_error = type(exc).__name__
        else:
            verification_error = None
        results.append({"index": index, "status": "verified" if verified else "verification_failed", "operation": operation["operation"], "result": applied, "observed_after": after})
        if verification_error:
            results[-1]["verification_error_type"] = verification_error
        if not verified:
            return {"status": "partial_failure", "plan_id": plan["plan_id"], "steps": results, "recovery": plan.get("recovery", [])}
    return {"status": "applied_and_verified", "plan_id": plan["plan_id"], "steps": results}


def unavailable_plan(device: Dict[str, Any], action: str) -> Dict[str, Any]:
    """Produce an honest dry-run when no model/firmware-verified adapter exists."""
    manual_steps = {
        "service-start": ["在 QTS UI 確認套件相依與維護窗口，再由管理者手動啟動；回來後重新執行 qts services。"],
        "service-stop": ["先確認該服務沒有承載使用者工作、同步或備份；本 CLI 不會替你停止服務。"],
        "notification-change": ["由 QTS UI 記錄原值與目標值，確認可用通知管道後手動調整並回讀。"],
        "firmware-update": ["依型號與版本核對 QNAP 官方韌體、備份與維護窗口；本 CLI 不下載或安裝韌體。"],
        "raid-rebuild": ["停止自動化處置，先保存 SMART、RAID 與事件證據並聯絡 QNAP 支援；本 CLI 不執行 rebuild。"],
        "smart-repair": ["保存 SMART/系統告警並評估磁碟更換與備份；本 CLI 不會重設 SMART 或寫入磁碟。"],
    }.get(action, ["尚無此動作的已驗證處理程序。"])
    return create_plan(
        device=device,
        action=action,
        operations=[],
        preconditions=["已重新查詢狀態", "確認第二管理帳號與獨立復原路徑"],
        recovery=["本計畫沒有執行任何操作；請使用 QTS UI／QNAP 支援依型號文件處理。"],
        refusal_reason="沒有通過本機型與韌體實機驗證的 QTS mutation adapter；不產生猜測 API 或 shell 指令。",
        manual_steps=manual_steps,
    )
