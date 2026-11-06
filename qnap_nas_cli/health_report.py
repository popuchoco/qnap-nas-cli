"""Local, redacted health report bundles."""

import hashlib
import json
import os
import re
import shutil
import stat
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Mapping, Optional

from .errors import QtsError
from .redaction import redact_value


_SAFE_CODE = re.compile(r"^[a-z][a-z0-9_.:-]{0,79}$")


def _emission_time(value: Optional[datetime]) -> tuple:
    if value is None:
        value = datetime.now(timezone.utc)
    if value.tzinfo is None or value.utcoffset() is None:
        raise QtsError("emitted_at 必須包含時區")
    value = value.astimezone(timezone.utc).replace(microsecond=0)
    return value.strftime("%Y%m%dT%H%M%SZ"), value.isoformat().replace("+00:00", "Z")


def _target_directory(directory: Path) -> Path:
    requested = Path(directory).expanduser()
    if not requested.is_absolute():
        requested = Path.cwd() / requested
    if not requested.name or requested.name in (".", ".."):
        raise QtsError("report directory 必須是專用目錄")
    parent = requested.parent.resolve()
    target = parent / requested.name
    protected = {Path(target.anchor), Path.cwd().resolve(), Path.home().resolve()}
    if target in protected:
        raise QtsError("拒絕將 report 寫入根目錄、目前目錄或 home 目錄")
    return target


def _check_destination(target: Path) -> Optional[tuple]:
    try:
        info = target.lstat()
    except FileNotFoundError:
        return None
    if not stat.S_ISDIR(info.st_mode):
        raise QtsError("report directory 必須是實際目錄，且不可為 symlink：{}".format(target))
    if not os.access(str(target), os.W_OK | os.X_OK):
        raise QtsError("report directory 不可寫入：{}".format(target))
    try:
        next(target.iterdir())
    except StopIteration:
        return info.st_dev, info.st_ino
    raise QtsError("report directory 必須是新的或空目錄；拒絕覆寫：{}".format(target))


def _write_staged_file(directory: Path, name: str, content: bytes) -> None:
    path = directory / name
    descriptor = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
    except BaseException:
        # fdopen owns the descriptor once entered; close it if setup failed earlier.
        try:
            os.close(descriptor)
        except OSError:
            pass
        raise


def _inline(value: Any) -> str:
    rendered = str(value).replace("\r", " ").replace("\n", " ")
    return rendered.replace("\\", "\\\\").replace("`", "\\`")


def _codes(report: Mapping[str, Any], key: str) -> list:
    values = report.get(key)
    if not isinstance(values, list):
        return []
    result = []
    for item in values:
        if isinstance(item, dict) and isinstance(item.get("code"), (str, int, float)):
            code = str(item["code"])
            if code not in result:
                result.append(code)
    return result


def _summary(report: Mapping[str, Any], emitted_at: str) -> bytes:
    status = report.get("status")
    if status not in ("healthy", "unhealthy", "indeterminate"):
        status = "unknown"
    system = report.get("system")
    if not isinstance(system, dict):
        system = {}
    lines = [
        "# Health report",
        "",
        "- Status: `{}`".format(status),
        "- Emitted at: `{}`".format(emitted_at),
    ]
    device = []
    for label, key in (("model", "model"), ("firmware", "firmware"), ("build", "build")):
        value = system.get(key)
        if value is not None and value != "":
            device.append("{}=`{}`".format(label, _inline(value)))
    if device:
        lines.append("- Device: " + ", ".join(device))
    lines.extend(("", "- Finding codes: {}".format(", ".join("`{}`".format(_inline(code)) for code in _codes(report, "findings")) or "none"),
                  "- Unknown codes: {}".format(", ".join("`{}`".format(_inline(code)) for code in _codes(report, "unknowns")) or "none"), ""))
    return "\n".join(lines).encode("utf-8")


def _json_bytes(value: Any) -> bytes:
    return (json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2) + "\n").encode("utf-8")


def _restore_codes(safe: Dict[str, Any], original: Mapping[str, Any]) -> None:
    """Retain bounded machine codes after generic token scrubbing."""
    for key in ("findings", "unknowns"):
        source_items = original.get(key)
        safe_items = safe.get(key)
        if not isinstance(source_items, list) or not isinstance(safe_items, list):
            continue
        for source, cleaned in zip(source_items, safe_items):
            if not isinstance(source, dict) or not isinstance(cleaned, dict):
                continue
            code = source.get("code")
            if isinstance(code, str) and _SAFE_CODE.fullmatch(code):
                cleaned["code"] = code


def write_health_report(
    directory: Path,
    observation: Mapping[str, Any],
    *,
    emitted_at: Optional[datetime] = None,
) -> Dict[str, Any]:
    """Publish a complete report bundle in a new or empty local directory.

    Files are written into a private staging directory, then the directory is
    atomically renamed into place so a failed write cannot leave partial final
    files. ``emitted_at`` is injectable to make filenames and contents stable
    in offline tests.
    """
    stamp, emitted = _emission_time(emitted_at)
    target = _target_directory(Path(directory))
    target.parent.mkdir(parents=True, exist_ok=True)
    previous = _check_destination(target)

    safe_observation = redact_value(dict(observation))
    if not isinstance(safe_observation, dict):
        raise QtsError("health observation 根節點必須是 object")
    _restore_codes(safe_observation, observation)
    safe_observation["emitted_at"] = emitted
    json_name = "health-{}.json".format(stamp)
    summary_name = "health-{}.md".format(stamp)
    json_content = _json_bytes(safe_observation)
    summary_content = _summary(safe_observation, emitted)
    manifest_content = "".join(
        "{}  {}\n".format(hashlib.sha256(content).hexdigest(), name)
        for name, content in ((json_name, json_content), (summary_name, summary_content))
    ).encode("ascii")
    names = [json_name, summary_name, "manifest.sha256"]

    stage_name = None
    try:
        stage_name = tempfile.mkdtemp(prefix=".{}-tmp-".format(target.name), dir=str(target.parent))
        stage = Path(stage_name)
        _write_staged_file(stage, json_name, json_content)
        _write_staged_file(stage, summary_name, summary_content)
        _write_staged_file(stage, "manifest.sha256", manifest_content)

        current = _check_destination(target)
        if current != previous:
            raise QtsError("report directory 在寫入期間變更；已拒絕發布")
        os.replace(stage_name, str(target))
        stage_name = None
    except OSError as exc:
        raise QtsError("無法寫入 health report：{}".format(exc)) from exc
    finally:
        if stage_name is not None:
            shutil.rmtree(stage_name, ignore_errors=True)

    return {
        "directory": str(target),
        "files": names,
        "status": safe_observation.get("status"),
        "emitted_at": emitted,
    }
