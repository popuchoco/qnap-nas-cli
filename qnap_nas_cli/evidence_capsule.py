"""Atomic, bounded local evidence capsules for incident reports."""

import hashlib
import json
import os
import re
import shutil
import stat
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, List, Mapping, Optional, Tuple

from .errors import QtsError
from .redaction import redact_value


DEFAULT_MAX_BYTES = 100 * 1024 * 1024
MAX_MAX_BYTES = 1024 * 1024 * 1024
MAX_ATTACHMENTS = 100
_SAFE_CODE = re.compile(r"^[a-z][a-z0-9_.:-]{0,79}$")
_SAFE_FAMILY = re.compile(r"^[A-Za-z][A-Za-z0-9 -]{0,39}$")
_CAPSULE_SENSITIVE_KEYS = {"url", "endpoint", "callbackurl", "webhookendpoint"}
_CAPSULE_BEARER_RE = re.compile(r"(?i)(\bBearer\s+)[A-Za-z0-9._~+/=-]+")
_CAPSULE_SECRET_PARAMETER_RE = re.compile(
    r"(?i)(\b(?:token|api[-_]?key|secret(?:[-_]?key)?|access[-_]?key|"
    r"client[-_]?secret|authorization|cookie|webhook[-_]?url)\s*[:=]\s*)[^&\s,;\"']+"
)
_CAPSULE_URL_RE = re.compile(r"(?i)\bhttps?://[^\s<>\"']+")
_SAFE_ASSESSMENTS = {"suspected", "indeterminate"}
_EVIDENCE_SCOPE = (
    "local capsule only; not full forensics; no claim of complete NAS logs or disk image"
)


def _json_bytes(value: Any) -> bytes:
    return (json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2) + "\n").encode("utf-8")


def _redact_capsule_value(value: Any) -> Any:
    """Apply general redaction plus capsule-specific URL and bearer scrubbing."""
    if isinstance(value, Mapping):
        cleaned = {}
        for key, child in value.items():
            normalized_key = re.sub(r"[^a-z0-9]", "", str(key).lower())
            generally_sensitive = redact_value({key: None}).get(key) == "REDACTED"
            if normalized_key in _CAPSULE_SENSITIVE_KEYS or generally_sensitive:
                cleaned[key] = "REDACTED"
            else:
                cleaned[key] = _redact_capsule_value(child)
        return cleaned
    if isinstance(value, list):
        return [_redact_capsule_value(child) for child in value]
    if isinstance(value, str):
        value = _CAPSULE_BEARER_RE.sub(r"\1REDACTED", value)
        value = _CAPSULE_URL_RE.sub("REDACTED_URL", value)
        value = _CAPSULE_SECRET_PARAMETER_RE.sub(r"\1REDACTED", value)
    return redact_value(value)


def _emission_time(value: Optional[datetime]) -> str:
    if value is None:
        value = datetime.now(timezone.utc)
    if value.tzinfo is None or value.utcoffset() is None:
        raise QtsError("emitted_at 必須包含時區")
    return value.astimezone(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _target_directory(directory: Path) -> Path:
    requested = Path(directory).expanduser()
    if requested.name in ("", ".", ".."):
        raise QtsError("evidence directory 必須是專用目錄")
    if not requested.is_absolute():
        requested = Path.cwd() / requested
    parent = requested.parent.resolve()
    target = parent / requested.name
    protected = {Path(target.anchor), Path.cwd().resolve(), Path.home().resolve()}
    if target in protected:
        raise QtsError("拒絕將 evidence 寫入根目錄、目前目錄或 home 目錄")
    return target


def _check_destination(target: Path) -> Optional[Tuple[int, int]]:
    try:
        info = target.lstat()
    except FileNotFoundError:
        return None
    if not stat.S_ISDIR(info.st_mode):
        raise QtsError("evidence directory 必須是實際目錄，且不可為 symlink：{}".format(target))
    if not os.access(str(target), os.W_OK | os.X_OK):
        raise QtsError("evidence directory 不可寫入：{}".format(target))
    try:
        next(target.iterdir())
    except StopIteration:
        return info.st_dev, info.st_ino
    raise FileExistsError("evidence directory 必須是新的或空目錄；拒絕覆寫：{}".format(target))


def _write_staged_file(directory: Path, name: str, content: bytes) -> None:
    path = directory / name
    descriptor = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
    except BaseException:
        try:
            os.close(descriptor)
        except OSError:
            pass
        raise


def _restore_codes(safe: Any, original: Any) -> None:
    """Restore bounded machine codes and exact IOC examples after recursive redaction."""
    if isinstance(original, Mapping) and isinstance(safe, dict):
        for key, original_value in original.items():
            safe_value = safe.get(key)
            if key in ("findings", "unknowns", "indicators") and isinstance(original_value, list) and isinstance(safe_value, list):
                for source, cleaned in zip(original_value, safe_value):
                    if not isinstance(source, Mapping) or not isinstance(cleaned, dict):
                        continue
                    code = source.get("code")
                    if isinstance(code, str) and _SAFE_CODE.fullmatch(code):
                        cleaned["code"] = code
                    if key == "indicators":
                        examples = source.get("examples")
                        if isinstance(examples, list):
                            # Examples are the exact-path allowlist used by sample export.
                            cleaned_examples = cleaned.get("examples")
                            if isinstance(cleaned_examples, list):
                                cleaned["examples"] = [
                                    original_example if isinstance(original_example, str) else cleaned_example
                                    for original_example, cleaned_example in zip(examples, cleaned_examples)
                                ]
                    _restore_codes(cleaned, source)
            else:
                _restore_codes(safe_value, original_value)
    elif isinstance(original, list) and isinstance(safe, list):
        for cleaned, source in zip(safe, original):
            _restore_codes(cleaned, source)


def _walk_code_values(report: Mapping[str, Any], field: str) -> List[str]:
    found = []

    def visit(value: Any) -> None:
        if isinstance(value, Mapping):
            for key, child in value.items():
                if key == field and isinstance(child, list):
                    for item in child:
                        if isinstance(item, Mapping):
                            code = item.get("code")
                            if isinstance(code, str) and _SAFE_CODE.fullmatch(code) and code not in found:
                                found.append(code)
                visit(child)
        elif isinstance(value, list):
            for child in value:
                visit(child)

    visit(report)
    return found


def _summary(report: Mapping[str, Any], emitted_at: str) -> bytes:
    scan = report.get("ransomware_scan")
    if not isinstance(scan, Mapping):
        scan = {}
    assessment = report.get("assessment", scan.get("assessment", "unknown"))
    if assessment not in _SAFE_ASSESSMENTS:
        assessment = "unknown"
    indicators = scan.get("indicators")
    if not isinstance(indicators, list):
        indicators = []
    codes = []
    families = []
    for indicator in indicators:
        if not isinstance(indicator, Mapping):
            continue
        code = indicator.get("code")
        family = indicator.get("family")
        if isinstance(code, str) and _SAFE_CODE.fullmatch(code) and code not in codes:
            codes.append(code)
        if isinstance(family, str) and _SAFE_FAMILY.fullmatch(family) and family not in families:
            families.append(family)
    coverage = scan.get("coverage")
    if not isinstance(coverage, Mapping):
        coverage = {}
    coverage_flags = []
    for name in ("truncated", "depth_limited"):
        value = coverage.get(name)
        coverage_flags.append("{}={}".format(name, "true" if value is True else "false" if value is False else "unknown"))
    lines = [
        "# Incident evidence capsule",
        "",
        "- Assessment: `{}`".format(assessment),
        "- Emitted at: `{}`".format(emitted_at),
        "- Coverage flags: `{}`".format(", ".join(coverage_flags)),
        "- Indicator families: {}".format(", ".join("`{}`".format(value) for value in families) or "none"),
        "- Indicator codes: {}".format(", ".join("`{}`".format(value) for value in codes) or "none"),
        "- Finding codes: {}".format(", ".join("`{}`".format(value) for value in _walk_code_values(report, "findings")) or "none"),
        "- Unknown codes: {}".format(", ".join("`{}`".format(value) for value in _walk_code_values(report, "unknowns")) or "none"),
        "",
    ]
    return "\n".join(lines).encode("utf-8")


def _candidate_examples(report: Mapping[str, Any]) -> List[str]:
    scan = report.get("ransomware_scan")
    indicators = scan.get("indicators") if isinstance(scan, Mapping) else None
    result = []
    if isinstance(indicators, list):
        for indicator in indicators:
            examples = indicator.get("examples") if isinstance(indicator, Mapping) else None
            if isinstance(examples, list):
                result.extend(value for value in examples if isinstance(value, str))
    return result


def _validate_candidate_path(candidate: str) -> Tuple[str, str]:
    if (
        not candidate.startswith("/")
        or "\\" in candidate
        or any(ord(character) < 0x20 or ord(character) == 0x7f for character in candidate)
    ):
        raise QtsError("candidate path 必須是安全的絕對 File Station 路徑")
    parts = candidate.split("/")
    if len(parts) < 3 or parts[0] != "" or any(part in ("", ".", "..") for part in parts[1:]):
        raise QtsError("candidate path 不可包含空白或 dot segment 路徑元件")
    return "/" + "/".join(parts[1:-1]), parts[-1]


def validate_attachments(
    report: Mapping[str, Any], candidates: Iterable[str], max_bytes: int = DEFAULT_MAX_BYTES,
) -> List[str]:
    if type(max_bytes) is not int or not 1 <= max_bytes <= MAX_MAX_BYTES:
        raise QtsError("max-bytes 必須介於 1 byte 與 1 GiB")
    if isinstance(candidates, str):
        candidates = [candidates]
    selected = []
    for candidate in candidates:
        selected.append(candidate)
        if len(selected) > MAX_ATTACHMENTS:
            raise QtsError("candidate attachments 最多可指定 {} 個".format(MAX_ATTACHMENTS))
    examples = _candidate_examples(report)
    for candidate in selected:
        if not isinstance(candidate, str) or candidate not in examples:
            raise QtsError("只能匯出本 report 列出的 indicator 範例路徑")
        _validate_candidate_path(candidate)
    return selected


def _hash_file(path: Path, max_bytes: int) -> Tuple[int, str]:
    if not hasattr(os, "O_NOFOLLOW") or not hasattr(os, "O_NONBLOCK"):
        raise QtsError("平台不支援安全檢查 sample symlink 與 non-regular file")
    flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK
    descriptor = os.open(str(path), flags)
    size = 0
    digest = hashlib.sha256()
    try:
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode):
            raise QtsError("sample export 必須是一般檔案")
        with os.fdopen(descriptor, "rb") as stream:
            while True:
                chunk = stream.read(1024 * 1024)
                if not chunk:
                    break
                size += len(chunk)
                if size > max_bytes:
                    raise QtsError("sample exports 超過 max-bytes 上限 {} bytes".format(max_bytes))
                digest.update(chunk)
    except BaseException:
        try:
            os.close(descriptor)
        except OSError:
            pass
        raise
    return size, digest.hexdigest()


def write_evidence_capsule(
    directory: Path,
    report: Mapping[str, Any],
    *,
    attach_candidates: Iterable[str] = (),
    max_bytes: int = DEFAULT_MAX_BYTES,
    sample_exporter: Optional[Callable[[str, Path, int], Any]] = None,
    rescue_manifest: bool = False,
    emitted_at: Optional[datetime] = None,
) -> Dict[str, Any]:
    """Write a redacted incident capsule and publish it with one directory rename.

    ``sample_exporter`` is called inside the private staging directory with the
    exact report-listed path, destination, and remaining aggregate byte budget.
    """
    if not isinstance(report, Mapping):
        raise QtsError("incident report 根節點必須是 object")
    emitted = _emission_time(emitted_at)
    candidates = validate_attachments(report, attach_candidates, max_bytes)
    if candidates and sample_exporter is None:
        raise QtsError("匯出 candidate samples 需要 read-only sample exporter")
    if rescue_manifest and len(candidates) != 1:
        raise QtsError("rescue capsule 必須剛好匯出一個 candidate")

    target = _target_directory(Path(directory))
    target.parent.mkdir(parents=True, exist_ok=True)
    previous = _check_destination(target)

    safe_report = _redact_capsule_value(dict(report))
    if not isinstance(safe_report, dict):
        raise QtsError("incident report 根節點必須是 object")
    _restore_codes(safe_report, report)
    safe_report["emitted_at"] = emitted
    report_bytes = _json_bytes(safe_report)
    summary_bytes = _summary(safe_report, emitted)

    stage_name = None
    try:
        stage_name = tempfile.mkdtemp(prefix=".{}-tmp-".format(target.name), dir=str(target.parent))
        stage = Path(stage_name)
        _write_staged_file(stage, "incident.json", report_bytes)
        _write_staged_file(stage, "summary.md", summary_bytes)
        file_entries = []
        for name, content in (("incident.json", report_bytes), ("summary.md", summary_bytes)):
            file_entries.append({"name": name, "size_bytes": len(content), "sha256": hashlib.sha256(content).hexdigest()})

        samples = []
        total_bytes = 0
        if candidates:
            samples_dir = stage / "samples"
            samples_dir.mkdir(mode=0o700)
            for index, candidate in enumerate(candidates, 1):
                remaining = max_bytes - total_bytes
                if remaining < 1:
                    raise QtsError("sample exports 已達 max-bytes 上限 {} bytes".format(max_bytes))
                relative_name = "samples/sample-{:03d}.bin".format(index)
                sample_path = stage / relative_name
                sample_exporter(candidate, sample_path, remaining)
                size, digest = _hash_file(sample_path, remaining)
                os.chmod(str(sample_path), 0o600)
                total_bytes += size
                sample = {
                    "source": candidate,
                    "name": relative_name,
                    "size_bytes": size,
                    "sha256": digest,
                    "max_bytes": max_bytes,
                }
                samples.append(sample)
                file_entries.append({"name": relative_name, "size_bytes": size, "sha256": digest})

        if rescue_manifest:
            sample = samples[0]
            rescue_value = {
                "status": "sample_exported_not_restored",
                "actions_applied": [],
                "source": candidates[0],
                "sample": {
                    "path": str(target / sample["name"]),
                    "size_bytes": sample["size_bytes"],
                    "sha256": sample["sha256"],
                    "max_bytes": max_bytes,
                },
                "capsule_manifest": "manifest.json",
                "note": "唯讀匯出到新本機目錄；這不是 NAS 復原，也不會執行或解密樣本。",
            }
            rescue_bytes = _json_bytes(rescue_value)
            _write_staged_file(stage, "rescue-manifest.json", rescue_bytes)
            file_entries.append({
                "name": "rescue-manifest.json", "size_bytes": len(rescue_bytes),
                "sha256": hashlib.sha256(rescue_bytes).hexdigest(),
            })

        manifest = {
            "format_version": 2,
            "created_at": emitted,
            "emitted_at": emitted,
            "files": file_entries,
            "evidence_scope": _EVIDENCE_SCOPE,
        }
        manifest_bytes = _json_bytes(manifest)
        _write_staged_file(stage, "manifest.json", manifest_bytes)

        current = _check_destination(target)
        if current != previous:
            raise QtsError("evidence directory 在寫入期間變更；已拒絕發布")
        os.replace(stage_name, str(target))
        stage_name = None
    except (QtsError, FileExistsError):
        raise
    except OSError as exc:
        raise QtsError("無法寫入 evidence capsule：{}".format(exc)) from exc
    finally:
        if stage_name is not None:
            shutil.rmtree(stage_name, ignore_errors=True)

    receipt = dict(manifest)
    receipt["directory"] = str(target)
    receipt["samples"] = samples
    return receipt
