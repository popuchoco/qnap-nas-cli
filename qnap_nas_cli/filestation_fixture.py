"""Bounded, redacted File Station fixture capture and offline replay."""

import json
import re
import string
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from .errors import CompatibilityError, QtsError
from .incident import DEFAULT_MAX_ITEMS, FILE_STATION_PATH, MAX_FOLDERS, _rows, _share_path
from .redaction import redact_filestation_value


PAGE_SIZE = 200
# Capture at most the incident scanner's 5,000-folder bound and 10,000 items.
# Each query is only a root page (depth zero, below the scanner's depth 12).
MAX_CAPTURE_SHARES = MAX_FOLDERS
MAX_CAPTURE_ITEMS = DEFAULT_MAX_ITEMS
_UNREDACTED_PATTERNS = (
    re.compile(r"(?<![\w:])(?:\d{1,3}\.){3}\d{1,3}(?![\w:])"),
    re.compile(r"(?i)(?<![0-9a-f])(?:[0-9a-f]{2}[:-]){5}[0-9a-f]{2}(?![0-9a-f])"),
    re.compile(r"(?i)\bsid\s*="),
    re.compile(r"(?i)\bqtoken\s*="),
)


def _placeholder(index: int) -> str:
    """Return stable spreadsheet-style names: ShareA, ShareB, ..., ShareAA."""
    letters = ""
    while index:
        index, remainder = divmod(index - 1, 26)
        letters = string.ascii_uppercase[remainder] + letters
    return "Share" + letters


def _share_mappings(rows: List[Dict[str, Any]]) -> Tuple[Dict[str, str], Dict[str, str], List[Tuple[str, str]]]:
    path_mapping: Dict[str, str] = {}
    name_candidates: Dict[str, List[str]] = {}
    captured: List[Tuple[str, str]] = []
    seen_paths = set()
    for index, row in enumerate(rows, 1):
        placeholder = _placeholder(index)
        path = _share_path(row)
        raw_id = row.get("id")
        if not path and isinstance(raw_id, str) and raw_id.startswith(("/", "\\")):
            path = raw_id.replace("\\", "/")
        display = row.get("text")
        if not isinstance(display, str) or not display:
            display = path.rstrip("/").split("/")[-1] if path else None
        if isinstance(display, str) and display:
            name_candidates.setdefault(display, []).append(placeholder)
        if path:
            if path not in path_mapping:
                path_mapping[path] = "/" + placeholder
            if path not in seen_paths:
                captured.append((path, placeholder))
                seen_paths.add(path)
    name_mapping = {name: choices[0] for name, choices in name_candidates.items()}
    return path_mapping, name_mapping, captured


def _total(payload: Any) -> Optional[int]:
    if not isinstance(payload, dict):
        return None
    value = payload.get("real_total", payload.get("total"))
    try:
        total = int(value)
    except (TypeError, ValueError):
        return None
    return total if total >= 0 else None


def _write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def capture_filestation(client: Any, directory: Path) -> Dict[str, Any]:
    """Capture share roots and bounded first pages using read-only JSON calls."""
    directory = Path(directory)
    directory.mkdir(parents=True, exist_ok=True)
    tree_payload = client.get_json(FILE_STATION_PATH, {
        "func": "get_tree", "node": "share_root", "is_iso": "0",
        "hidden_file": "1", "recycle": "0", "check_acl": "1",
    })
    shares = _rows(tree_payload)
    path_mapping, name_mapping, share_paths = _share_mappings(shares)
    mapping = dict(path_mapping)
    mapping.update(name_mapping)
    _write_json(directory / "share_root.json", redact_filestation_value(tree_payload, mapping))

    pages = []
    items_captured = 0
    truncated = len(share_paths) > MAX_CAPTURE_SHARES
    for path, placeholder in share_paths[:MAX_CAPTURE_SHARES]:
        if items_captured >= MAX_CAPTURE_ITEMS:
            truncated = True
            break
        limit = min(PAGE_SIZE, MAX_CAPTURE_ITEMS - items_captured)
        payload = client.get_json(FILE_STATION_PATH, {
            "func": "get_list", "path": path, "dir": "ASC", "limit": str(limit),
            "sort": "filename", "start": "0", "list_mode": "all",
            "hidden_file": "1", "is_iso": "0", "v": "1",
        })
        entries = _rows(payload, "datas")
        bounded_entries = entries[:limit]
        safe_name = "list__{}__0.json".format(placeholder)
        if isinstance(payload, dict):
            bounded_payload = dict(payload)
            if "datas" in payload:
                bounded_payload["datas"] = bounded_entries
            elif "data" in payload:
                bounded_payload["data"] = bounded_entries
            else:
                bounded_payload["datas"] = bounded_entries
        else:
            bounded_payload = bounded_entries
        _write_json(directory / safe_name, redact_filestation_value(bounded_payload, mapping))
        total = _total(payload)
        items_captured += len(bounded_entries)
        page_truncated = len(entries) > len(bounded_entries) or total is not None and len(bounded_entries) < total
        truncated = truncated or page_truncated
        pages.append({
            "share": placeholder,
            "path": "/" + placeholder,
            "start": 0,
            "limit": limit,
            "total": total,
            "returned": len(bounded_entries),
            "file": safe_name,
            "truncated": page_truncated,
        })

    manifest = {
        "format_version": 1,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "redacted": True,
        "provenance_status": "capture_pending_human_review",
        "limits": {"max_shares": MAX_CAPTURE_SHARES, "max_items": MAX_CAPTURE_ITEMS, "page_size": PAGE_SIZE, "max_depth": 0},
        "shares_visible": len(shares),
        "shares_captured": len(pages),
        "items_captured": items_captured,
        "truncated": truncated,
        "pages": pages,
    }
    _write_json(directory / "manifest.json", manifest)
    return manifest


def validate_filestation_dump(directory: Path) -> Dict[str, Any]:
    """Validate File Station fixture shape and scan serialized JSON for leaks."""
    directory = Path(directory)
    errors = []
    root_path = directory / "share_root.json"
    try:
        share_root = json.loads(root_path.read_text(encoding="utf-8"))
        shares = _rows(share_root)
    except (OSError, ValueError, CompatibilityError, QtsError) as exc:
        shares = []
        errors.append("share_root.json: {}".format(exc))

    try:
        manifest = json.loads((directory / "manifest.json").read_text(encoding="utf-8"))
        pages = manifest.get("pages") if isinstance(manifest, dict) else None
        if not isinstance(pages, list):
            raise ValueError("manifest pages must be a list")
    except (OSError, ValueError) as exc:
        pages = []
        errors.append("manifest.json: {}".format(exc))

    parsed_lists = 0
    seen_list_files = set()
    for page in pages:
        if not isinstance(page, dict) or not isinstance(page.get("file"), str):
            errors.append("manifest page entry is invalid")
            continue
        filename = page["file"]
        if Path(filename).name != filename or not filename.endswith(".json"):
            errors.append("manifest page filename is unsafe")
            continue
        seen_list_files.add(filename)
        try:
            payload = json.loads((directory / filename).read_text(encoding="utf-8"))
            _rows(payload, "datas")
            parsed_lists += 1
        except (OSError, ValueError, CompatibilityError, QtsError) as exc:
            errors.append("{}: {}".format(filename, exc))

    if directory.is_dir():
        for candidate in sorted(directory.glob("list__*.json")):
            if candidate.name in seen_list_files:
                continue
            try:
                _rows(json.loads(candidate.read_text(encoding="utf-8")), "datas")
                parsed_lists += 1
            except (OSError, ValueError, CompatibilityError, QtsError) as exc:
                errors.append("{}: {}".format(candidate.name, exc))

    pattern_hits = []
    if directory.is_dir():
        for candidate in sorted(directory.rglob("*.json")):
            try:
                raw = candidate.read_text(encoding="utf-8")
            except (OSError, UnicodeError) as exc:
                errors.append("{}: {}".format(candidate.name, exc))
                continue
            for pattern in _UNREDACTED_PATTERNS:
                if pattern.search(raw):
                    pattern_hits.append(candidate.name)
                    break
    if pattern_hits:
        errors.append("unredacted sensitive pattern in: {}".format(", ".join(sorted(set(pattern_hits)))))
    return {
        "valid": not errors,
        "errors": errors,
        "shares": len(shares),
        "list_files": parsed_lists,
        "pattern_scan": "failed" if pattern_hits else "passed",
    }


class FileStationFixtureClient:
    """Serve captured File Station JSON to the existing incident scanner."""

    def __init__(self, directory: Path):
        directory = Path(directory)
        self.directory = directory / "filestation" if (directory / "filestation").is_dir() else directory
        self.calls = []

    def _read(self, filename: str) -> Any:
        if not isinstance(filename, str) or Path(filename).name != filename:
            raise QtsError("File Station fixture filename 無效")
        try:
            return json.loads((self.directory / filename).read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            raise QtsError("File Station fixture 無法讀取：{}".format(filename)) from exc

    def get_json(self, path: str, params: Dict[str, Any]) -> Any:
        self.calls.append({"path": path, **params})
        if path != FILE_STATION_PATH:
            raise QtsError("File Station fixture 不支援此 endpoint")
        if params.get("func") == "get_tree" and params.get("node") == "share_root":
            return self._read("share_root.json")
        if params.get("func") == "get_list":
            try:
                start = int(params.get("start", 0))
            except (TypeError, ValueError) as exc:
                raise QtsError("File Station fixture start 無效") from exc
            try:
                manifest = self._read("manifest.json")
            except QtsError:
                raise
            if not isinstance(manifest, dict) or not isinstance(manifest.get("pages"), list):
                raise QtsError("File Station fixture manifest 格式無效")
            for page in manifest.get("pages", []):
                if isinstance(page, dict) and page.get("path") == params.get("path") and page.get("start") == start:
                    return self._read(page["file"])
            raise QtsError("File Station fixture 沒有此路徑／頁面：{} start={}".format(params.get("path"), start))
        raise QtsError("File Station fixture 不支援此查詢")
