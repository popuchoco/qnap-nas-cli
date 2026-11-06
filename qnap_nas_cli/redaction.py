import json
import re
import xml.etree.ElementTree as ET
from typing import Any, Mapping, Optional


SENSITIVE_TAGS = {"serial_number", "hostname", "server_name", "serial", "serial_no"}
NETWORK_TAGS = {
    "dns1", "dns2", "dns_list", "dns_server",
}

_SENSITIVE_JSON_KEYS = {
    "sid", "qtoken", "authsid", "username", "user", "password", "pwd",
    "hostname", "host", "server", "servername", "serial", "serialno", "mac",
    "ip", "email", "phone", "cookie", "token", "securitycode", "passwd",
    "authorization", "account", "owner", "realname", "session", "sessionid",
    "deviceid", "uuid", "credential", "credentials", "passphrase",
}
_IPV4_RE = re.compile(r"(?<![\w:])(?:\d{1,3}\.){3}\d{1,3}(?![\w:])")
_MAC_RE = re.compile(r"(?i)(?<![0-9a-f])(?:[0-9a-f]{2}[:-]){5}[0-9a-f]{2}(?![0-9a-f])")
_EMAIL_RE = re.compile(r"(?i)\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b")
_SID_PARAMETER_RE = re.compile(r"(?i)(\b(?:sid|qtoken)\s*=\s*)[^&\s,;\"']+")
_SID_TOKEN_RE = re.compile(r"(?<![A-Za-z0-9])[A-Za-z0-9_-]{24,}(?![A-Za-z0-9])")
_LONG_NUMERIC_ID_RE = re.compile(r"(?<!\d)\d{8,}(?!\d)")


def _normalized_key(key: Any) -> str:
    return re.sub(r"[^a-z0-9]", "", str(key).lower())


def _sensitive_json_key(key: Any) -> bool:
    normalized = _normalized_key(key)
    return (
        normalized in _SENSITIVE_JSON_KEYS
        or normalized.startswith("serial")
        or re.search(r"ip\d*$", normalized) is not None
        or "ipaddress" in normalized
        or re.search(r"mac\d*$", normalized) is not None
        or "macaddress" in normalized
        or "email" in normalized
        or "phone" in normalized
        or "cookie" in normalized
        or "token" in normalized
        or normalized.endswith("passwd")
    )


def _scrub_string(value: str, redact_sid_token: bool = True) -> str:
    value = _IPV4_RE.sub("x.x.x.x", value)
    value = _MAC_RE.sub("xx:xx:xx:xx:xx:xx", value)
    value = _EMAIL_RE.sub("REDACTED", value)
    value = _SID_PARAMETER_RE.sub(r"\1REDACTED", value)
    if redact_sid_token:
        value = _SID_TOKEN_RE.sub("REDACTED", value)
    return value


def _rewrite_share_reference(value: str, share_mapping: Mapping[str, str]) -> str:
    """Rewrite share names and path prefixes before the originals are persisted."""
    if not share_mapping:
        return value
    path_mapping = sorted(
        ((original, replacement) for original, replacement in share_mapping.items() if original.startswith("/")),
        key=lambda pair: len(pair[0]), reverse=True,
    )
    for original, replacement in path_mapping:
        if value == original or value.startswith(original.rstrip("/") + "/"):
            value = replacement.rstrip("/") + value[len(original.rstrip("/")):]
            break
    for original, replacement in share_mapping.items():
        if not original.startswith("/") and value == original:
            value = replacement
            break
    return value


def _sanitize_path_components(value: str) -> str:
    if not value.startswith(("/", "\\")):
        return value
    parts = re.split(r"([/\\])", value)
    for index in range(0, len(parts), 2):
        component = parts[index]
        if _EMAIL_RE.search(component) or _LONG_NUMERIC_ID_RE.search(component):
            parts[index] = "REDACTED_NAME"
        else:
            parts[index] = _scrub_string(component)
    return "".join(parts)


def _is_sensitive_network_tag(tag: str) -> bool:
    return (
        tag in NETWORK_TAGS
        or re.fullmatch(r"eth_(?:ip|mask|mac)\d+", tag) is not None
        or re.fullmatch(r"eth_ipv6_(?:ip|info)\d+", tag) is not None
    )


def redact_xml(raw: bytes) -> str:
    try:
        root = ET.fromstring(raw)
    except ET.ParseError:
        return "[unparseable response omitted]"
    for node in root.iter():
        lowered = node.tag.lower()
        if lowered in SENSITIVE_TAGS:
            node.text = "REDACTED"
        elif _is_sensitive_network_tag(lowered):
            node.text = "x.x.x.x"
    return ET.tostring(root, encoding="unicode")


def redact_value(value: Any) -> Any:
    if isinstance(value, dict):
        return {key: ("REDACTED" if _sensitive_json_key(key) or str(key).lower() in SENSITIVE_TAGS else redact_value(item)) for key, item in value.items()}
    if isinstance(value, list):
        return [redact_value(item) for item in value]
    if isinstance(value, str):
        return _scrub_string(value)
    return value


def redact_filestation_value(value: Any, share_mapping: Optional[Mapping[str, str]] = None, key: Optional[str] = None) -> Any:
    """Redact File Station JSON while retaining replayable placeholder share paths.

    ``share_mapping`` is an in-memory map containing original share paths to
    placeholder paths and (where unambiguous) display names to placeholders.
    Callers must not persist the mapping itself.
    """
    mapping = share_mapping or {}
    if isinstance(value, dict):
        result = {}
        for child_key, item in value.items():
            if _sensitive_json_key(child_key) or str(child_key).lower() in SENSITIVE_TAGS:
                result[child_key] = "REDACTED"
            else:
                result[child_key] = redact_filestation_value(item, mapping, str(child_key))
        return result
    if isinstance(value, list):
        return [redact_filestation_value(item, mapping, key) for item in value]
    if not isinstance(value, str):
        return value

    rewritten = _rewrite_share_reference(value, mapping)
    normalized_key = _normalized_key(key or "")
    if normalized_key == "filename" and (_EMAIL_RE.search(rewritten) or _LONG_NUMERIC_ID_RE.search(rewritten)):
        return "REDACTED_NAME"
    if normalized_key in ("id", "path", "sourcepath"):
        rewritten = _sanitize_path_components(rewritten)
    return _scrub_string(rewritten, redact_sid_token=normalized_key != "filename")


def safe_json(value: Any) -> str:
    return json.dumps(redact_value(value), ensure_ascii=False, indent=2)
