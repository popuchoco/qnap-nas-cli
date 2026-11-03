import json
import re
import xml.etree.ElementTree as ET
from typing import Any


SENSITIVE_TAGS = {"serial_number", "hostname", "server_name", "serial", "serial_no"}


def redact_xml(raw: bytes) -> str:
    try:
        root = ET.fromstring(raw)
    except ET.ParseError:
        return "[unparseable response omitted]"
    for node in root.iter():
        lowered = node.tag.lower()
        if lowered in SENSITIVE_TAGS:
            node.text = "REDACTED"
        elif lowered.startswith("eth_ip") or lowered in ("dns1", "dns2", "dns_list"):
            node.text = "x.x.x.x"
    return ET.tostring(root, encoding="unicode")


def redact_value(value: Any) -> Any:
    if isinstance(value, dict):
        return {key: ("REDACTED" if key.lower() in SENSITIVE_TAGS else redact_value(item)) for key, item in value.items()}
    if isinstance(value, list):
        return [redact_value(item) for item in value]
    if isinstance(value, str):
        value = re.sub(r"(?<![\w:])(?:\d{1,3}\.){3}\d{1,3}(?![\w:])", "x.x.x.x", value)
        return value
    return value


def safe_json(value: Any) -> str:
    return json.dumps(redact_value(value), ensure_ascii=False, indent=2)
