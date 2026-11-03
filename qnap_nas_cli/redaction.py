import json
import re
import xml.etree.ElementTree as ET
from typing import Any


SENSITIVE_TAGS = {"serial_number", "hostname", "server_name", "serial", "serial_no"}
NETWORK_TAGS = {
    "dns1", "dns2", "dns_list", "dns_server",
}


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
        return {key: ("REDACTED" if key.lower() in SENSITIVE_TAGS else redact_value(item)) for key, item in value.items()}
    if isinstance(value, list):
        return [redact_value(item) for item in value]
    if isinstance(value, str):
        value = re.sub(r"(?<![\w:])(?:\d{1,3}\.){3}\d{1,3}(?![\w:])", "x.x.x.x", value)
        value = re.sub(r"(?i)(?<![0-9a-f])(?:[0-9a-f]{2}[:-]){5}[0-9a-f]{2}(?![0-9a-f])", "xx:xx:xx:xx:xx:xx", value)
        return value
    return value


def safe_json(value: Any) -> str:
    return json.dumps(redact_value(value), ensure_ascii=False, indent=2)
