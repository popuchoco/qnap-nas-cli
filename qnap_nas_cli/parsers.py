import re
import xml.etree.ElementTree as ET
from typing import Any, Dict, List, Optional


def text(root: ET.Element, tag: str) -> Optional[str]:
    node = root.find(".//{}".format(tag))
    if node is None:
        return None
    value = (node.text or "").strip()
    return value if value else None


def number(value: Optional[str]) -> Optional[float]:
    if value is None:
        return None
    match = re.search(r"-?\d+(?:\.\d+)?", value.replace(",", ""))
    return float(match.group(0)) if match else None


def integer(value: Optional[str]) -> Optional[int]:
    parsed = number(value)
    return None if parsed is None else int(parsed)


def parse_uptime(root: ET.Element) -> Optional[Dict[str, Any]]:
    days = integer(text(root, "uptime_day"))
    if days is None:
        return None
    hours = integer(text(root, "uptime_hour")) or 0
    minutes = integer(text(root, "uptime_min")) or 0
    seconds = integer(text(root, "uptime_sec")) or 0
    return {
        "display": "{}d {}h {}m".format(days, hours, minutes),
        "total_seconds": days * 86400 + hours * 3600 + minutes * 60 + seconds,
    }


def parse_system(root: ET.Element) -> Dict[str, Any]:
    total = integer(text(root, "total_memory"))
    free = integer(text(root, "free_memory"))
    return {
        "hostname": text(root, "hostname") or text(root, "server_name"),
        "model": text(root, "modelName") or text(root, "model"),
        "firmware": text(root, "version"),
        "build": text(root, "build"),
        "serial_number": text(root, "serial_number"),
        "cpu_usage_pct": number(text(root, "cpu_usage")),
        "memory_total_mb": total,
        "memory_free_mb": free,
        "memory_used_mb": total - free if total is not None and free is not None and total >= free else None,
        "temperature_c": number(text(root, "sys_tempc")),
        "uptime": parse_uptime(root),
    }


def parse_network(root: ET.Element) -> Dict[str, Any]:
    count = integer(text(root, "nic_cnt")) or 0
    adapters = []  # type: List[Dict[str, Any]]
    for index in range(1, count + 1):
        status_code = integer(text(root, "eth_status{}".format(index)))
        adapters.append({
            "interface": text(root, "ifname{}".format(index)) or "eth{}".format(index - 1),
            "name": text(root, "dname{}".format(index)) or "Adapter {}".format(index),
            "status": "up" if status_code == 1 else "down" if status_code == 0 else "unknown",
            "ip": text(root, "eth_ip{}".format(index)),
            "mask": text(root, "eth_mask{}".format(index)),
            "mac": text(root, "eth_mac{}".format(index)),
            "speed_mbps": integer(text(root, "eth_max_speed{}".format(index))),
        })
    dns_nodes = [node for node in root.iter() if node.tag.lower() in ("dns_list", "dns1", "dns2", "dns_server")]
    dns = []
    for node in dns_nodes:
        for value in node.itertext():
            cleaned = value.strip()
            if cleaned and cleaned not in dns:
                dns.append(cleaned)
    dns_status = "observed" if dns else "unknown_format" if dns_nodes else "not_reported"
    return {"adapters": adapters, "dns": dns, "dns_status": dns_status}


VOLUME_STATUS = {-7: "ready", -5: "degraded", -4: "unmounted", -3: "not_ready", 0: "unknown"}
KNOWN_BAD_VOLUME_STATUS = {-5, -4, -3}


def parse_storage(root: ET.Element) -> Dict[str, Any]:
    volumes = []
    disks = []
    for node in root.iter():
        tag = node.tag.lower()
        if tag in ("volume", "vol_info") or ("volume" in tag and list(node)):
            status_code = integer(text(node, "vol_status"))
            label = text(node, "volume_name") or text(node, "vol_label") or text(node, "name")
            if label or status_code is not None:
                if status_code == -7:
                    semantics = "known_good"
                elif status_code in KNOWN_BAD_VOLUME_STATUS:
                    semantics = "known_bad"
                else:
                    semantics = "unknown"
                volumes.append({
                    "name": label,
                    "status": VOLUME_STATUS.get(status_code, "unknown"),
                    "status_code": status_code,
                    "status_semantics": semantics,
                })
        if tag in ("disk", "disk_info") or (tag.startswith("disk") and list(node)):
            disk_no = text(node, "disk_no") or text(node, "disk_number") or text(node, "port_no")
            model = text(node, "model") or text(node, "model_name")
            if disk_no or model:
                disks.append({
                    "disk": disk_no,
                    "model": model,
                    "serial": text(node, "serial_no") or text(node, "serial"),
                    "temperature_c": number(text(node, "temperature") or text(node, "temp")),
                    "smart": text(node, "smart") or text(node, "smart_status") or text(node, "status"),
                })
    warnings = []
    if not volumes:
        warnings.append("no_volume_records")
    if not disks:
        warnings.append("no_disk_records")
    return {"volumes": _unique(volumes), "disks": _unique(disks), "parser_warnings": warnings}


def _unique(items: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    result = []
    seen = set()
    for item in items:
        key = tuple(sorted(item.items()))
        if key not in seen:
            seen.add(key)
            result.append(item)
    return result
