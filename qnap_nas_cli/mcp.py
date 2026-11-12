import json
import os
import sys
from typing import Any, Callable, Dict

from . import __version__
from .commands import disks_ssh, health, incident_report, legacy_ransomware_audit, network, plex2shell_audit, raid, services, smart_details, storage, sysinfo, tailscale
from .config import Config, password_from_environment
from .client import QtsClient
from .errors import QtsError
from .incident import DEFAULT_MAX_ITEMS, MAX_MAX_ITEMS
from .security import IOC_FIELDS
from .legacy_ransomware import QSNATCH_CONTROLS


TOOLS = [
    {"name": "qts_status", "description": "Read QTS system status", "inputSchema": {"type": "object", "properties": {}}},
    {"name": "qts_health", "description": "Read-only QTS disk and storage health audit; volume coverage remains unverified", "inputSchema": {"type": "object", "properties": {"volume_indices": {"type": "array", "items": {"type": "integer", "minimum": 1, "maximum": 256}, "maxItems": 32}}}},
    {"name": "qts_storage", "description": "List observable QTS volumes and disks; indices are explicit and do not prove full coverage", "inputSchema": {"type": "object", "properties": {"volume_indices": {"type": "array", "items": {"type": "integer", "minimum": 1, "maximum": 256}, "maxItems": 32}}}},
    {"name": "qts_network", "description": "List observable QTS network adapters and DNS", "inputSchema": {"type": "object", "properties": {}}},
    {"name": "qts_tailscale", "description": "Read Tailscale state through configured passwordless SSH", "inputSchema": {"type": "object", "properties": {}}},
    {"name": "qts_raid", "description": "Read and parse /proc/mdstat through configured passwordless SSH", "inputSchema": {"type": "object", "properties": {}}},
    {"name": "qts_smart_details", "description": "Read SMART attributes for one disk bay through configured passwordless SSH", "inputSchema": {"type": "object", "properties": {"disk": {"type": "integer", "minimum": 1, "maximum": 64}}, "required": ["disk"]}},
    {"name": "qts_disk_topology", "description": "Read physical disk bay, role and model through configured passwordless SSH", "inputSchema": {"type": "object", "properties": {}}},
    {"name": "qts_services", "description": "Read Container Station and Tailscale package state", "inputSchema": {"type": "object", "properties": {}}},
    {
        "name": "qts_plex_security",
        "description": "Read-only Plex patch posture plus operator-reported indicators; optional fixed pidof checks for three known process names only; never remediates",
        "inputSchema": {
            "type": "object",
            "additionalProperties": False,
            "properties": {
                "exposure_during_vulnerable_version": {"type": "string", "enum": ["yes", "no"]},
                "current_exposure": {"type": "string", "enum": ["yes", "no"]},
                "ioc_unknown_plex_process": {"type": "string", "enum": ["yes", "no"]},
                "ioc_unfamiliar_codecs_files": {"type": "string", "enum": ["yes", "no"]},
                "ioc_proxystream_st_connection": {"type": "string", "enum": ["yes", "no"]},
                "ioc_sustained_idle_cpu": {"type": "string", "enum": ["yes", "no"]},
                "ioc_malware_remover_detection": {"type": "string", "enum": ["yes", "no"]},
                "check_known_process_iocs": {"type": "boolean"}
            }
        }
    },
    {
        "name": "qts_legacy_ransomware_security",
        "description": "Read-only Qlocker/DeadBolt/QSnatch-related package posture using fixed HBS 3, Photo Station and security-app QPKG reads; firmware thresholds outside published branches remain unknown",
        "inputSchema": {
            "type": "object",
            "additionalProperties": False,
            "properties": {
                "historical_internet_exposure": {"type": "string", "enum": ["yes", "no"]},
                "current_internet_exposure": {"type": "string", "enum": ["yes", "no"]},
                "qsnatch_controls": {
                    "type": "object",
                    "additionalProperties": False,
                    "properties": {name: {"type": "string", "enum": ["yes", "no"]} for name in QSNATCH_CONTROLS}
                }
            }
        }
    },
    {"name": "qts_incident", "description": "Bounded read-only ransomware IOC triage for visible shares plus health evidence; never reports clean and never contains/remediates", "inputSchema": {"type": "object", "properties": {"max_items": {"type": "integer", "minimum": 1, "maximum": MAX_MAX_ITEMS, "default": DEFAULT_MAX_ITEMS}}}},
]


def _web_call(config: Config, operation: Callable[[QtsClient], Dict[str, Any]]) -> Dict[str, Any]:
    password = password_from_environment()
    if not password:
        raise QtsError("MCP 模式需要 QTS_PASSWORD 環境變數")
    with QtsClient(config) as client:
        client.login(password, os.environ.get("QTS_SECURITY_CODE") or None)
        return operation(client)


def call_tool(config: Config, name: str, arguments: Dict[str, Any] = None) -> Dict[str, Any]:
    arguments = {} if arguments is None else arguments
    if not isinstance(arguments, dict):
        raise QtsError("MCP tool arguments 必須是 object")
    operations = {
        "qts_status": sysinfo,
        "qts_network": network,
    }
    ssh_operations = {"qts_tailscale": tailscale, "qts_raid": raid, "qts_disk_topology": disks_ssh, "qts_services": services}
    if name == "qts_smart_details":
        if set(arguments) != {"disk"}:
            raise QtsError("只接受 disk 整數參數")
        disk = arguments["disk"]
        if type(disk) is not int or not 1 <= disk <= 64:
            raise QtsError("disk 必須介於 1 到 64")
        return smart_details(config, disk)
    if name in ssh_operations:
        if arguments:
            raise QtsError("此 MCP tool 不接受參數")
        return ssh_operations[name](config)
    if name == "qts_plex_security":
        ioc_arguments = {"ioc_" + field: field for field in IOC_FIELDS}
        allowed = {"exposure_during_vulnerable_version", "current_exposure", "check_known_process_iocs"} | set(ioc_arguments)
        if set(arguments) - allowed:
            raise QtsError("Only documented operator-reported exposure/IOC fields are accepted")
        for key, value in arguments.items():
            if key == "check_known_process_iocs":
                if type(value) is not bool:
                    raise QtsError("check_known_process_iocs must be boolean")
                continue
            if value not in ("yes", "no"):
                raise QtsError("{} must be 'yes' or 'no'".format(key))
        indicators = {ioc_arguments[key]: value for key, value in arguments.items() if key in ioc_arguments}
        return plex2shell_audit(
            config,
            arguments.get("exposure_during_vulnerable_version"),
            arguments.get("current_exposure"),
            indicators,
            arguments.get("check_known_process_iocs", False),
        )
    if name == "qts_legacy_ransomware_security":
        allowed = {"historical_internet_exposure", "current_internet_exposure", "qsnatch_controls"}
        if set(arguments) - allowed:
            raise QtsError("只接受文件定義的 exposure 與 QSnatch 控制確認欄位")
        for key in ("historical_internet_exposure", "current_internet_exposure"):
            value = arguments.get(key)
            if value is not None and value not in ("yes", "no"):
                raise QtsError("{} must be 'yes' or 'no'".format(key))
        controls = arguments.get("qsnatch_controls", {})
        if not isinstance(controls, dict) or set(controls) - set(QSNATCH_CONTROLS):
            raise QtsError("qsnatch_controls must contain only documented control names")
        if any(value not in ("yes", "no") for value in controls.values()):
            raise QtsError("QSnatch controls must be 'yes' or 'no'")
        return _web_call(config, lambda client: legacy_ransomware_audit(
            client, config,
            arguments.get("historical_internet_exposure"),
            arguments.get("current_internet_exposure"),
            controls,
        ))
    if name in ("qts_health", "qts_storage"):
        if set(arguments) - {"volume_indices"}:
            raise QtsError("只接受 volume_indices 參數")
        indices = arguments.get("volume_indices")
        if indices is not None and (not isinstance(indices, list) or not indices or len(indices) > 32 or any(type(item) is not int or not 1 <= item <= 256 for item in indices)):
            raise QtsError("volume_indices 必須是 1..256 的整數陣列，最多 32 個")
        operation = (lambda client: health(client, indices)) if name == "qts_health" else (lambda client: storage(client, indices))
        return _web_call(config, operation)
    if name == "qts_incident":
        if set(arguments) - {"max_items"}:
            raise QtsError("只接受 max_items 參數")
        max_items = arguments.get("max_items", DEFAULT_MAX_ITEMS)
        if type(max_items) is not int or not 1 <= max_items <= MAX_MAX_ITEMS:
            raise QtsError("max_items 必須介於 1 到 {}".format(MAX_MAX_ITEMS))
        return _web_call(config, lambda client: incident_report(client, config, max_items))
    if name not in operations:
        raise QtsError("未知 MCP tool：{}".format(name))
    if arguments:
        raise QtsError("此 MCP tool 不接受參數")
    return _web_call(config, operations[name])


def response(request_id: Any, result: Any = None, error: Any = None) -> Dict[str, Any]:
    value = {"jsonrpc": "2.0", "id": request_id}
    if error is not None:
        value["error"] = error
    else:
        value["result"] = result
    return value


def handle_line(line: str, config: Config):
    request_id = None
    try:
        request = json.loads(line)
    except ValueError:
        return response(None, error={"code": -32700, "message": "Parse error"})
    if not isinstance(request, dict):
        return response(None, error={"code": -32600, "message": "Invalid Request"})
    request_id = request.get("id")
    if request.get("jsonrpc") != "2.0" or not isinstance(request.get("method"), str):
        return response(request_id, error={"code": -32600, "message": "Invalid Request"})
    method = request["method"]
    params = request.get("params", {})
    if not isinstance(params, dict):
        return response(request_id, error={"code": -32602, "message": "Invalid params"})
    is_notification = "id" not in request
    try:
        if method == "initialize":
            result = {"protocolVersion": "2025-06-18", "capabilities": {"tools": {}}, "serverInfo": {"name": "qnap-nas-cli", "version": __version__}}
        elif method == "notifications/initialized":
            return None
        elif method == "tools/list":
            result = {"tools": TOOLS}
        elif method == "tools/call":
            name = params.get("name")
            if not isinstance(name, str):
                return None if is_notification else response(request_id, error={"code": -32602, "message": "Invalid params"})
            arguments = params.get("arguments", {})
            if not isinstance(arguments, dict):
                return None if is_notification else response(request_id, error={"code": -32602, "message": "Invalid params"})
            data = call_tool(config, name, arguments)
            result = {"content": [{"type": "text", "text": json.dumps(data, ensure_ascii=False, indent=2)}], "structuredContent": data}
        elif method == "ping":
            result = {}
        else:
            return None if is_notification else response(request_id, error={"code": -32601, "message": "Method not found"})
        return None if is_notification else response(request_id, result=result)
    except QtsError as exc:
        return None if is_notification else response(request_id, error={"code": -32000, "message": str(exc)})


def serve(config: Config) -> int:
    for line in sys.stdin:
        result = handle_line(line, config)
        if result is not None:
            print(json.dumps(result, ensure_ascii=False), flush=True)
    return 0
