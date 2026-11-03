import json
import os
import sys
from typing import Any, Callable, Dict

from .commands import health, network, storage, sysinfo, tailscale
from .config import Config, password_from_environment
from .client import QtsClient
from .errors import QtsError


TOOLS = [
    {"name": "qts_status", "description": "Read QTS system status", "inputSchema": {"type": "object", "properties": {}}},
    {"name": "qts_health", "description": "Read-only QTS disk and storage health audit", "inputSchema": {"type": "object", "properties": {}}},
    {"name": "qts_storage", "description": "List observable QTS volumes and disks", "inputSchema": {"type": "object", "properties": {}}},
    {"name": "qts_network", "description": "List observable QTS network adapters and DNS", "inputSchema": {"type": "object", "properties": {}}},
    {"name": "qts_tailscale", "description": "Read Tailscale state through configured passwordless SSH", "inputSchema": {"type": "object", "properties": {}}},
]


def _web_call(config: Config, operation: Callable[[QtsClient], Dict[str, Any]]) -> Dict[str, Any]:
    password = password_from_environment()
    if not password:
        raise QtsError("MCP 模式需要 QTS_PASSWORD 環境變數")
    with QtsClient(config) as client:
        client.login(password, os.environ.get("QTS_SECURITY_CODE") or None)
        return operation(client)


def call_tool(config: Config, name: str) -> Dict[str, Any]:
    operations = {
        "qts_status": sysinfo,
        "qts_health": health,
        "qts_storage": storage,
        "qts_network": network,
    }
    if name == "qts_tailscale":
        return tailscale(config)
    if name not in operations:
        raise QtsError("未知 MCP tool：{}".format(name))
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
            result = {"protocolVersion": "2025-06-18", "capabilities": {"tools": {}}, "serverInfo": {"name": "qnap-nas-cli", "version": "0.1.1"}}
        elif method == "notifications/initialized":
            return None
        elif method == "tools/list":
            result = {"tools": TOOLS}
        elif method == "tools/call":
            name = params.get("name")
            if not isinstance(name, str):
                return None if is_notification else response(request_id, error={"code": -32602, "message": "Invalid params"})
            data = call_tool(config, name)
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
