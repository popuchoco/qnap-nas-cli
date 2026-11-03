import json
import re
import subprocess
from typing import Any, Dict, List

from .config import Config
from .errors import QtsError


ALLOWED_COMMANDS = {
    "tailscale": ["tailscale", "status", "--json"],
    "disk_summary": ["/bin/sh", "-c", "cat /proc/mdstat; echo; df -h"],
}


def run_ssh(config: Config, command_name: str) -> str:
    if not config.ssh_host or not config.ssh_user:
        raise QtsError("此命令需要 SSH；請用 qts setup 設定 --ssh-host 與 --ssh-user")
    if not re.fullmatch(r"[A-Za-z0-9_.:-]+", config.ssh_host):
        raise QtsError("ssh_host 格式不安全")
    if not re.fullmatch(r"[A-Za-z0-9_.-]+", config.ssh_user):
        raise QtsError("ssh_user 格式不安全")
    command = ALLOWED_COMMANDS[command_name]
    target = "{}@{}".format(config.ssh_user, config.ssh_host)
    args = ["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=10", "--", target] + command
    try:
        completed = subprocess.run(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=30, check=False)
    except FileNotFoundError as exc:
        raise QtsError("找不到 ssh 執行檔") from exc
    except subprocess.TimeoutExpired as exc:
        raise QtsError("SSH 命令逾時") from exc
    if completed.returncode != 0:
        raise QtsError("SSH 命令失敗：{}".format(completed.stderr.strip() or "exit {}".format(completed.returncode)))
    return completed.stdout


def tailscale_status(config: Config) -> Dict[str, Any]:
    raw = run_ssh(config, "tailscale")
    try:
        payload = json.loads(raw)
    except ValueError as exc:
        raise QtsError("tailscale status 未回傳有效 JSON") from exc
    self_node = payload.get("Self") or {}
    peers = payload.get("Peer") or {}
    online = sum(1 for peer in peers.values() if peer.get("Online")) if isinstance(peers, dict) else 0
    return {
        "backend": "ssh",
        "state": payload.get("BackendState"),
        "hostname": self_node.get("HostName"),
        "tailscale_ips": self_node.get("TailscaleIPs", []),
        "online": self_node.get("Online"),
        "peer_count": len(peers) if isinstance(peers, dict) else 0,
        "online_peer_count": online,
        "exit_node": self_node.get("ExitNode"),
    }
