import json
import re
import subprocess
from pathlib import Path
from typing import Any, Dict, List, Tuple

from .config import Config
from .errors import QtsError


ALLOWED_COMMANDS = {
    "raid": (["cat", "/proc/mdstat"], (0,)),
    "disk_topology": (["/sbin/qcli_storage", "-d"], (0,)),
    "container_station_enabled": (["/sbin/getcfg", "container-station", "Enable", "-f", "/etc/config/qpkg.conf"], (0,)),
    "container_station_status": (["/sbin/getcfg", "container-station", "Status", "-f", "/etc/config/qpkg.conf"], (0,)),
    "tailscale_enabled": (["/sbin/getcfg", "Tailscale", "Enable", "-f", "/etc/config/qpkg.conf"], (0,)),
    "tailscale_install_path": (["/sbin/getcfg", "Tailscale", "Install_Path", "-f", "/etc/config/qpkg.conf"], (0,)),
}


def _validate_ssh_config(config: Config) -> None:
    if not config.ssh_host or not config.ssh_user:
        raise QtsError("尚未設定 SSH；請用 qts setup 設定 --ssh-host 與 --ssh-user")
    if not re.fullmatch(r"[A-Za-z0-9_.:-]+", config.ssh_host):
        raise QtsError("ssh_host 格式不安全")
    if not re.fullmatch(r"[A-Za-z0-9_.-]+", config.ssh_user):
        raise QtsError("ssh_user 格式不安全")


def _run_ssh_argv(config: Config, command: List[str], accepted_codes: Tuple[int, ...] = (0,)) -> str:
    _validate_ssh_config(config)
    target = "{}@{}".format(config.ssh_user, config.ssh_host)
    args = ["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=10"]
    if config.ssh_identity_file:
        identity = Path(config.ssh_identity_file).expanduser()
        if not identity.is_file():
            raise QtsError("找不到 SSH identity file：{}".format(identity))
        args.extend(["-i", str(identity)])
    args.extend(["--", target] + command)
    try:
        completed = subprocess.run(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, encoding="utf-8", errors="replace", timeout=30, check=False)
    except FileNotFoundError as exc:
        raise QtsError("找不到 ssh 執行檔") from exc
    except subprocess.TimeoutExpired as exc:
        raise QtsError("SSH 連線逾時") from exc
    if completed.returncode not in accepted_codes:
        raise QtsError("SSH 指令失敗：{}".format(completed.stderr.strip() or "exit {}".format(completed.returncode)))
    return completed.stdout


def run_ssh(config: Config, command_name: str, disk: int = 0) -> str:
    if command_name == "smart_attributes":
        if not 1 <= disk <= 64:
            raise QtsError("disk 必須介於 1 到 64")
        command, accepted_codes = (["/sbin/get_hd_smartinfo", "-d", str(disk)], (0,))
    else:
        try:
            command, accepted_codes = ALLOWED_COMMANDS[command_name]
        except KeyError as exc:
            raise QtsError("SSH probe 不在 allowlist：{}".format(command_name)) from exc
    return _run_ssh_argv(config, command, accepted_codes)


def tailscale_status(config: Config) -> Dict[str, Any]:
    install_path = run_ssh(config, "tailscale_install_path").strip()
    if not re.fullmatch(r"/share/[A-Za-z0-9_.-]+/\.qpkg/Tailscale", install_path):
        raise QtsError("Tailscale QPKG 安裝路徑不符合安全格式")
    raw = _run_ssh_argv(config, [install_path + "/tailscale", "status", "--json"])
    try:
        payload = json.loads(raw)
    except ValueError as exc:
        raise QtsError("tailscale status 未傳回有效 JSON") from exc
    self_node = payload.get("Self") or {}
    peers = payload.get("Peer") or {}
    online = sum(1 for peer in peers.values() if peer.get("Online")) if isinstance(peers, dict) else 0
    return {"backend": "ssh", "state": payload.get("BackendState"), "hostname": self_node.get("HostName"), "tailscale_ips": self_node.get("TailscaleIPs", []), "online": self_node.get("Online"), "peer_count": len(peers) if isinstance(peers, dict) else 0, "online_peer_count": online, "exit_node": self_node.get("ExitNode")}


def parse_mdstat(raw: str) -> Dict[str, Any]:
    arrays = []
    lines = raw.splitlines()
    for index, line in enumerate(lines):
        match = re.match(r"^(md\d+)\s*:\s*(\w+)\s+(\S+)\s*(.*)$", line.strip())
        if not match:
            continue
        name, state, level, members_text = match.groups()
        detail = lines[index + 1].strip() if index + 1 < len(lines) else ""
        counts = re.search(r"\[(\d+)/(\d+)\]\s+\[([U_]+)\]", detail)
        operation = None
        for candidate in lines[index + 1:index + 4]:
            op = re.search(r"(recovery|resync|reshape|check)\s*=\s*([0-9.]+)%", candidate)
            if op:
                operation = {"type": op.group(1), "progress_pct": float(op.group(2))}
                break
        member_state = counts.group(3) if counts else None
        expected_members = int(counts.group(1)) if counts else None
        wide_qnap_bitmap = expected_members is not None and expected_members >= 64
        arrays.append({"name": name, "state": state, "level": level, "members": re.findall(r"\S+\[\d+\](?:\([A-Z]\))?", members_text), "expected_members": expected_members, "active_members": int(counts.group(2)) if counts else None, "member_state": member_state, "degraded": None if wide_qnap_bitmap else ("_" in member_state if member_state else None), "member_map_semantics": "qnap_wide_bitmap_unknown" if wide_qnap_bitmap else "linux_md", "operation": operation})
    return {"backend": "ssh", "arrays": arrays, "array_count": len(arrays), "parser_warning": None if arrays else "no_md_arrays"}


def raid_status(config: Config) -> Dict[str, Any]:
    return parse_mdstat(run_ssh(config, "raid"))


def parse_smart_attributes(raw: str, disk: int) -> Dict[str, Any]:
    attributes = []
    for line in raw.splitlines():
        match = re.match(r"^\s*(\d{1,3})\s+(\S+)\s+(\S+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\S+)\s*$", line)
        if not match:
            continue
        attribute_id, name, raw_value, current, worst, threshold, status = match.groups()
        attributes.append({"id": int(attribute_id), "name": name, "raw": raw_value, "current": int(current), "worst": int(worst), "threshold": int(threshold), "status": status})
    return {"backend": "ssh", "provider": "get_hd_smartinfo", "disk": disk, "attributes": attributes, "attribute_count": len(attributes), "data_status": "available" if attributes else "unavailable_on_firmware", "parser_warning": None if attributes else "no_smart_attributes"}


def smart_attributes(config: Config, disk: int) -> Dict[str, Any]:
    return parse_smart_attributes(run_ssh(config, "smart_attributes", disk), disk)


def parse_disk_topology(raw: str) -> Dict[str, Any]:
    disks = []
    pattern = re.compile(r"^(\S+)\s+(\d+)\s+(\S+)\s+HDD:(\S+)\s+(\S+\s+[A-Z]+)\s+(.+?)\s{2,}(.+?)\s{2,}(\d+)\s+(.+)$")
    for line in raw.splitlines():
        match = pattern.match(line.strip())
        if not match:
            continue
        enclosure, port, system_name, role, size, alias, signature, partitions, model = match.groups()
        disks.append({"enclosure": enclosure, "bay": int(port), "system_name": system_name, "role": role, "size": size, "alias": alias.strip(), "signature": signature, "partitions": int(partitions), "model": model.strip()})
    return {"backend": "ssh", "provider": "qcli_storage", "disks": disks, "disk_count": len(disks), "parser_warning": None if disks else "no_disks"}


def disk_topology(config: Config) -> Dict[str, Any]:
    return parse_disk_topology(run_ssh(config, "disk_topology"))


def service_status(config: Config) -> Dict[str, Any]:
    container_enabled = run_ssh(config, "container_station_enabled").strip()
    container_status = run_ssh(config, "container_station_status").strip()
    tailscale_enabled = run_ssh(config, "tailscale_enabled").strip()
    return {"backend": "ssh", "container_station": {"enabled": container_enabled.lower() == "true", "qpkg_status": container_status or "unknown", "runtime": "unknown"}, "tailscale": {"enabled": tailscale_enabled.lower() == "true"}, "limitations": ["QPKG Enable/Status 不證明 daemon 或 workload 正在健康運行；本工具不會自動 restart。"]}
