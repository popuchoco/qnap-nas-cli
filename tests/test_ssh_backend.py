import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from qnap_nas_cli.config import Config
from qnap_nas_cli.errors import QtsError
from qnap_nas_cli.ssh_backend import parse_disk_topology, parse_mdstat, parse_smart_attributes, run_ssh, service_status, tailscale_status


class Completed:
    returncode = 0
    stderr = ""
    stdout = json.dumps({"BackendState": "Running", "Self": {"HostName": "nas", "Online": True, "TailscaleIPs": ["100.64.0.1"]}, "Peer": {"x": {"Online": True}}})


class SshBackendTest(unittest.TestCase):
    def config(self):
        return Config("https://nas.example", "ops", ssh_host="nas.local", ssh_user="ops")

    @patch("qnap_nas_cli.ssh_backend.subprocess.run")
    def test_only_allowlisted_tailscale_command_is_built(self, run):
        path = Completed()
        path.stdout = "/share/CACHEDEV1_DATA/.qpkg/Tailscale\n"
        run.side_effect = [path, Completed()]
        result = tailscale_status(self.config())
        args = run.call_args_list[-1].args[0]
        self.assertEqual(args[-3:], ["/share/CACHEDEV1_DATA/.qpkg/Tailscale/tailscale", "status", "--json"])
        self.assertEqual(result["online_peer_count"], 1)

    @patch("qnap_nas_cli.ssh_backend.subprocess.run")
    def test_tailscale_uses_validated_qpkg_path(self, run):
        path = Completed()
        path.stdout = "/share/CACHEDEV1_DATA/.qpkg/Tailscale\n"
        status = Completed()
        run.side_effect = [path, status]
        tailscale_status(self.config())
        self.assertEqual(run.call_args_list[-1].args[0][-3], "/share/CACHEDEV1_DATA/.qpkg/Tailscale/tailscale")

    def test_rejects_shell_characters_in_host(self):
        config = self.config()
        config.ssh_host = "nas;shutdown"
        with self.assertRaises(QtsError):
            run_ssh(config, "tailscale")

    @patch("qnap_nas_cli.ssh_backend.subprocess.run", return_value=Completed())
    def test_allowlist_never_invokes_a_shell(self, run):
        run_ssh(self.config(), "raid")
        args = run.call_args.args[0]
        self.assertEqual(args[-2:], ["cat", "/proc/mdstat"])
        self.assertNotIn("-c", args)
        self.assertNotIn("/bin/sh", args)

    def test_rejects_invalid_smart_disk(self):
        with self.assertRaises(QtsError):
            run_ssh(self.config(), "smart_attributes", 0)

    @patch("qnap_nas_cli.ssh_backend.subprocess.run", return_value=Completed())
    def test_explicit_identity_file_is_passed_before_target(self, run):
        with tempfile.TemporaryDirectory() as directory:
            identity = Path(directory) / "id_ed25519"
            identity.write_text("test", encoding="utf-8")
            config = self.config()
            config.ssh_identity_file = str(identity)
            run_ssh(config, "raid")
        args = run.call_args.args[0]
        self.assertEqual(args[args.index("-i") + 1], str(identity))
        self.assertLess(args.index("-i"), args.index("--"))

    def test_parse_mdstat_degraded_and_recovery(self):
        raw = """Personalities : [raid1]\nmd1 : active raid1 sda3[0] sdb3[1](F) sdc3[2]\n      100 blocks [3/2] [U_U]\n      [=>...................] recovery = 7.5% finish=20min\n"""
        result = parse_mdstat(raw)
        self.assertTrue(result["arrays"][0]["degraded"])
        self.assertEqual(result["arrays"][0]["active_members"], 2)
        self.assertEqual(result["arrays"][0]["operation"]["progress_pct"], 7.5)

    def test_qnap_wide_bitmap_is_unknown_not_degraded(self):
        raw = "md13 : active raid1 sdb4[0] sdc4[1] sdd4[2]\n      458880 blocks [128/3] [_UUU____________________________________________________________________________________________________________________________]\n"
        array = parse_mdstat(raw)["arrays"][0]
        self.assertIsNone(array["degraded"])
        self.assertEqual(array["member_map_semantics"], "qnap_wide_bitmap_unknown")

    def test_reviewed_ts431k_ssh_fixtures(self):
        fixture = Path(__file__).parent / "fixtures" / "ts431k-qts-5.2.8-build-20251216"
        raid = parse_mdstat((fixture / "mdstat.txt").read_text(encoding="utf-8"))
        disks = parse_disk_topology((fixture / "qcli-storage-d.txt").read_text(encoding="utf-8"))
        self.assertFalse(next(item for item in raid["arrays"] if item["name"] == "md1")["degraded"])
        self.assertIsNone(next(item for item in raid["arrays"] if item["name"] == "md13")["degraded"])
        self.assertEqual(disks["disk_count"], 4)
        self.assertEqual(disks["disks"][0]["role"], "spare")

    def test_parse_smart_attributes(self):
        raw = "001 Raw_Read_Error_Rate 215244560 119 099 006 OK\n197 Current_Pending_Sector 8 100 100 000 ABNORMAL\n"
        result = parse_smart_attributes(raw, 2)
        self.assertEqual(result["attribute_count"], 2)
        self.assertEqual(result["attributes"][1]["raw"], "8")
        self.assertEqual(result["attributes"][1]["status"], "ABNORMAL")

    def test_empty_smart_output_is_explicitly_unavailable(self):
        result = parse_smart_attributes("", 2)
        self.assertEqual(result["data_status"], "unavailable_on_firmware")

    def test_parse_real_qcli_storage_shape(self):
        raw = 'NAS_HOST   1     /dev/sda          HDD:spare 465.76 GB 3.5" SATA HDD 1       --          5           WDC WD5000AAKX-22ERMA0\nNAS_HOST   2     /dev/sdb          HDD:data  1.82 TB   3.5" SATA HDD 2       QNAP FLEX   5           Seagate ST2000VN000-1HJ164\n'
        result = parse_disk_topology(raw)
        self.assertEqual(result["disk_count"], 2)
        self.assertEqual(result["disks"][0]["role"], "spare")
        self.assertEqual(result["disks"][1]["bay"], 2)
        self.assertEqual(result["disks"][1]["signature"], "QNAP FLEX")

    @patch("qnap_nas_cli.ssh_backend.run_ssh", side_effect=["TRUE\n", "complete\n", "FALSE\n"])
    def test_service_status_is_observational(self, _run):
        result = service_status(self.config())
        self.assertTrue(result["container_station"]["enabled"])
        self.assertEqual(result["container_station"]["runtime"], "unknown")
        self.assertFalse(result["tailscale"]["enabled"])


if __name__ == "__main__":
    unittest.main()
