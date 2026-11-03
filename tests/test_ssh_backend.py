import json
import unittest
from unittest.mock import patch

from qnap_nas_cli.config import Config
from qnap_nas_cli.errors import QtsError
from qnap_nas_cli.ssh_backend import run_ssh, tailscale_status


class Completed:
    returncode = 0
    stderr = ""
    stdout = json.dumps({"BackendState": "Running", "Self": {"HostName": "nas", "Online": True, "TailscaleIPs": ["100.64.0.1"]}, "Peer": {"x": {"Online": True}}})


class SshBackendTest(unittest.TestCase):
    def config(self):
        return Config("https://nas.example", "ops", ssh_host="nas.local", ssh_user="ops")

    @patch("qnap_nas_cli.ssh_backend.subprocess.run", return_value=Completed())
    def test_only_allowlisted_tailscale_command_is_built(self, run):
        result = tailscale_status(self.config())
        args = run.call_args.args[0]
        self.assertEqual(args[-3:], ["tailscale", "status", "--json"])
        self.assertEqual(result["online_peer_count"], 1)

    def test_rejects_shell_characters_in_host(self):
        config = self.config()
        config.ssh_host = "nas;shutdown"
        with self.assertRaises(QtsError):
            run_ssh(config, "tailscale")


if __name__ == "__main__":
    unittest.main()
