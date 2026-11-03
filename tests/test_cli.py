import unittest

from pathlib import Path

from qnap_nas_cli.cli import _doctor, parser
from qnap_nas_cli.config import Config


class CliTest(unittest.TestCase):
    def test_global_flags_before_command(self):
        args = parser().parse_args(["--json", "status"])
        self.assertTrue(args.json)

    def test_global_flags_after_command(self):
        args = parser().parse_args(["status", "--json", "--config", "custom.json"])
        self.assertTrue(args.json)
        self.assertEqual(str(args.config), "custom.json")

    def test_doctor_reports_actual_config_and_local_http_as_safe(self):
        result = _doctor(Config("http://127.0.0.1:8080", "ops"), Path("custom.json"))
        self.assertEqual(result["config"], "custom.json")
        self.assertTrue(result["safe"])


if __name__ == "__main__":
    unittest.main()
