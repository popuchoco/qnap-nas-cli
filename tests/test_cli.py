import unittest
import io
import json
import sys
import tempfile
from unittest.mock import patch

from pathlib import Path

from qnap_nas_cli.cli import _doctor, main, parser
from qnap_nas_cli.config import Config
from qnap_nas_cli.remediation import unavailable_plan


class CliTest(unittest.TestCase):
    def test_global_flags_before_command(self):
        args = parser().parse_args(["--json", "status"])
        self.assertTrue(args.json)

    def test_global_flags_after_command(self):
        args = parser().parse_args(["status", "--json", "--config", "custom.json"])
        self.assertTrue(args.json)
        self.assertEqual(str(args.config), "custom.json")

    def test_filestation_dump_flag_is_optional(self):
        plain = parser().parse_args(["dump"])
        extended = parser().parse_args(["dump", "--filestation"])
        self.assertFalse(plain.filestation)
        self.assertTrue(extended.filestation)

    def test_incident_nested_command_flags_and_bounds(self):
        args = parser().parse_args(["incident", "scan", "--max-items", "250", "--json"])
        self.assertEqual(args.max_items, 250)
        self.assertTrue(args.json)

    def test_storage_accepts_multiple_explicit_volume_indices(self):
        args = parser().parse_args(["storage", "--volume-index", "1", "--volume-index", "3"])
        self.assertEqual(args.volume_index, [1, 3])

    def test_incident_contain_works_offline_from_saved_report(self):
        with tempfile.TemporaryDirectory() as temp:
            report = Path(temp) / "incident.json"
            report.write_text(json.dumps({"ransomware_scan": {"assessment": "suspected", "indicators": []}}), encoding="utf-8")
            output = io.StringIO()
            with patch.object(sys, "stdout", output):
                code = main(["incident", "contain", str(report), "--json"])
        self.assertEqual(code, 0)
        self.assertIn("manual_response_required", output.getvalue())

    def test_missing_config_returns_2(self):
        with tempfile.TemporaryDirectory() as temp:
            output = io.StringIO()
            with patch.object(sys, "stderr", output):
                code = main(["--config", str(Path(temp) / "missing.json"), "status"])
        self.assertEqual(code, 2)
        self.assertIn("尚未設定 NAS", output.getvalue())

    def test_repair_apply_offline_refuses_manual_only_plan(self):
        with tempfile.TemporaryDirectory() as temp:
            plan = Path(temp) / "plan.json"
            plan.write_text(json.dumps(unavailable_plan({"origin": "https://nas.example"}, "service-stop")), encoding="utf-8")
            output = io.StringIO()
            with patch.object(sys, "stdout", output):
                code = main(["repair", "apply", str(plan), "--confirm", "unused", "--json"])
        self.assertEqual(code, 2)
        self.assertIn('"status": "refused"', output.getvalue())

    def test_successful_identity_read_still_refuses_plan_and_apply_without_mutation(self):
        class ReadOnlyClient:
            def __init__(self):
                self.identity_reads = 0

            def __enter__(self):
                return self

            def __exit__(self, exc_type, exc_value, traceback):
                return None

            def get_xml(self, path, params):
                self.identity_reads += 1
                import xml.etree.ElementTree as ET
                return ET.fromstring("<QDocRoot><modelName>TS-X41</modelName><version>5.2.8</version><build>20251216</build></QDocRoot>")

        client = ReadOnlyClient()
        config = Config("https://nas.invalid", "operator")
        with tempfile.TemporaryDirectory() as temporary:
            plan_path = Path(temporary) / "plan.json"
            output = io.StringIO()
            with patch("qnap_nas_cli.cli._config", return_value=config), \
                 patch("qnap_nas_cli.cli.QtsClient", return_value=client), \
                 patch("qnap_nas_cli.cli._login"), \
                 patch.object(sys, "stdout", output):
                plan_code = main(["repair", "plan", "--action", "service-stop", "--output", str(plan_path), "--json"])
            plan = json.loads(plan_path.read_text(encoding="utf-8"))
            self.assertEqual(plan_code, 2)
            self.assertEqual(plan["status"], "refused")
            self.assertEqual(plan["operations"], [])
            self.assertEqual(client.identity_reads, 1)

            with patch.object(sys, "stdout", io.StringIO()):
                apply_code = main(["repair", "apply", str(plan_path), "--confirm", plan["plan_id"], "--json"])
            self.assertEqual(apply_code, 2)
            self.assertEqual(client.identity_reads, 1)

    def test_doctor_reports_actual_config_and_local_http_as_safe(self):
        result = _doctor(Config("http://127.0.0.1:8080", "ops"), Path("custom.json"))
        self.assertEqual(result["config"], "custom.json")
        self.assertTrue(result["safe"])

    def test_doctor_does_not_treat_empty_password_as_available(self):
        with patch.dict("os.environ", {"QTS_PASSWORD": ""}, clear=False):
            result = _doctor(Config("https://nas.example", "ops"), Path("custom.json"))
        self.assertFalse(result["password_available"])


if __name__ == "__main__":
    unittest.main()
