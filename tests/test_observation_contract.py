import copy
import json
import tempfile
import unittest
import xml.etree.ElementTree as ET
from pathlib import Path
from unittest.mock import patch

from qnap_nas_cli.commands import health, incident_report, legacy_ransomware_audit, plex2shell_audit, storage
from qnap_nas_cli.config import Config
from qnap_nas_cli.errors import QtsError
from qnap_nas_cli.mcp import TOOLS, handle_line, response
from qnap_nas_cli.security import assess_plex2shell
from qnap_nas_cli.ssh_backend import parse_mdstat
from qnap_nas_cli.legacy_ransomware import assess_legacy_ransomware
from qnap_nas_cli.health_report import write_legacy_ransomware_report
from schema_lite import validate


ROOT = Path(__file__).resolve().parents[1]
SCHEMA_DIR = ROOT / "schemas"
FIXTURE_DIR = ROOT / "tests" / "fixtures" / "ts431k-qts-5.2.8-build-20251216"


def load_schema(name):
    return json.loads((SCHEMA_DIR / name).read_text(encoding="utf-8"))


class SampleClient:
    """Offline responses with the same field shapes used by command tests."""

    def get_xml(self, path, params):
        if "disk_manage" in path:
            return ET.fromstring("""<QDocRoot>
                <volume><volume_name>DataVol1</volume_name><vol_status>0</vol_status></volume>
                <disk><disk_no>1</disk_no><smart_status>Good</smart_status><temperature>30 C</temperature></disk>
            </QDocRoot>""")
        if "qsmart" in path:
            return ET.fromstring("<QDocRoot/>")
        return ET.fromstring("<QDocRoot><modelName>TS-431K</modelName><sys_tempc>35 C</sys_tempc></QDocRoot>")

    def get_json(self, path, params):
        if params.get("func") == "get_tree":
            return []
        return {"total": 0, "real_total": 0, "datas": []}


class ObservationContractTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.health_schema = load_schema("observation-health.schema.json")
        cls.storage_schema = load_schema("observation-storage.schema.json")
        cls.raid_schema = load_schema("observation-raid.schema.json")
        cls.incident_schema = load_schema("observation-incident.schema.json")
        cls.plex_security_schema = load_schema("observation-security-plex2shell.schema.json")
        cls.legacy_ransomware_schema = load_schema("observation-security-legacy-ransomware.schema.json")
        client = SampleClient()
        cls.health_sample = health(client)
        cls.storage_sample = storage(client)
        mdstat = (FIXTURE_DIR / "mdstat.txt").read_text(encoding="utf-8")
        cls.raid_sample = parse_mdstat(mdstat)
        cls.incident_sample = incident_report(client, Config("https://nas.example", "ops"))
        cls.plex_security_sample = assess_plex2shell({
            "package": "PlexMediaServer", "installed": True, "version": "1.43.3",
            "qpkg_status": "complete", "enabled": True, "data_status": "version_available",
            "version_source": "QPKG metadata (/etc/config/qpkg.conf)", "runtime_health": "unknown",
        })
        unknown_package = {"installed": None, "version": None, "enabled": None, "qpkg_status": None}
        cls.legacy_ransomware_sample = assess_legacy_ransomware(
            {"model": "TS-431K", "firmware_product": "QTS", "firmware": "5.2.8", "build": "20251216"},
            {name: dict(unknown_package) for name in ("hbs3", "photo_station", "malware_remover", "security_center", "security_counselor")},
        )

    def assert_valid(self, instance, schema):
        self.assertEqual(validate(instance, schema), [])

    def test_health_storage_raid_and_incident_samples_validate(self):
        self.assert_valid(self.health_sample, self.health_schema)
        self.assert_valid(self.health_sample["storage"], self.storage_schema)
        self.assert_valid(self.storage_sample, self.storage_schema)
        self.assert_valid(self.raid_sample, self.raid_schema)
        self.assert_valid(self.incident_sample, self.incident_schema)
        self.assert_valid(self.incident_sample["observations"]["health"], self.health_schema)
        self.assert_valid(self.plex_security_sample, self.plex_security_schema)
        self.assert_valid(self.legacy_ransomware_sample, self.legacy_ransomware_schema)
        self.assertEqual(self.plex_security_sample["runtime_ioc_probes"]["status"], "not_requested")
        self.assertEqual(self.incident_sample["assessment"], "indeterminate")

    def test_plex_security_schema_and_mcp_contract(self):
        tool = next(tool for tool in TOOLS if tool["name"] == "qts_plex_security")
        self.assertEqual(tool["inputSchema"]["properties"]["current_exposure"]["enum"], ["yes", "no"])
        self.assertEqual(tool["inputSchema"]["properties"]["ioc_malware_remover_detection"]["enum"], ["yes", "no"])
        self.assertEqual(tool["inputSchema"]["properties"]["check_known_process_iocs"]["type"], "boolean")
        broken = copy.deepcopy(self.plex_security_sample)
        broken["assessment"] = "clean"
        self.assertTrue(validate(broken, self.plex_security_schema))

    def test_legacy_ransomware_schema_and_qsnatch_mcp_contract(self):
        self.assert_valid(self.legacy_ransomware_sample, self.legacy_ransomware_schema)
        broken = copy.deepcopy(self.legacy_ransomware_sample)
        broken["qsnatch_security_controls"]["controls"]["qts_latest"]["status"] = "maybe"
        self.assertTrue(validate(broken, self.legacy_ransomware_schema))
        tool = next(tool for tool in TOOLS if tool["name"] == "qts_legacy_ransomware_security")
        controls = tool["inputSchema"]["properties"]["qsnatch_controls"]["properties"]
        self.assertIn("malware_remover_updated_and_scan_run", controls)
        self.assertEqual(controls["qts_latest"]["enum"], ["yes", "no"])

    def test_real_legacy_assessment_bundle_remains_schema_valid_after_redaction(self):
        packages = {
            "hbs3": {"installed": True, "version": "16.0.0.414", "enabled": True},
            "photo_station": {"installed": True, "version": "6.0.21", "enabled": True},
            "malware_remover": {"installed": True, "version": "5.0", "enabled": True},
            "security_center": {"installed": None, "version": None, "enabled": None},
            "security_counselor": {"installed": None, "version": None, "enabled": None},
        }
        observation = assess_legacy_ransomware(
            {"model": "TS-X41", "firmware_product": "QTS", "firmware": "4.5.2", "build": "20251216"},
            packages,
            historical_exposure="no",
            current_exposure="no",
        )
        self.assertEqual(observation["report_type"], "qnap_legacy_ransomware_posture")
        self.assertEqual(observation["rule_id"], "qnap-legacy-ransomware-2026-11")
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "legacy-bundle"
            receipt = write_legacy_ransomware_report(target, observation)
            bundle = json.loads((target / receipt["files"][0]).read_text(encoding="utf-8"))

        self.assertEqual(validate(bundle, self.legacy_ransomware_schema), [])
        self.assertEqual(bundle["report_type"], "qnap_legacy_ransomware_posture")
        self.assertEqual(bundle["rule_id"], "qnap-legacy-ransomware-2026-11")
        self.assertEqual(bundle["package_posture"]["hbs3"]["version"], "16.0.0.414")
        self.assertEqual(bundle["system"]["build"], "20251216")

    def test_ssh_collection_errors_validate_as_unknown_postures(self):
        config = Config("https://nas.example", "ops", ssh_host="nas", ssh_user="ops")
        with patch("qnap_nas_cli.commands.plex_qpkg_info", side_effect=QtsError("timeout")):
            plex_report = plex2shell_audit(config, check_known_process_iocs=True)
        self.assertEqual(validate(plex_report, self.plex_security_schema), [])
        self.assertEqual(plex_report["assessment"], "indeterminate")
        self.assertIsNone(plex_report["package"]["installed"])

        with patch("qnap_nas_cli.commands.sysinfo", return_value={"model": "TS-X41", "firmware_product": "QTS", "firmware": "5.2.8", "build": "20251216"}), \
             patch("qnap_nas_cli.commands.legacy_ransomware_packages", side_effect=QtsError("timeout")):
            legacy_report = legacy_ransomware_audit(SampleClient(), config)
        self.assertEqual(validate(legacy_report, self.legacy_ransomware_schema), [])
        self.assertEqual(legacy_report["assessment"], "indeterminate")
        self.assertEqual(legacy_report["collection_errors"][0]["code"], "ssh_collection_failed")

    def test_broken_health_shapes_fail_validation(self):
        missing_unknowns = copy.deepcopy(self.health_sample)
        del missing_unknowns["unknowns"]
        self.assertTrue(validate(missing_unknowns, self.health_schema))

        invalid_status = copy.deepcopy(self.health_sample)
        invalid_status["status"] = "ok"
        self.assertTrue(validate(invalid_status, self.health_schema))

    def test_mcp_tools_list_has_no_shell_tool_and_structured_health_validates(self):
        listed = handle_line('{"jsonrpc":"2.0","id":1,"method":"tools/list"}', Config("https://nas.example", "ops"))
        tools = listed["result"]["tools"]
        descriptions = " ".join(str(tool).lower() for tool in tools)
        self.assertNotIn("shell", descriptions)
        self.assertNotIn("api_call", descriptions)
        self.assertEqual({tool["name"] for tool in tools}, {tool["name"] for tool in TOOLS})

        structured_response = response(2, result={"structuredContent": self.health_sample})
        payload = structured_response["result"]["structuredContent"]
        self.assert_valid(payload, self.health_schema)


if __name__ == "__main__":
    unittest.main()
