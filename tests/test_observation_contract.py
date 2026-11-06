import copy
import json
import unittest
import xml.etree.ElementTree as ET
from pathlib import Path

from qnap_nas_cli.commands import health, incident_report, storage
from qnap_nas_cli.config import Config
from qnap_nas_cli.mcp import TOOLS, handle_line, response
from qnap_nas_cli.ssh_backend import parse_mdstat
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
        client = SampleClient()
        cls.health_sample = health(client)
        cls.storage_sample = storage(client)
        mdstat = (FIXTURE_DIR / "mdstat.txt").read_text(encoding="utf-8")
        cls.raid_sample = parse_mdstat(mdstat)
        cls.incident_sample = incident_report(client, Config("https://nas.example", "ops"))

    def assert_valid(self, instance, schema):
        self.assertEqual(validate(instance, schema), [])

    def test_health_storage_raid_and_incident_samples_validate(self):
        self.assert_valid(self.health_sample, self.health_schema)
        self.assert_valid(self.health_sample["storage"], self.storage_schema)
        self.assert_valid(self.storage_sample, self.storage_schema)
        self.assert_valid(self.raid_sample, self.raid_schema)
        self.assert_valid(self.incident_sample, self.incident_schema)
        self.assert_valid(self.incident_sample["observations"]["health"], self.health_schema)
        self.assertEqual(self.incident_sample["assessment"], "indeterminate")

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
