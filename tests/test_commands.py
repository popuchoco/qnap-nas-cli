import unittest
import xml.etree.ElementTree as ET
import tempfile
from pathlib import Path

from qnap_nas_cli.commands import health, validate_dump


class FakeClient:
    def get_xml(self, path, params):
        if "disk_manage" in path:
            return ET.fromstring("""<QDocRoot>
                <volume><volume_name>DataVol1</volume_name><vol_status>-5</vol_status></volume>
                <disk><disk_no>2</disk_no><smart_status>Warning</smart_status><temperature>56 C</temperature></disk>
            </QDocRoot>""")
        return ET.fromstring("<QDocRoot><modelName>TS-431K</modelName><sys_tempc>72 C</sys_tempc></QDocRoot>")


class CommandsTest(unittest.TestCase):
    def test_health_reports_observations_without_claiming_repair(self):
        report = health(FakeClient())
        codes = {item["code"] for item in report["findings"]}
        self.assertFalse(report["healthy"])
        self.assertEqual(codes, {"system_temperature", "disk_health", "disk_temperature", "volume_status"})
        self.assertEqual(report["status"], "unhealthy")
        self.assertEqual(report["healthy"], False)

    def test_unknown_volume_is_indeterminate_not_healthy(self):
        class UnknownClient(FakeClient):
            def get_xml(self, path, params):
                if "disk_manage" in path:
                    return ET.fromstring("""<QDocRoot>
                        <volume><volume_name>DataVol1</volume_name><vol_status>0</vol_status></volume>
                        <disk><disk_no>1</disk_no><smart_status>Good</smart_status></disk>
                    </QDocRoot>""")
                return ET.fromstring("<QDocRoot><modelName>TS-431K</modelName></QDocRoot>")

        report = health(UnknownClient())
        self.assertEqual(report["status"], "indeterminate")
        self.assertIsNone(report["healthy"])
        self.assertEqual(report["findings"], [])
        self.assertIn("volume_status_unknown", {item["code"] for item in report["unknowns"]})

    def test_ready_volume_remains_indeterminate_while_query_scope_is_unverified(self):
        class ReadyClient(FakeClient):
            def get_xml(self, path, params):
                if "disk_manage" in path:
                    return ET.fromstring("""<QDocRoot>
                        <volume><volume_name>DataVol1</volume_name><vol_status>-7</vol_status></volume>
                        <disk><disk_no>1</disk_no><smart_status>Good</smart_status></disk>
                    </QDocRoot>""")
                return ET.fromstring("<QDocRoot><modelName>TS-431K</modelName></QDocRoot>")

        report = health(ReadyClient())
        self.assertEqual(report["status"], "indeterminate")
        self.assertIsNone(report["healthy"])
        self.assertIn("storage_scope_unverified", {item["code"] for item in report["unknowns"]})

    def test_validate_dump_reports_unknown_code_without_inventing_status(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "sysinfo.xml").write_text("<QDocRoot><modelName>TS-431K</modelName></QDocRoot>", encoding="utf-8")
            (root / "storage.xml").write_text("<QDocRoot><volume><volume_name>DataVol1</volume_name><vol_status>99</vol_status></volume></QDocRoot>", encoding="utf-8")
            result = validate_dump(root)
        self.assertTrue(result["valid"])
        self.assertIn("unknown_volume_status:99", result["warnings"])
        self.assertEqual(result["observations"]["storage"]["volumes"][0]["status"], "unknown")


if __name__ == "__main__":
    unittest.main()
