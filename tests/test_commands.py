import unittest
import xml.etree.ElementTree as ET

from qnap_nas_cli.commands import health


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
        self.assertIn("unknown", report["note"])


if __name__ == "__main__":
    unittest.main()
