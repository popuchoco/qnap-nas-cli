import unittest
import xml.etree.ElementTree as ET
import tempfile
from pathlib import Path

from qnap_nas_cli.commands import dump, health, storage, validate_dump
from qnap_nas_cli.errors import QtsError


class FakeClient:
    def get_xml(self, path, params):
        if "disk_manage" in path:
            return ET.fromstring("""<QDocRoot>
                <volume><volume_name>DataVol1</volume_name><vol_status>-5</vol_status></volume>
                <disk><disk_no>2</disk_no><smart_status>Warning</smart_status><temperature>56 C</temperature></disk>
            </QDocRoot>""")
        return ET.fromstring("<QDocRoot><modelName>TS-431K</modelName><sys_tempc>72 C</sys_tempc></QDocRoot>")


class CommandsTest(unittest.TestCase):
    def test_dump_filestation_is_opt_in_and_uses_a_new_manifest_format(self):
        class DumpClient:
            def __init__(self):
                self.json_calls = []

            def get(self, path, params):
                return b"<QDocRoot><modelName>TS-X41</modelName></QDocRoot>"

            def get_json(self, path, params):
                self.json_calls.append(dict(params))
                return []

        client = DumpClient()
        with tempfile.TemporaryDirectory() as temporary:
            plain = dump(client, Path(temporary) / "plain")
            self.assertEqual(plain["format_version"], 2)
            self.assertFalse(client.json_calls)

            captured = dump(client, Path(temporary) / "with-filestation", filestation=True)
            self.assertEqual(captured["format_version"], 3)
            self.assertEqual(client.json_calls[0]["func"], "get_tree")
            self.assertTrue(captured["validation"]["valid"])
            self.assertEqual(captured["validation"]["filestation"]["list_files"], 0)

    def test_storage_queries_explicit_volume_indices_without_claiming_full_coverage(self):
        class IndexedClient(FakeClient):
            def __init__(self):
                self.indices = []
            def get_xml(self, path, params):
                if "extra_vol_index" in params:
                    self.indices.append(int(params["extra_vol_index"]))
                    return ET.fromstring("<QDocRoot><volume><volume_name>DataVol{}</volume_name><vol_status>-7</vol_status></volume></QDocRoot>".format(params["extra_vol_index"]))
                if "disk_manage" in path:
                    return ET.fromstring("<QDocRoot/>")
                if "qsmart" in path:
                    return ET.fromstring("<QDocRoot/>")
                return ET.fromstring("<QDocRoot><modelName>TS-431K</modelName></QDocRoot>")
        client = IndexedClient()
        result = storage(client, [1, 2, 2])
        self.assertEqual(client.indices, [1, 2])
        self.assertEqual(result["source"]["extra_vol_indices"], [1, 2])
        self.assertEqual(result["source"]["coverage"], "unverified")
        self.assertEqual([v["name"] for v in result["volumes"]], ["DataVol1", "DataVol2"])

    def test_storage_rejects_out_of_range_volume_index(self):
        with self.assertRaises(QtsError):
            storage(FakeClient(), [0])

    def test_reviewed_ts431k_fixture(self):
        fixture = Path(__file__).parent / "fixtures" / "ts431k-qts-5.2.8-build-20251216"
        result = validate_dump(fixture)
        self.assertTrue(result["valid"])
        self.assertEqual(result["observations"]["system"]["model"], "TS-X41")
        disks = result["observations"]["storage"]["disks"]
        self.assertEqual([disk["disk"] for disk in disks], ["1", "2", "3", "4"])
        self.assertEqual([disk["locator"] for disk in disks], ["0:1", "0:2", "0:3", "0:4"])
        self.assertEqual(disks[1]["model"], "ST2000VN000-1HJ164")
        self.assertEqual(disks[1]["smart"], "Normal")

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
        self.assertEqual(report["healthy_claim"], "not_permitted")
        self.assertIn("不能據此宣告 Storage healthy", report["storage"]["limitations"][0])

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
