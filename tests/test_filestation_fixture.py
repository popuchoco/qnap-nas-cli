import json
import shutil
import tempfile
import unittest
from pathlib import Path

from qnap_nas_cli.commands import validate_dump
from qnap_nas_cli.filestation_fixture import FileStationFixtureClient, capture_filestation
from qnap_nas_cli.incident import FILE_STATION_PATH, scan_ransomware_artifacts


FIXTURES = Path(__file__).parent / "fixtures"
SYNTHETIC = FIXTURES / "filestation-synthetic-shape"


class FixtureCaptureTest(unittest.TestCase):
    def test_capture_is_bounded_redacted_and_records_first_page_metadata(self):
        class Client:
            def __init__(self):
                self.calls = []

            def get_json(self, path, params):
                self.calls.append((path, dict(params)))
                if params["func"] == "get_tree":
                    return [{"id": "/PrivateShare", "text": "PrivateShare", "isfolder": True}]
                return {
                    "status": 1,
                    "real_total": 2,
                    "datas": [
                        {"filename": "normal.txt", "isfolder": 0, "path": "/PrivateShare"},
                        {"filename": "owner@example.invalid", "isfolder": 0},
                    ],
                }

        client = Client()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "filestation"
            manifest = capture_filestation(client, root)
            saved = "\n".join(path.read_text(encoding="utf-8") for path in root.glob("*.json"))
            self.assertNotIn("PrivateShare", saved)
            self.assertNotIn("owner@example.invalid", saved)
            self.assertEqual(manifest["pages"][0]["path"], "/ShareA")
            self.assertEqual(manifest["pages"][0]["total"], 2)
            self.assertEqual(manifest["pages"][0]["returned"], 2)
            self.assertEqual(client.calls[0][0], FILE_STATION_PATH)
            self.assertEqual(client.calls[1][1]["limit"], "200")

    def test_capture_caps_a_provider_response_that_exceeds_the_requested_page(self):
        class OversizedClient:
            def get_json(self, path, params):
                if params["func"] == "get_tree":
                    return [{"id": "/Public", "text": "Public"}]
                return {"real_total": 205, "datas": [{"filename": "item-{}.txt".format(i)} for i in range(205)]}

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            manifest = capture_filestation(OversizedClient(), root)
            page = json.loads((root / "list__ShareA__0.json").read_text(encoding="utf-8"))
        self.assertEqual(len(page["datas"]), 200)
        self.assertEqual(manifest["items_captured"], 200)
        self.assertEqual(manifest["pages"][0]["returned"], 200)
        self.assertTrue(manifest["truncated"])

    def test_clean_replay_is_indeterminate_not_clean(self):
        result = scan_ransomware_artifacts(FileStationFixtureClient(SYNTHETIC / "filestation"))
        self.assertEqual(result["assessment"], "indeterminate")
        self.assertFalse(result["indicators"])
        self.assertEqual(result["coverage"]["status"], "bounded_complete_for_visible_shares")

    def test_ioc_replay_is_suspected_with_expected_codes(self):
        result = scan_ransomware_artifacts(FileStationFixtureClient(SYNTHETIC / "filestation-ioc"))
        self.assertEqual(result["assessment"], "suspected")
        self.assertEqual({item["code"] for item in result["indicators"]}, {"deadbolt_extension", "qlocker_ransom_note"})

    def test_replay_preserves_partial_coverage_when_fixture_page_is_truncated(self):
        result = scan_ransomware_artifacts(FileStationFixtureClient(SYNTHETIC / "filestation-truncated"))
        self.assertEqual(result["assessment"], "indeterminate")
        self.assertEqual(result["coverage"]["status"], "partial")
        self.assertTrue(result["coverage"]["issues"])

    def test_validate_dump_accepts_fixture_and_rejects_dirty_json(self):
        base = FIXTURES / "ts431k-qts-5.2.8-build-20251216"
        with tempfile.TemporaryDirectory() as temporary:
            clean = Path(temporary) / "clean"
            shutil.copytree(base, clean)
            shutil.copytree(SYNTHETIC / "filestation", clean / "filestation")
            result = validate_dump(clean)
            self.assertTrue(result["valid"], result["errors"])
            self.assertTrue(result["filestation"]["valid"])

            dirty = Path(temporary) / "dirty"
            shutil.copytree(base, dirty)
            shutil.copytree(SYNTHETIC / "filestation", dirty / "filestation")
            list_file = dirty / "filestation" / "list__ShareA__0.json"
            payload = json.loads(list_file.read_text(encoding="utf-8"))
            payload["debug"] = "sid=unredacted-session-value"
            list_file.write_text(json.dumps(payload), encoding="utf-8")
            failed = validate_dump(dirty)
            self.assertFalse(failed["valid"])
            self.assertIn("failed", failed["filestation"]["pattern_scan"])


if __name__ == "__main__":
    unittest.main()
