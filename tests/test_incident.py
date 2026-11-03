import hashlib
import json
import tempfile
import unittest
from pathlib import Path

from qnap_nas_cli.incident import response_plan, scan_ransomware_artifacts, write_evidence_bundle


class FakeFileStation:
    def __init__(self, entries=None, fail_path=None):
        self.entries = entries or {}
        self.fail_path = fail_path
        self.calls = []

    def get_json(self, path, params):
        self.calls.append(dict(params))
        if params.get("node") == "share_root":
            return [{"id": "/Public", "text": "Public"}]
        folder = params["path"]
        if folder == self.fail_path:
            from qnap_nas_cli.errors import QtsError
            raise QtsError("permission denied")
        rows = self.entries.get(folder, [])
        start = int(params["start"])
        limit = int(params["limit"])
        page = rows[start:start + limit]
        return {"total": len(rows), "real_total": len(rows), "datas": page}


class IncidentTest(unittest.TestCase):
    def test_known_artifacts_are_detected_but_scope_is_explicit(self):
        entries = [
            {"filename": "!!!READ_ME.txt", "isfolder": 0},
            {"filename": "backup.deadbolt", "isfolder": 0},
        ] + [{"filename": "archive-{}.7z".format(index), "isfolder": 0} for index in range(12)]
        client = FakeFileStation({"/Public": entries})
        result = scan_ransomware_artifacts(client)
        self.assertEqual(result["assessment"], "suspected")
        self.assertEqual(result["coverage"]["status"], "bounded_complete_for_visible_shares")
        codes = {item["code"] for item in result["indicators"]}
        self.assertEqual(codes, {"deadbolt_extension", "qlocker_ransom_note", "qlocker_archive_cluster"})
        self.assertIn("不等同", result["note"])
        self.assertEqual(client.calls[0]["hidden_file"], "1")
        self.assertEqual(client.calls[0]["check_acl"], "1")

    def test_no_match_is_indeterminate_not_clean(self):
        result = scan_ransomware_artifacts(FakeFileStation({"/Public": [{"filename": "photo.jpg", "isfolder": 0}]}))
        self.assertEqual(result["assessment"], "indeterminate")
        self.assertFalse(result["indicators"])

    def test_exact_item_cap_is_complete_when_provider_total_matches(self):
        result = scan_ransomware_artifacts(FakeFileStation({"/Public": [{"filename": "one.txt", "isfolder": 0}]}), max_items=1)
        self.assertFalse(result["coverage"]["truncated"])
        self.assertEqual(result["coverage"]["status"], "bounded_complete_for_visible_shares")

    def test_recursive_scan_obeys_item_limit_and_marks_partial(self):
        entries = [{"filename": "nested", "isfolder": 1}] + [{"filename": "{}.txt".format(i), "isfolder": 0} for i in range(20)]
        result = scan_ransomware_artifacts(FakeFileStation({"/Public": entries}), max_items=5)
        self.assertEqual(result["coverage"]["entries_scanned"], 5)
        self.assertTrue(result["coverage"]["truncated"])
        self.assertEqual(result["coverage"]["status"], "partial")

    def test_paged_file_station_listing_reaches_reported_total(self):
        rows = [{"filename": "file-{}.txt".format(i), "isfolder": 0} for i in range(250)]
        client = FakeFileStation({"/Public": rows})
        result = scan_ransomware_artifacts(client, max_items=500)
        starts = [int(call["start"]) for call in client.calls if call.get("func") == "get_list"]
        self.assertEqual(starts, [0, 200])
        self.assertEqual(result["coverage"]["entries_scanned"], 250)
        self.assertEqual(result["coverage"]["status"], "bounded_complete_for_visible_shares")

    def test_boolean_folder_flag_is_recursed(self):
        client = FakeFileStation({"/Public": [{"filename": "nested", "isfolder": True}], "/Public/nested": [{"filename": "x.deadbolt", "isfolder": False}]})
        result = scan_ransomware_artifacts(client)
        self.assertEqual(result["assessment"], "suspected")
        self.assertEqual(result["coverage"]["folders_scanned"], 2)

    def test_scan_query_failure_degrades_to_indeterminate(self):
        class Broken(FakeFileStation):
            def get_json(self, path, params):
                from qnap_nas_cli.errors import QtsError
                raise QtsError("offline")
        result = scan_ransomware_artifacts(Broken())
        self.assertEqual(result["assessment"], "indeterminate")
        self.assertEqual(result["coverage"]["status"], "partial")

    def test_response_plan_is_manual_and_never_claims_actions(self):
        plan = response_plan({"assessment": "suspected"})
        self.assertFalse(plan["automation_supported"])
        self.assertEqual(plan["actions_applied"], [])
        self.assertEqual(plan["status"], "manual_response_required")

    def test_evidence_bundle_is_new_directory_and_hashes_report(self):
        with tempfile.TemporaryDirectory() as temp:
            target = Path(temp) / "evidence"
            manifest = write_evidence_bundle(target, {"assessment": "indeterminate"})
            raw = (target / "incident.json").read_bytes()
            self.assertEqual(manifest["files"][0]["sha256"], hashlib.sha256(raw).hexdigest())
            self.assertEqual(json.loads((target / "manifest.json").read_text(encoding="utf-8"))["format_version"], 1)
            with self.assertRaises(FileExistsError):
                write_evidence_bundle(target, {})


if __name__ == "__main__":
    unittest.main()
