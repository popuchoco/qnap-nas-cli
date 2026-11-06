import hashlib
import io
import json
import os
import sys
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch

from qnap_nas_cli.cli import main, parser
from qnap_nas_cli.config import Config
from qnap_nas_cli.errors import QtsError
from qnap_nas_cli.evidence_capsule import validate_attachments, write_evidence_capsule
from qnap_nas_cli.redaction import redact_value


def synthetic_incident_report():
    return {
        "report_type": "qnap_incident_triage",
        "assessment": "suspected",
        "checked_at": "2026-11-06T00:00:00+00:00",
        "ransomware_scan": {
            "assessment": "suspected",
            "coverage": {"truncated": True, "depth_limited": False, "status": "partial"},
            "indicators": [{
                "code": "indicator_code_machine_1234567890",
                "family": "Qlocker-like",
                "examples": ["/Public/operator@example.invalid/!!!READ_ME.txt", "/Public/archive.deadbolt"],
                "interpretation": "token=INDICATOR_TEXT_SECRET",
            }],
        },
        "observations": {
            "health": {
                "status": "unhealthy",
                "findings": [{
                    "code": "finding_machine_code_1234567890",
                    "message": "password=FINDING_SECRET free text must not appear in summary",
                }],
                "unknowns": [{"code": "unknown_machine_code_1234567890", "message": "sid=UNKNOWN_SECRET"}],
                "nested": {"more": [{
                    "webhook_url": "https://hooks.example.invalid/services/WEBHOOK_SECRET",
                    "api_key": "API_KEY_SECRET",
                    "url": "https://service.example.invalid/path/URL_KEY_SECRET",
                    "endpoint": "https://service.example.invalid/hook/ENDPOINT_SECRET",
                    "detail": "request failed at https://service.example.invalid/path/FREE_URL_SECRET",
                }]},
            },
        },
        "collection_errors": [{
            "detail": "Bearer BEARER_SECRET",
            "header": "authorization: Bearer AUTHORIZATION_SECRET",
            "credentials": "api_key=API_KEY_TEXT_SECRET secret_key=SECRET_KEY_TEXT_SECRET",
            "sid": "NESTED_SID_SECRET",
        }],
    }


class EvidenceCapsuleWriterTest(unittest.TestCase):
    def test_report_redaction_summary_codes_coverage_and_manifest_hashes(self):
        report = synthetic_incident_report()
        with tempfile.TemporaryDirectory() as temporary:
            target = Path(temporary) / "capsule"
            receipt = write_evidence_capsule(
                target, report,
                emitted_at=datetime(2026, 11, 6, 1, 2, 3, tzinfo=timezone.utc),
            )
            self.assertTrue(target.is_dir())
            self.assertEqual(receipt["format_version"], 2)
            self.assertEqual(receipt["emitted_at"], "2026-11-06T01:02:03Z")
            self.assertEqual(receipt["directory"], str(target))
            self.assertEqual({path.name for path in target.iterdir()}, {"incident.json", "summary.md", "manifest.json"})

            saved = json.loads((target / "incident.json").read_text(encoding="utf-8"))
            self.assertEqual(saved["assessment"], "suspected")
            self.assertEqual(saved["emitted_at"], receipt["emitted_at"])
            self.assertEqual(saved["ransomware_scan"]["coverage"], report["ransomware_scan"]["coverage"])
            self.assertEqual(saved["ransomware_scan"]["indicators"][0]["examples"], report["ransomware_scan"]["indicators"][0]["examples"])
            self.assertEqual(saved["ransomware_scan"]["indicators"][0]["code"], "indicator_code_machine_1234567890")
            self.assertEqual(saved["observations"]["health"]["findings"][0]["code"], "finding_machine_code_1234567890")
            self.assertEqual(saved["observations"]["health"]["unknowns"][0]["code"], "unknown_machine_code_1234567890")

            contents = "\n".join(path.read_text(encoding="utf-8") for path in target.iterdir())
            for secret in (
                "INDICATOR_TEXT_SECRET", "FINDING_SECRET", "UNKNOWN_SECRET", "WEBHOOK_SECRET",
                "API_KEY_SECRET", "BEARER_SECRET", "AUTHORIZATION_SECRET", "NESTED_SID_SECRET",
                "URL_KEY_SECRET", "ENDPOINT_SECRET", "FREE_URL_SECRET",
                "API_KEY_TEXT_SECRET", "SECRET_KEY_TEXT_SECRET",
            ):
                self.assertNotIn(secret, contents)
            summary = (target / "summary.md").read_text(encoding="utf-8")
            for expected in (
                "Assessment: `suspected`", "Indicator families: `Qlocker-like`",
                "indicator_code_machine_1234567890", "finding_machine_code_1234567890",
                "unknown_machine_code_1234567890", "truncated=true", "depth_limited=false",
            ):
                self.assertIn(expected, summary)
            self.assertNotIn("free text must not appear", summary)

            manifest = json.loads((target / "manifest.json").read_text(encoding="utf-8"))
            self.assertEqual(manifest["evidence_scope"], "local capsule only; not full forensics; no claim of complete NAS logs or disk image")
            self.assertEqual({item["name"] for item in manifest["files"]}, {"incident.json", "summary.md"})
            for item in manifest["files"]:
                raw = (target / item["name"]).read_bytes()
                self.assertEqual(item["size_bytes"], len(raw))
                self.assertEqual(item["sha256"], hashlib.sha256(raw).hexdigest())

    def test_capsule_scrubs_urls_and_credentials_without_changing_general_redaction(self):
        ordinary_url = "https://service.example.invalid/status"
        self.assertEqual(redact_value({"link": ordinary_url})["link"], ordinary_url)
        ordinary_credential_text = "api_key=short-secret"
        self.assertEqual(
            redact_value({"message": ordinary_credential_text})["message"],
            ordinary_credential_text,
        )

        report = synthetic_incident_report()
        with tempfile.TemporaryDirectory() as temporary:
            target = Path(temporary) / "capsule"
            write_evidence_capsule(target, report)
            saved = json.loads((target / "incident.json").read_text(encoding="utf-8"))
        nested = saved["observations"]["health"]["nested"]["more"][0]
        self.assertEqual(nested["url"], "REDACTED")
        self.assertEqual(nested["endpoint"], "REDACTED")
        self.assertEqual(nested["detail"], "request failed at REDACTED_URL")

    def test_attachment_and_rescue_receipt_scrub_metadata_but_preserve_raw_sample(self):
        report = synthetic_incident_report()
        candidate = report["ransomware_scan"]["indicators"][0]["examples"][0]
        raw_sample_canary = b"RAW_NAS_SAMPLE_CANARY"

        def exporter(source, path, remaining):
            self.assertEqual(source, candidate)
            self.assertGreaterEqual(remaining, len(raw_sample_canary))
            path.write_bytes(raw_sample_canary)

        with tempfile.TemporaryDirectory() as temporary:
            target = Path(temporary) / "capsule"
            receipt = write_evidence_capsule(
                target, report, attach_candidates=[candidate], max_bytes=100,
                sample_exporter=exporter, rescue_manifest=True,
            )
            sample = target / "samples" / "sample-001.bin"
            self.assertEqual(sample.read_bytes(), raw_sample_canary)
            sidecar_paths = [
                target / "incident.json", target / "summary.md", target / "manifest.json",
                target / "rescue-manifest.json",
            ]
            sidecars = b"".join(path.read_bytes() for path in sidecar_paths)
            receipt_bytes = json.dumps(receipt, ensure_ascii=False).encode("utf-8")
            for secret in (
                b"INDICATOR_TEXT_SECRET", b"FINDING_SECRET", b"UNKNOWN_SECRET",
                b"WEBHOOK_SECRET", b"API_KEY_SECRET", b"BEARER_SECRET",
                b"AUTHORIZATION_SECRET", b"NESTED_SID_SECRET", b"URL_KEY_SECRET",
                b"ENDPOINT_SECRET", b"FREE_URL_SECRET", b"API_KEY_TEXT_SECRET",
                b"SECRET_KEY_TEXT_SECRET", raw_sample_canary,
            ):
                self.assertNotIn(secret, sidecars)
                self.assertNotIn(secret, receipt_bytes)
            self.assertIn(raw_sample_canary, sample.read_bytes())

    def test_atomic_failure_cleans_staging_and_does_not_publish_partial_capsule(self):
        with tempfile.TemporaryDirectory() as temporary:
            parent = Path(temporary)
            target = parent / "atomic"
            from qnap_nas_cli import evidence_capsule
            original_writer = evidence_capsule._write_staged_file
            calls = []

            def fail_after_one(directory, name, content):
                calls.append(name)
                if len(calls) == 2:
                    raise PermissionError("synthetic staging failure")
                original_writer(directory, name, content)

            with patch("qnap_nas_cli.evidence_capsule._write_staged_file", side_effect=fail_after_one):
                with self.assertRaises(QtsError):
                    write_evidence_capsule(target, synthetic_incident_report())
            self.assertFalse(target.exists())
            self.assertEqual(list(parent.iterdir()), [])

    def test_atomic_replace_failure_preserves_existing_empty_destination(self):
        with tempfile.TemporaryDirectory() as temporary:
            parent = Path(temporary)
            target = parent / "empty-target"
            target.mkdir()
            with patch("qnap_nas_cli.evidence_capsule.os.replace", side_effect=OSError("synthetic rename failure")):
                with self.assertRaises(QtsError):
                    write_evidence_capsule(target, synthetic_incident_report())
            self.assertTrue(target.is_dir())
            self.assertEqual(list(target.iterdir()), [])
            self.assertEqual(list(parent.iterdir()), [target])

    def test_rejects_protected_nonempty_and_symlink_destinations_but_accepts_empty(self):
        report = synthetic_incident_report()
        with tempfile.TemporaryDirectory() as temporary:
            parent = Path(temporary)
            with self.assertRaises(QtsError):
                write_evidence_capsule(Path("/"), report)
            with self.assertRaises(QtsError):
                write_evidence_capsule(Path.cwd(), report)
            with self.assertRaises(QtsError):
                write_evidence_capsule(Path.home(), report)

            nonempty = parent / "nonempty"
            nonempty.mkdir()
            marker = nonempty / "keep.txt"
            marker.write_text("keep", encoding="utf-8")
            with self.assertRaises(FileExistsError):
                write_evidence_capsule(nonempty, report)
            self.assertEqual(marker.read_text(encoding="utf-8"), "keep")

            link = parent / "link"
            link.symlink_to(nonempty, target_is_directory=True)
            with self.assertRaises(QtsError):
                write_evidence_capsule(link, report)
            self.assertTrue(link.is_symlink())

            empty = parent / "empty"
            empty.mkdir()
            write_evidence_capsule(empty, report)
            self.assertTrue((empty / "manifest.json").is_file())

    def test_candidate_whitelist_path_traversal_and_aggregate_size_are_fail_closed(self):
        report = synthetic_incident_report()
        candidate = report["ransomware_scan"]["indicators"][0]["examples"][0]
        with self.assertRaises(QtsError):
            validate_attachments(report, ["/Public/not-listed.txt"], 100)
        traversal_report = synthetic_incident_report()
        traversal_report["ransomware_scan"]["indicators"][0]["examples"].append("/Public/../secret.txt")
        with self.assertRaises(QtsError):
            validate_attachments(traversal_report, ["/Public/../secret.txt"], 100)
        with self.assertRaises(QtsError):
            validate_attachments(report, [candidate], 0)
        with self.assertRaises(QtsError):
            validate_attachments(report, [candidate] * 101, 100)

        with tempfile.TemporaryDirectory() as temporary:
            target = Path(temporary) / "too-large"
            calls = []

            def overrun(source, path, remaining):
                calls.append((source, remaining))
                path.write_bytes(b"123456")

            with self.assertRaises(QtsError):
                write_evidence_capsule(
                    target, report, attach_candidates=[candidate], max_bytes=5,
                    sample_exporter=overrun,
                )
            self.assertEqual(calls, [(candidate, 5)])
            self.assertFalse(target.exists())
            self.assertEqual(list(Path(temporary).iterdir()), [])

    def test_multiple_attachments_cannot_exceed_the_combined_byte_cap(self):
        report = synthetic_incident_report()
        candidates = report["ransomware_scan"]["indicators"][0]["examples"]
        calls = []

        def aggregate_overrun(source, path, remaining):
            calls.append((source, remaining))
            if len(calls) == 1:
                path.write_bytes(b"1234")
            else:
                path.write_bytes(b"567")

        with tempfile.TemporaryDirectory() as temporary:
            parent = Path(temporary)
            target = parent / "aggregate-too-large"
            with self.assertRaises(QtsError):
                write_evidence_capsule(
                    target, report, attach_candidates=candidates, max_bytes=6,
                    sample_exporter=aggregate_overrun,
                )
            self.assertEqual(calls, [(candidates[0], 6), (candidates[1], 2)])
            self.assertFalse(target.exists())
            self.assertEqual(list(parent.iterdir()), [])

    def test_bounded_samples_are_safe_named_and_included_in_manifest(self):
        report = synthetic_incident_report()
        candidates = report["ransomware_scan"]["indicators"][0]["examples"]
        exported = []

        def exporter(source, path, remaining):
            payload = source.rsplit("/", 1)[-1].encode("utf-8")
            self.assertLessEqual(len(payload), remaining)
            path.write_bytes(payload)
            exported.append(source)

        with tempfile.TemporaryDirectory() as temporary:
            target = Path(temporary) / "attached"
            receipt = write_evidence_capsule(
                target, report, attach_candidates=candidates, max_bytes=100,
                sample_exporter=exporter,
            )
            self.assertEqual(exported, candidates)
            self.assertEqual([sample["name"] for sample in receipt["samples"]], ["samples/sample-001.bin", "samples/sample-002.bin"])
            manifest = json.loads((target / "manifest.json").read_text(encoding="utf-8"))
            files = {item["name"]: item for item in manifest["files"]}
            self.assertEqual(set(files), {"incident.json", "summary.md", "samples/sample-001.bin", "samples/sample-002.bin"})
            for name, item in files.items():
                raw = (target / name).read_bytes()
                self.assertEqual(item["size_bytes"], len(raw))
                self.assertEqual(item["sha256"], hashlib.sha256(raw).hexdigest())


class EvidenceCapsuleCliTest(unittest.TestCase):
    class Client:
        sample_payload = b"synthetic sample bytes"

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc_value, traceback):
            return None

        def download_file(self, source_path, filename, target, max_bytes):
            payload = self.sample_payload
            if len(payload) > max_bytes:
                raise QtsError("sample exceeds limit")
            target.write_bytes(payload)
            return {"path": str(target), "size_bytes": len(payload), "sha256": hashlib.sha256(payload).hexdigest(), "max_bytes": max_bytes}

    def setUp(self):
        self.report = synthetic_incident_report()

    def test_evidence_cli_accepts_repeatable_bounded_attachments(self):
        args = parser().parse_args([
            "incident", "evidence", "report.json", "case",
            "--attach-candidate", "/Public/a.txt", "--attach-candidate", "/Public/b.txt",
            "--max-bytes", "20",
        ])
        self.assertEqual(args.attach_candidate, ["/Public/a.txt", "/Public/b.txt"])
        self.assertEqual(args.max_bytes, 20)

    def test_existing_incident_evidence_cli_writes_capsule_and_rejects_nonempty_exit_two(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            report_path = root / "report.json"
            report_path.write_text(json.dumps(self.report), encoding="utf-8")
            target = root / "evidence"
            with patch.object(sys, "stdout", io.StringIO()):
                self.assertEqual(main(["incident", "evidence", str(report_path), str(target)]), 0)
            self.assertTrue((target / "incident.json").is_file())
            self.assertTrue((target / "summary.md").is_file())
            self.assertTrue((target / "manifest.json").is_file())
            stderr = io.StringIO()
            with patch.object(sys, "stderr", stderr), patch.object(sys, "stdout", io.StringIO()):
                self.assertEqual(main(["incident", "evidence", str(report_path), str(target)]), 2)
            self.assertIn("error:", stderr.getvalue())

    def test_cli_rejects_sample_symlink_and_nonregular_files_and_cleans_staging(self):
        class InvalidExporterClient(self.Client):
            def __init__(self, kind, symlink_target):
                self.kind = kind
                self.symlink_target = symlink_target

            def download_file(self, source_path, filename, target, max_bytes):
                if self.kind == "symlink":
                    target.symlink_to(self.symlink_target)
                elif self.kind == "fifo":
                    os.mkfifo(target)
                else:
                    target.mkdir()

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            report_path = root / "report.json"
            report_path.write_text(json.dumps(self.report), encoding="utf-8")
            symlink_target = root / "source.bin"
            symlink_target.write_bytes(b"outside the capsule")
            config = Config("https://nas.invalid", "ops")
            kinds = ["symlink", "directory"]
            if hasattr(os, "mkfifo") and hasattr(os, "O_NONBLOCK"):
                kinds.append("fifo")

            for kind in kinds:
                with self.subTest(kind=kind):
                    target = root / ("invalid-" + kind)
                    stderr = io.StringIO()
                    client = InvalidExporterClient(kind, symlink_target)
                    with patch("qnap_nas_cli.cli._config", return_value=config), \
                         patch("qnap_nas_cli.cli.QtsClient", return_value=client), \
                         patch("qnap_nas_cli.cli._login"), \
                         patch.object(sys, "stderr", stderr), patch.object(sys, "stdout", io.StringIO()):
                        result = main([
                            "incident", "evidence", str(report_path), str(target),
                            "--attach-candidate", self.report["ransomware_scan"]["indicators"][0]["examples"][0],
                        ])
                    self.assertEqual(result, 2)
                    self.assertIn("error:", stderr.getvalue())
                    self.assertFalse(target.exists())
                    self.assertEqual(set(root.iterdir()), {report_path, symlink_target})

    def test_incident_evidence_cli_streams_only_report_examples(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            report_path = root / "report.json"
            report_path.write_text(json.dumps(self.report), encoding="utf-8")
            target = root / "attached-case"
            candidate = self.report["ransomware_scan"]["indicators"][0]["examples"][1]
            config = Config("https://nas.invalid", "ops")
            with patch("qnap_nas_cli.cli._config", return_value=config), \
                 patch("qnap_nas_cli.cli.QtsClient", return_value=self.Client()), \
                 patch("qnap_nas_cli.cli._login"), \
                 patch.object(sys, "stdout", io.StringIO()):
                self.assertEqual(main([
                    "incident", "evidence", str(report_path), str(target),
                    "--attach-candidate", candidate, "--max-bytes", "100",
                ]), 0)
            self.assertEqual((target / "samples" / "sample-001.bin").read_bytes(), b"synthetic sample bytes")
            manifest = json.loads((target / "manifest.json").read_text(encoding="utf-8"))
            self.assertIn("samples/sample-001.bin", {item["name"] for item in manifest["files"]})

            rejected_target = root / "rejected-case"
            stderr = io.StringIO()
            with patch("qnap_nas_cli.cli._config", return_value=config), \
                 patch.object(sys, "stderr", stderr), patch.object(sys, "stdout", io.StringIO()):
                self.assertEqual(main([
                    "incident", "evidence", str(report_path), str(rejected_target),
                    "--attach-candidate", "/Public/not-an-example.txt",
                ]), 2)
            self.assertFalse(rejected_target.exists())
            self.assertIn("indicator", stderr.getvalue())

    def test_scan_evidence_dir_uses_shared_writer_and_keeps_scan_exit_contract(self):
        with tempfile.TemporaryDirectory() as temporary:
            target = Path(temporary) / "scan-case"
            config = Config("https://nas.invalid", "ops")
            with patch("qnap_nas_cli.cli._config", return_value=config), \
                 patch("qnap_nas_cli.cli.QtsClient", return_value=self.Client()), \
                 patch("qnap_nas_cli.cli._login"), \
                 patch("qnap_nas_cli.cli.incident_report", return_value=self.report), \
                 patch("qnap_nas_cli.cli.maybe_notify_incident", return_value=None), \
                 patch("qnap_nas_cli.cli.webhook_enabled", return_value=False), \
                 patch.object(sys, "stdout", io.StringIO()):
                self.assertEqual(main(["incident", "scan", "--evidence-dir", str(target)]), 0)
            saved = json.loads((target / "incident.json").read_text(encoding="utf-8"))
            self.assertEqual(saved["assessment"], "suspected")
            self.assertTrue((target / "manifest.json").is_file())

    def test_rescue_candidate_uses_shared_capsule_writer_and_safe_sample_name(self):
        class RawCanaryClient(self.Client):
            sample_payload = b"RAW_NAS_SAMPLE_CANARY"

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            report_path = root / "report.json"
            report_path.write_text(json.dumps(self.report), encoding="utf-8")
            target = root / "rescue-case"
            candidate = self.report["ransomware_scan"]["indicators"][0]["examples"][0]
            config = Config("https://nas.invalid", "ops")
            output = io.StringIO()
            with patch("qnap_nas_cli.cli._config", return_value=config), \
                 patch("qnap_nas_cli.cli.QtsClient", return_value=RawCanaryClient()), \
                 patch("qnap_nas_cli.cli._login"), \
                 patch.object(sys, "stdout", output):
                result = main([
                    "incident", "rescue", str(report_path), "--candidate-path", candidate,
                    "--directory", str(target), "--max-bytes", "100",
                ])
            self.assertEqual(result, 0)
            self.assertEqual((target / "samples" / "sample-001.bin").read_bytes(), b"RAW_NAS_SAMPLE_CANARY")
            self.assertTrue((target / "rescue-manifest.json").is_file())
            manifest = json.loads((target / "manifest.json").read_text(encoding="utf-8"))
            self.assertEqual(manifest["format_version"], 2)
            self.assertIn("samples/sample-001.bin", {item["name"] for item in manifest["files"]})
            sidecars = b"".join(
                path.read_bytes() for path in (
                    target / "incident.json", target / "summary.md", target / "manifest.json",
                    target / "rescue-manifest.json",
                )
            )
            for secret in (
                "INDICATOR_TEXT_SECRET", "FINDING_SECRET", "UNKNOWN_SECRET", "WEBHOOK_SECRET",
                "API_KEY_SECRET", "BEARER_SECRET", "AUTHORIZATION_SECRET", "NESTED_SID_SECRET",
                "URL_KEY_SECRET", "ENDPOINT_SECRET", "FREE_URL_SECRET", "API_KEY_TEXT_SECRET",
                "SECRET_KEY_TEXT_SECRET", "RAW_NAS_SAMPLE_CANARY",
            ):
                self.assertNotIn(secret.encode("utf-8"), sidecars)
                self.assertNotIn(secret, output.getvalue())

    def test_cli_help_exposes_capsule_attachment_options(self):
        with self.assertRaises(SystemExit) as raised:
            with patch.object(sys, "stdout", io.StringIO()):
                main(["incident", "evidence", "--help"])
        self.assertEqual(raised.exception.code, 0)


if __name__ == "__main__":
    unittest.main()
