import hashlib
import io
import json
import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

from qnap_nas_cli.cli import main, parser
from qnap_nas_cli.config import Config
from qnap_nas_cli.errors import QtsError
from qnap_nas_cli.health_report import _write_staged_file, write_health_report


def synthetic_observation(status="unhealthy"):
    return {
        "status": status,
        "healthy": False if status == "unhealthy" else None,
        "checked_at": "2026-11-06T00:00:00+00:00",
        "system": {"model": "MODEL-SYNTHETIC", "firmware": "0.0-test", "build": "synthetic-build"},
        "findings": [{"code": "disk_health", "severity": "warning", "message": "password=PRIVATE_MESSAGE_CANARY"}],
        "unknowns": [{"code": "storage_scope_unverified", "message": "sid=UNKNOWN_MESSAGE_CANARY"}],
        "nested": {"integration": {"api_key": "API_KEY_CANARY", "secret_key": "SECRET_KEY_CANARY"}},
    }


class HealthReportWriterTest(unittest.TestCase):
    def setUp(self):
        self.emitted_at = datetime(2026, 11, 6, 12, 34, 56, tzinfo=timezone(timedelta(hours=8)))

    def test_creates_timestamped_files_with_injected_utc_time_and_hashes(self):
        with tempfile.TemporaryDirectory() as temporary:
            target = Path(temporary) / "daily-report"
            receipt = write_health_report(target, synthetic_observation(), emitted_at=self.emitted_at)

            self.assertEqual(receipt["emitted_at"], "2026-11-06T04:34:56Z")
            self.assertEqual(receipt["files"], [
                "health-20261106T043456Z.json",
                "health-20261106T043456Z.md",
                "manifest.sha256",
            ])
            self.assertTrue(target.is_dir())
            self.assertEqual(sorted(path.name for path in target.iterdir()), sorted(receipt["files"]))

            manifest = (target / "manifest.sha256").read_text(encoding="ascii")
            for line in manifest.splitlines():
                digest, name = line.split("  ", 1)
                self.assertEqual(digest, hashlib.sha256((target / name).read_bytes()).hexdigest())

            report = json.loads((target / receipt["files"][0]).read_text(encoding="utf-8"))
            self.assertEqual(report["status"], "unhealthy")
            self.assertEqual(report["emitted_at"], receipt["emitted_at"])

    def test_summary_contains_codes_and_device_identity_without_free_text(self):
        with tempfile.TemporaryDirectory() as temporary:
            target = Path(temporary) / "summary"
            receipt = write_health_report(target, synthetic_observation(), emitted_at=self.emitted_at)
            summary = (target / receipt["files"][1]).read_text(encoding="utf-8")

        for expected in (
            "Status: `unhealthy`", "Finding codes: `disk_health`",
            "Unknown codes: `storage_scope_unverified`", "model=`MODEL-SYNTHETIC`",
            "firmware=`0.0-test`", "build=`synthetic-build`", "2026-11-06T04:34:56Z",
        ):
            self.assertIn(expected, summary)
        self.assertNotIn("PRIVATE_MESSAGE_CANARY", summary)
        self.assertNotIn("UNKNOWN_MESSAGE_CANARY", summary)

    def test_recursive_redaction_covers_json_summary_and_manifest_inputs(self):
        observation = synthetic_observation()
        observation["system"].update({
            "hostname": "HOST_CANARY",
            "serial_number": "SERIAL_CANARY",
            "ip": "203.0.113.77",
            "comment": "sid=SESSION_CANARY password=PASSWORD_CANARY",
        })
        with tempfile.TemporaryDirectory() as temporary:
            target = Path(temporary) / "redacted"
            receipt = write_health_report(target, observation, emitted_at=self.emitted_at)
            contents = "".join(path.read_text(encoding="utf-8") for path in target.iterdir())

        for secret in (
            "HOST_CANARY", "SERIAL_CANARY", "203.0.113.77", "SESSION_CANARY",
            "PASSWORD_CANARY", "API_KEY_CANARY", "SECRET_KEY_CANARY",
            "PRIVATE_MESSAGE_CANARY", "UNKNOWN_MESSAGE_CANARY",
        ):
            self.assertNotIn(secret, contents)
        self.assertEqual(receipt["status"], "unhealthy")

    def test_existing_empty_directory_is_allowed_but_nonempty_and_symlink_are_refused(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            empty = root / "empty"
            empty.mkdir()
            write_health_report(empty, synthetic_observation(), emitted_at=self.emitted_at)

            nonempty = root / "nonempty"
            nonempty.mkdir()
            marker = nonempty / "keep.txt"
            marker.write_text("keep", encoding="utf-8")
            with self.assertRaises(QtsError):
                write_health_report(nonempty, synthetic_observation(), emitted_at=self.emitted_at)
            self.assertEqual(marker.read_text(encoding="utf-8"), "keep")

            link = root / "link"
            link.symlink_to(nonempty, target_is_directory=True)
            with self.assertRaises(QtsError):
                write_health_report(link, synthetic_observation(), emitted_at=self.emitted_at)

    def test_staging_failure_leaves_no_partial_final_files(self):
        with tempfile.TemporaryDirectory() as temporary:
            target = Path(temporary) / "atomic"
            calls = []

            def fail_during_staging(directory, name, content):
                calls.append(name)
                if len(calls) == 2:
                    raise PermissionError("synthetic write failure")
                _write_staged_file(directory, name, content)

            with patch("qnap_nas_cli.health_report._write_staged_file", side_effect=fail_during_staging):
                with self.assertRaises(QtsError):
                    write_health_report(target, synthetic_observation(), emitted_at=self.emitted_at)
            self.assertFalse(target.exists())
            self.assertEqual(list(Path(temporary).iterdir()), [])

    def test_missing_parent_is_created_and_unwritable_parent_is_reported(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            target = root / "missing" / "nested" / "report"
            write_health_report(target, synthetic_observation(), emitted_at=self.emitted_at)
            self.assertTrue((target / "manifest.sha256").is_file())

            blocker = root / "not-a-directory"
            blocker.write_text("synthetic", encoding="utf-8")
            with self.assertRaises(OSError):
                write_health_report(blocker / "report", synthetic_observation(), emitted_at=self.emitted_at)

            unwritable = root / "unwritable"
            unwritable.mkdir()
            with patch("qnap_nas_cli.health_report.os.access", return_value=False):
                with self.assertRaises(QtsError):
                    write_health_report(unwritable, synthetic_observation(), emitted_at=self.emitted_at)
            self.assertEqual(list(unwritable.iterdir()), [])


class HealthReportCliTest(unittest.TestCase):
    class Client:
        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc_value, traceback):
            return None

    def test_nested_cli_surface_and_webhook_flags(self):
        args = parser().parse_args(["report", "health", "--directory", "out", "--no-webhook"])
        self.assertEqual(args.command, "report")
        self.assertEqual(args.report_command, "health")
        self.assertFalse(args.webhook)
        self.assertTrue(parser().parse_args(["--webhook", "report", "health", "--directory", "out"]).webhook)

        with tempfile.TemporaryDirectory() as temporary:
            config = Config("https://nas.invalid", "ops")
            for index, flags in enumerate(([], ["--webhook"], ["--no-webhook"])):
                target = Path(temporary) / "report-{}".format(index)
                with patch("qnap_nas_cli.cli._config", return_value=config), \
                     patch("qnap_nas_cli.cli.QtsClient", return_value=self.Client()), \
                     patch("qnap_nas_cli.cli._login"), \
                     patch("qnap_nas_cli.cli.health", return_value=synthetic_observation("indeterminate")), \
                     patch("qnap_nas_cli.cli.maybe_notify_health", return_value=None) as notify, \
                     patch("qnap_nas_cli.cli.webhook_enabled", return_value=False), \
                     patch.object(sys, "stdout", io.StringIO()):
                    code = main(["report", "health", "--directory", str(target)] + flags)
                self.assertEqual(code, 0)
                expected = None if not flags else flags[0] == "--webhook"
                self.assertEqual(notify.call_args.kwargs["force"], expected)

    def test_health_status_keeps_health_exit_code_and_report_failure_returns_two(self):
        config = Config("https://nas.invalid", "ops")
        with tempfile.TemporaryDirectory() as temporary:
            target = Path(temporary) / "unhealthy"
            with patch("qnap_nas_cli.cli._config", return_value=config), \
                 patch("qnap_nas_cli.cli.QtsClient", return_value=self.Client()), \
                 patch("qnap_nas_cli.cli._login"), \
                 patch("qnap_nas_cli.cli.health", return_value=synthetic_observation("unhealthy")), \
                 patch("qnap_nas_cli.cli.maybe_notify_health", return_value=None), \
                 patch("qnap_nas_cli.cli.webhook_enabled", return_value=False), \
                 patch.object(sys, "stdout", io.StringIO()):
                self.assertEqual(main(["report", "health", "--directory", str(target)]), 0)
            self.assertTrue((target / "manifest.sha256").is_file())

            error = io.StringIO()
            with patch("qnap_nas_cli.cli._config", return_value=config), \
                 patch("qnap_nas_cli.cli.QtsClient", return_value=self.Client()), \
                 patch("qnap_nas_cli.cli._login"), \
                 patch("qnap_nas_cli.cli.health", return_value=synthetic_observation()), \
                 patch("qnap_nas_cli.cli.maybe_notify_health", return_value=None), \
                 patch("qnap_nas_cli.cli.webhook_enabled", return_value=False), \
                 patch("qnap_nas_cli.cli.write_health_report", side_effect=OSError("unwritable")), \
                 patch.object(sys, "stderr", error):
                self.assertEqual(main(["report", "health", "--directory", str(Path(temporary) / "failed")]), 2)
            self.assertIn("error:", error.getvalue())


if __name__ == "__main__":
    unittest.main()
