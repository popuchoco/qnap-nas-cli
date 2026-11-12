import io
import json
import unittest
from unittest.mock import patch

from qnap_nas_cli.cli import main, parser
from qnap_nas_cli.commands import legacy_ransomware_audit
from qnap_nas_cli.config import Config
from qnap_nas_cli.errors import QtsError
from qnap_nas_cli.legacy_ransomware import QSNATCH_CONTROLS, assess_legacy_ransomware, parse_qsnatch_control, parse_version
from qnap_nas_cli.mcp import call_tool
from qnap_nas_cli.ssh_backend import ALLOWED_COMMANDS, legacy_ransomware_packages


def package(installed, version=None, enabled=None):
    return {"installed": installed, "version": version, "enabled": enabled, "qpkg_status": None}


def sample(product="QTS", firmware="4.5.2", hbs="16.0.0415", photo_installed=False, photo=None):
    return assess_legacy_ransomware(
        {"model": "TS-SAMPLE", "firmware_product": product, "firmware": firmware, "build": "123456"},
        {
            "hbs3": package(True, hbs, True),
            "photo_station": package(photo_installed, photo, True if photo_installed else None),
            "malware_remover": package(True, "5.6.0", True),
            "security_center": package(True, "3.0.0", True),
            "security_counselor": package(False),
        },
    )


class LegacyRansomwareAssessmentTest(unittest.TestCase):
    def test_strict_version_parser(self):
        self.assertEqual(parse_version("16.0.0415"), (16, 0, 415))
        self.assertIsNone(parse_version("16.0.0415-beta"))
        self.assertIsNone(parse_version(""))

    def test_qsa_21_13_hbs_baseline_boundaries(self):
        self.assertEqual(sample(hbs="16.0.0414")["package_posture"]["hbs3"]["status"], "vulnerable")
        self.assertEqual(sample(hbs="16.0.0415")["package_posture"]["hbs3"]["status"], "patched")
        self.assertEqual(sample(firmware="4.3.6", hbs="3.0.210411")["package_posture"]["hbs3"]["status"], "vulnerable")
        self.assertEqual(sample(firmware="4.3.4", hbs="3.0.210411")["package_posture"]["hbs3"]["status"], "patched")
        self.assertEqual(sample(product="QuTS hero", firmware="h4.5.1", hbs="16.0.0419")["package_posture"]["hbs3"]["status"], "patched")
        self.assertEqual(sample(product="QuTScloud", firmware="c4.5.4", hbs="16.0.0418")["package_posture"]["hbs3"]["status"], "vulnerable")

    def test_qsa_22_24_photo_station_baselines_and_eol(self):
        result = sample(firmware="5.0.1", photo_installed=True, photo="6.1.1")
        self.assertEqual(result["package_posture"]["photo_station"]["status"], "vulnerable")
        self.assertIn("photo_station_end_of_service", [item["code"] for item in result["findings"]])
        fixed = sample(firmware="4.5.9", photo_installed=True, photo="6.0.22")
        self.assertEqual(fixed["package_posture"]["photo_station"]["status"], "patched")
        self.assertEqual(sample(firmware="5.2.8", photo_installed=True, photo="6.1.2")["package_posture"]["photo_station"]["status"], "unknown")

    def test_unlisted_firmware_stays_unknown_and_never_clean(self):
        report = sample(product="QTS", firmware="5.2.8", hbs="25.1.0")
        self.assertEqual(report["assessment"], "indeterminate")
        self.assertEqual(report["package_posture"]["hbs3"]["status"], "unknown")
        self.assertFalse(report["automation_supported"])
        self.assertTrue(report["unknowns"])
        self.assertNotIn("clean", report["assessment"])

    def test_historical_and_current_exposure_are_separated(self):
        packages = {
            "hbs3": package(True, "16.0.0414", True),
            "photo_station": package(False),
            "malware_remover": package(True, "5.6", True),
            "security_center": package(True, "3.0", True),
            "security_counselor": package(False),
        }
        system = {"firmware_product": "QTS", "firmware": "4.5.2"}
        historical = assess_legacy_ransomware(system, packages, historical_exposure="yes")
        current = assess_legacy_ransomware(system, packages, current_exposure="yes")
        self.assertEqual(historical["assessment"], "potentially_compromised")
        self.assertEqual(current["assessment"], "vulnerable_exposed")

    def test_qsnatch_security_apps_are_metadata_only_and_freshness_unknown(self):
        report = sample()
        self.assertEqual(report["security_apps"]["freshness"], "unknown")
        self.assertEqual(report["security_apps"]["scan_completed"], "unknown")
        self.assertTrue(any(item["code"] == "malware_remover_freshness_unverified" for item in report["unknowns"]))
        self.assertTrue(any("QSnatch" in item for item in report["recommended_actions"]))

    def test_qsnatch_controls_are_operator_reported_and_missing_stays_unknown(self):
        report = sample()
        controls = report["qsnatch_security_controls"]["controls"]
        self.assertEqual(len(controls), len(QSNATCH_CONTROLS))
        self.assertTrue(all(item["status"] == "unknown" for item in controls.values()))
        self.assertTrue(any(item["code"] == "qsnatch_control_unknown_unused_services_disabled" for item in report["unknowns"]))
        self.assertTrue(any(item["code"] == "qsnatch_control_not_confirmed_accounts_reviewed" for item in assess_legacy_ransomware(
            {"firmware_product": "QTS", "firmware": "4.5.2"},
            {"hbs3": package(True, "16.0.0415"), "photo_station": package(False)},
            qsnatch_controls={"accounts_reviewed": "no"},
        )["findings"]))

    def test_patched_posture_requires_explicit_no_exposure_and_all_controls_confirmed(self):
        system = {"firmware_product": "QTS", "firmware": "4.5.2"}
        packages = {"hbs3": package(True, "16.0.0415"), "photo_station": package(False)}
        controls = {name: "yes" for name in QSNATCH_CONTROLS}
        self.assertEqual(assess_legacy_ransomware(system, packages, qsnatch_controls=controls)["assessment"], "indeterminate")
        self.assertEqual(assess_legacy_ransomware(
            system, packages, historical_exposure="no", current_exposure="no", qsnatch_controls=controls,
        )["assessment"], "patched")

    def test_qsnatch_cli_control_parser_is_allowlisted(self):
        self.assertEqual(parse_qsnatch_control("qts_latest=yes"), ("qts_latest", "yes"))
        for value in ("arbitrary_command=yes", "qts_latest=maybe", "qts_latest"):
            with self.subTest(value=value), self.assertRaises(ValueError):
                parse_qsnatch_control(value)

    def test_photo_station_exposure_promotes_triage_without_claiming_compromise(self):
        report = sample(firmware="5.0.1", photo_installed=True, photo="6.1.2")
        report = assess_legacy_ransomware(
            {"firmware_product": "QTS", "firmware": "5.0.1"},
            {
                "hbs3": package(False), "photo_station": package(True, "6.1.2", True),
                "malware_remover": package(True, "5.0", True), "security_center": package(True, "3", True),
            },
            current_exposure="yes",
        )
        self.assertEqual(report["assessment"], "suspected")
        self.assertIn("legacy_photo_station_currently_exposed", [item["code"] for item in report["findings"]])

    def test_exposure_input_is_strict(self):
        with self.assertRaises(ValueError):
            assess_legacy_ransomware({}, {}, current_exposure=True)


class LegacyRansomwareWiringTest(unittest.TestCase):
    def test_ssh_probes_are_fixed_allowlist_without_shell(self):
        expected = {
            "legacy_hbs3_version": ["/sbin/getcfg", "HybridBackup", "Version", "-f", "/etc/config/qpkg.conf"],
            "legacy_hbs3_enabled": ["/sbin/getcfg", "HybridBackup", "Enable", "-f", "/etc/config/qpkg.conf"],
            "legacy_photo_station_version": ["/sbin/getcfg", "PhotoStation", "Version", "-f", "/etc/config/qpkg.conf"],
            "legacy_photo_station_enabled": ["/sbin/getcfg", "PhotoStation", "Enable", "-f", "/etc/config/qpkg.conf"],
        }
        for key, command in expected.items():
            self.assertEqual(ALLOWED_COMMANDS[key][0], command)
            self.assertNotIn("/bin/sh", command)
            self.assertNotIn("-c", command)

    def test_package_collector_retains_unknown_on_probe_failure(self):
        config = Config("https://nas.invalid", "ops", ssh_host="nas", ssh_user="ops")
        with patch("qnap_nas_cli.ssh_backend.run_ssh", side_effect=QtsError("unavailable")):
            result = legacy_ransomware_packages(config)
        self.assertIsNone(result["hbs3"]["installed"])
        self.assertIsNone(result["photo_station"]["version"])

    def test_cli_parser_and_dispatch(self):
        args = parser().parse_args([
            "security", "audit", "legacy-ransomware", "--historical-internet-exposure", "yes",
            "--qsnatch-control", "qts_latest=yes", "--json",
        ])
        self.assertEqual(args.audit_command, "legacy-ransomware")
        self.assertEqual(args.historical_internet_exposure, "yes")
        self.assertEqual(args.qsnatch_control, [("qts_latest", "yes")])

        class Client:
            def __enter__(self): return self
            def __exit__(self, *args): return None

        config = Config("https://nas.invalid", "ops")
        output = io.StringIO()
        expected = {"assessment": "indeterminate"}
        with patch("qnap_nas_cli.cli._config", return_value=config), \
             patch("qnap_nas_cli.cli.QtsClient", return_value=Client()), \
             patch("qnap_nas_cli.cli._login"), \
             patch("qnap_nas_cli.cli.legacy_ransomware_audit", return_value=expected) as audit, \
             patch("sys.stdout", output):
            code = main(["security", "audit", "legacy-ransomware", "--historical-internet-exposure", "yes",
                         "--qsnatch-control", "qts_latest=yes", "--json"])
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(output.getvalue()), expected)
        audit.assert_called_once()

    def test_mcp_only_accepts_documented_exposure_answers(self):
        config = Config("https://nas.invalid", "ops")
        expected = {"assessment": "indeterminate"}
        with patch("qnap_nas_cli.mcp._web_call", return_value=expected) as call:
            result = call_tool(config, "qts_legacy_ransomware_security", {"current_internet_exposure": "no"})
        self.assertEqual(result, expected)
        call.assert_called_once()
        for invalid in ({"command": "rm -rf /"}, {"current_internet_exposure": "unknown"}):
            with self.subTest(invalid=invalid), self.assertRaises(QtsError):
                call_tool(config, "qts_legacy_ransomware_security", invalid)
        fake_client = object()
        with patch("qnap_nas_cli.mcp._web_call", side_effect=lambda cfg, operation: operation(fake_client)) as call, \
             patch("qnap_nas_cli.mcp.legacy_ransomware_audit", return_value=expected) as audit:
            call_tool(config, "qts_legacy_ransomware_security", {
                "qsnatch_controls": {"qts_latest": "yes", "accounts_reviewed": "no"},
            })
        audit.assert_called_once_with(fake_client, config, None, None, {"qts_latest": "yes", "accounts_reviewed": "no"})
        call.assert_called_once()


if __name__ == "__main__":
    unittest.main()
