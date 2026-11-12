import io
import json
import unittest
from unittest.mock import patch

from qnap_nas_cli.cli import main, parser
from qnap_nas_cli.config import Config
from qnap_nas_cli.security import assess_plex2shell, is_patched_version, parse_plex_version
from qnap_nas_cli.errors import QtsError
from qnap_nas_cli.ssh_backend import ALLOWED_COMMANDS, plex_known_process_iocs, plex_qpkg_info, run_ssh


def package(installed=True, version="1.43.3.10861"):
    return {
        "package": "PlexMediaServer",
        "installed": installed,
        "version": version,
        "qpkg_status": "complete" if installed else None,
        "enabled": True if installed else None,
        "data_status": "version_available" if version else "version_unavailable",
        "version_source": "QPKG metadata (/etc/config/qpkg.conf)",
        "runtime_health": "unknown",
    }


class PlexSecurityTest(unittest.TestCase):
    def test_version_parser_and_fixed_baseline_boundaries(self):
        self.assertEqual(parse_plex_version("1.43.3.10861"), (1, 43, 3, 10861))
        self.assertEqual(parse_plex_version("1.43.3"), (1, 43, 3, 0))
        self.assertIsNone(parse_plex_version("1.43"))
        self.assertIsNone(parse_plex_version("1.43.3.10861-custom"))
        self.assertFalse(is_patched_version("1.43.2"))
        self.assertFalse(is_patched_version("1.43.3.10860"))
        self.assertTrue(is_patched_version("1.43.3"))
        self.assertTrue(is_patched_version("1.43.3.10861"))
        self.assertTrue(is_patched_version("1.43.4"))
        self.assertIsNone(is_patched_version("unknown"))

    def test_assessment_preserves_unknown_exposure_and_does_not_claim_clean(self):
        report = assess_plex2shell(package(), checked_at="2026-11-12T00:00:00+00:00")
        self.assertEqual(report["assessment"], "patched")
        self.assertEqual(report["exposure"]["current"], "unknown")
        self.assertTrue(report["unknowns"])
        self.assertFalse(report["automation_supported"])
        self.assertNotIn("clean", report["assessment"])
        self.assertEqual(report["ioc_observations"]["unknown_plex_process"]["value"], "unknown")

    def test_vulnerable_exposure_and_historical_exposure_are_distinguished(self):
        vulnerable = assess_plex2shell(package(version="1.43.2"))
        exposed = assess_plex2shell(package(version="1.43.2"), current_exposure="yes")
        history = assess_plex2shell(package(version="1.43.3.10861"), exposure_during_vulnerable_version="yes")
        self.assertEqual(vulnerable["assessment"], "vulnerable")
        self.assertEqual(exposed["assessment"], "vulnerable_exposed")
        self.assertEqual(history["assessment"], "potentially_compromised")
        self.assertEqual(history["findings"][0]["code"], "historical_exposure_while_vulnerable")
        self.assertIn("Plex", history["recommended_actions"][0])

    def test_patched_but_exposed_and_unknown_version_exposed(self):
        patched = assess_plex2shell(package(), current_exposure="yes")
        unknown = assess_plex2shell(package(version=None), current_exposure="yes")
        self.assertEqual(patched["assessment"], "patched_but_exposed")
        self.assertEqual(unknown["assessment"], "indeterminate")
        self.assertIn("external_exposure_with_unknown_patch_state", [item["code"] for item in unknown["findings"]])

    def test_uninstalled_and_unknown_version_are_not_healthy_claims(self):
        absent = assess_plex2shell(package(installed=False, version=None))
        unknown = assess_plex2shell(package(version="not-a-version"))
        self.assertEqual(absent["assessment"], "not_installed")
        self.assertEqual(unknown["assessment"], "indeterminate")
        self.assertIn("runtime_and_compromise_not_checked", [item["code"] for item in unknown["unknowns"]])

    def test_operator_reported_ioc_yields_suspected_and_evidence_first_plan(self):
        report = assess_plex2shell(package(), indicators={"malware_remover_detection": "yes"})
        historical = assess_plex2shell(
            package(),
            exposure_during_vulnerable_version="yes",
            indicators={"malware_remover_detection": "yes"},
        )
        self.assertEqual(report["assessment"], "suspected")
        self.assertEqual(historical["assessment"], "potentially_compromised")
        self.assertIn("plex_ioc_malware_remover_detection", [item["code"] for item in report["findings"]])
        self.assertEqual(report["ioc_observations"]["malware_remover_detection"]["source"], "operator_reported")
        self.assertIn("Plex", report["recommended_actions"][0])

    def test_unreported_iocs_and_exposure_remain_explicitly_unknown(self):
        report = assess_plex2shell(package(), indicators={"sustained_idle_cpu": "no"})
        self.assertEqual(report["ioc_observations"]["sustained_idle_cpu"]["value"], "no")
        self.assertEqual(report["ioc_observations"]["proxystream_st_connection"]["value"], "unknown")
        self.assertTrue(any(item["code"] == "ioc_proxystream_st_connection_not_collected" for item in report["unknowns"]))

    def test_unknown_ioc_fields_are_rejected(self):
        with self.assertRaises(ValueError):
            assess_plex2shell(package(), indicators={"unreviewed_signal": "yes"})

    def test_opt_in_runtime_probe_checks_only_exact_names_and_reports_match(self):
        config = Config("https://nas.example", "ops", ssh_host="nas", ssh_user="ops")
        with patch("qnap_nas_cli.ssh_backend.run_ssh", side_effect=["", "123 456\n", ""]):
            probe = plex_known_process_iocs(config)
        self.assertEqual(probe["status"], "exact_names_checked")
        self.assertEqual([item["name"] for item in probe["results"]], ["myawesomeproxy", "mylovelyminer", "x12345"])
        self.assertEqual(probe["results"][1], {"name": "mylovelyminer", "status": "found", "match_count": 2})
        self.assertNotIn("123 456", json.dumps(probe))
        report = assess_plex2shell(package(), runtime_iocs=probe)
        self.assertEqual(report["assessment"], "suspected")
        self.assertIn("plex_ioc_known_process_mylovelyminer", [item["code"] for item in report["findings"]])

    def test_runtime_probe_failure_degrades_to_unknown_and_stops_followup_calls(self):
        config = Config("https://nas.example", "ops", ssh_host="nas", ssh_user="ops")
        with patch("qnap_nas_cli.ssh_backend.run_ssh", side_effect=QtsError("probe failed")) as run:
            probe = plex_known_process_iocs(config)
        self.assertEqual(run.call_count, 1)
        self.assertEqual(probe["status"], "partial")
        self.assertEqual([item["status"] for item in probe["results"]], ["unavailable", "not_attempted", "not_attempted"])
        report = assess_plex2shell(package(), runtime_iocs=probe)
        self.assertEqual(report["assessment"], "patched")
        self.assertTrue(any(item["code"] == "runtime_process_probe_scope_limited" for item in report["unknowns"]))

    def test_invalid_exposure_values_are_rejected(self):
        for value in (True, "unknown", "YES"):
            with self.subTest(value=value), self.assertRaises(ValueError):
                assess_plex2shell(package(), current_exposure=value)

    def test_plex_probes_are_fixed_shell_free_allowlist_entries(self):
        expected = {
            "plex_name": ["/sbin/getcfg", "PlexMediaServer", "Name", "-f", "/etc/config/qpkg.conf"],
            "plex_version": ["/sbin/getcfg", "PlexMediaServer", "Version", "-f", "/etc/config/qpkg.conf"],
            "plex_status": ["/sbin/getcfg", "PlexMediaServer", "Status", "-f", "/etc/config/qpkg.conf"],
            "plex_enabled": ["/sbin/getcfg", "PlexMediaServer", "Enable", "-f", "/etc/config/qpkg.conf"],
            "plex_ioc_myawesomeproxy": ["/bin/pidof", "myawesomeproxy"],
            "plex_ioc_mylovelyminer": ["/bin/pidof", "mylovelyminer"],
            "plex_ioc_x12345": ["/bin/pidof", "x12345"],
        }
        for name, argv in expected.items():
            with self.subTest(name=name):
                self.assertEqual(ALLOWED_COMMANDS[name][0], argv)
                self.assertNotIn("-c", argv)
                self.assertNotIn("/bin/sh", argv)
                if name.startswith("plex_ioc_"):
                    self.assertEqual(ALLOWED_COMMANDS[name][1], (0, 1))

    @patch("qnap_nas_cli.ssh_backend.subprocess.run")
    def test_ssh_executes_plex_probe_as_fixed_argv_without_shell(self, run):
        run.return_value = type("Completed", (), {"returncode": 0, "stdout": "1.43.3\n", "stderr": ""})()
        result = run_ssh(Config("https://nas.example", "ops", ssh_host="nas", ssh_user="ops"), "plex_version")
        args = run.call_args.args[0]
        self.assertEqual(result, "1.43.3\n")
        self.assertEqual(args[args.index("--") + 2:], ALLOWED_COMMANDS["plex_version"][0])
        self.assertNotIn("-c", args)
        self.assertNotIn("/bin/sh", args)

    @patch("qnap_nas_cli.ssh_backend.subprocess.run")
    def test_known_process_probe_uses_fixed_pidof_argv(self, run):
        run.return_value = type("Completed", (), {"returncode": 1, "stdout": "", "stderr": ""})()
        run_ssh(Config("https://nas.example", "ops", ssh_host="nas", ssh_user="ops"), "plex_ioc_mylovelyminer")
        args = run.call_args.args[0]
        self.assertEqual(args[args.index("--") + 2:], ["/bin/pidof", "mylovelyminer"])
        self.assertNotIn("-c", args)
        self.assertNotIn("/bin/sh", args)

    @patch("qnap_nas_cli.ssh_backend.run_ssh", side_effect=["PlexMediaServer\n", "1.43.3\n", "complete\n", "TRUE\n"])
    def test_package_observation_is_metadata_only(self, run):
        result = plex_qpkg_info(Config("https://nas.example", "ops", ssh_host="nas", ssh_user="ops"))
        self.assertTrue(result["installed"])
        self.assertEqual(result["version"], "1.43.3")
        self.assertEqual(result["runtime_health"], "unknown")
        self.assertEqual(run.call_count, 4)

    def test_runtime_probes_are_opt_in_at_command_layer(self):
        from qnap_nas_cli.commands import plex2shell_audit

        config = Config("https://nas.example", "ops", ssh_host="nas", ssh_user="ops")
        with patch("qnap_nas_cli.commands.plex_qpkg_info", return_value=package()), \
             patch("qnap_nas_cli.commands.plex_known_process_iocs", return_value=None) as probes:
            not_requested = plex2shell_audit(config)
            self.assertEqual(not_requested["runtime_ioc_probes"]["status"], "not_requested")
            probes.assert_not_called()
            plex2shell_audit(config, check_known_process_iocs=True)
            probes.assert_called_once_with(config)

    def test_plex_ssh_collection_failure_is_explicit_unknown_and_stops_followups(self):
        from qnap_nas_cli.commands import plex2shell_audit

        config = Config("https://nas.example", "ops", ssh_host="nas", ssh_user="ops")
        with patch("qnap_nas_cli.ssh_backend.run_ssh", side_effect=QtsError("connection timeout")) as collect, \
             patch("qnap_nas_cli.commands.plex_known_process_iocs") as runtime:
            report = plex2shell_audit(config, check_known_process_iocs=True)
        self.assertEqual(collect.call_count, 1)
        runtime.assert_not_called()
        self.assertEqual(report["assessment"], "indeterminate")
        self.assertIsNone(report["package"]["installed"])
        self.assertEqual(report["collection_errors"][0]["code"], "ssh_collection_failed")
        self.assertEqual(report["runtime_ioc_probes"]["status"], "partial")
        self.assertTrue(all(item["status"] == "not_attempted" for item in report["runtime_ioc_probes"]["results"]))

    def test_cli_parser_accepts_operator_reported_exposure_and_json(self):
        args = parser().parse_args([
            "security", "audit", "plex2shell",
            "--current-exposure", "no", "--exposure-during-vulnerable-version", "yes",
            "--ioc-proxystream-st-connection", "yes", "--check-known-process-iocs", "--json",
        ])
        self.assertEqual(args.current_exposure, "no")
        self.assertEqual(args.exposure_during_vulnerable_version, "yes")
        self.assertEqual(args.ioc_proxystream_st_connection, "yes")
        self.assertTrue(args.check_known_process_iocs)
        self.assertTrue(args.json)

    def test_cli_dispatch_is_read_only_and_forwards_only_exposure_answers(self):
        config = Config("https://nas.example", "ops", ssh_host="nas", ssh_user="ops")
        output = io.StringIO()
        expected = {"assessment": "patched", "automation_supported": False}
        with patch("qnap_nas_cli.cli._config", return_value=config), \
             patch("qnap_nas_cli.cli.plex2shell_audit", return_value=expected) as audit, \
             patch("sys.stdout", output):
            code = main(["security", "audit", "plex2shell", "--current-exposure", "no", "--ioc-unknown-plex-process", "yes", "--json"])
        self.assertEqual(code, 0)
        audit.assert_called_once_with(config, None, "no", {"unknown_plex_process": "yes"}, False)
        self.assertEqual(json.loads(output.getvalue()), expected)


if __name__ == "__main__":
    unittest.main()
