import io
import json
import hashlib
import hmac
import sys
import urllib.error
import unittest
from unittest.mock import patch

from qnap_nas_cli.cli import main, parser
from qnap_nas_cli.config import Config
from qnap_nas_cli.webhook import (
    MAX_BODY_BYTES,
    build_payload,
    deliver_webhook,
    maybe_notify_health,
    maybe_notify_incident,
    webhook_enabled,
)


def _assert_payload_has_no_free_text_items(testcase, value, parent_key=None):
    if isinstance(value, dict):
        testcase.assertNotIn("message", value)
        if parent_key == "findings":
            testcase.assertTrue(set(value).issubset({"code", "severity"}))
            testcase.assertIn("code", value)
        elif parent_key == "unknowns":
            testcase.assertTrue(set(value).issubset({"code"}))
            testcase.assertIn("code", value)
        for key, child in value.items():
            _assert_payload_has_no_free_text_items(testcase, child, key)
    elif isinstance(value, list):
        for child in value:
            _assert_payload_has_no_free_text_items(testcase, child, parent_key)


class _Response:
    def __init__(self, status):
        self.status = status

    def getcode(self):
        return self.status

    def close(self):
        pass


class WebhookTest(unittest.TestCase):
    def test_disabled_by_default_does_not_open_transport(self):
        with patch("qnap_nas_cli.webhook.urllib.request.build_opener") as build_opener:
            result = maybe_notify_health({"status": "unhealthy"}, env={})
        self.assertIsNone(result)
        build_opener.assert_not_called()
        self.assertFalse(webhook_enabled({}))

    def test_http_url_is_rejected_without_transport_call(self):
        transport = unittest.mock.Mock()
        result = deliver_webhook("http://nas.example/hook", b"{}", transport=transport)
        self.assertEqual(result["status"], "rejected")
        self.assertEqual(result["error"], "invalid_url")
        transport.assert_not_called()

    def test_payload_allowlist_omits_secret_and_device_identity_fields(self):
        observation = {
            "status": "unhealthy",
            "password": "PASSWORD_SENTINEL",
            "sid": "SID_SENTINEL",
            "hostname": "HOST_SENTINEL",
            "serial_number": "SERIAL_SENTINEL",
            "ip": "203.0.113.55",
            "system": {
                "model": "TS-X41", "firmware": "5.2.8", "build": "20251216",
                "hostname": "HOST_SENTINEL", "serial_number": "SERIAL_SENTINEL",
                "ip": "203.0.113.55", "password": "PASSWORD_SENTINEL",
            },
            "findings": [{
                "code": "disk_health", "severity": "warning", "message": "SMART warning",
                "password": "PASSWORD_SENTINEL", "sid": "SID_SENTINEL",
            }],
            "unknowns": [{"code": "temperature_unavailable", "message": "detail", "sid": "SID_SENTINEL"}],
        }
        body = json.dumps(build_payload("health.unhealthy", observation), ensure_ascii=False)
        for secret in ("PASSWORD_SENTINEL", "SID_SENTINEL", "HOST_SENTINEL", "SERIAL_SENTINEL", "203.0.113.55"):
            self.assertNotIn(secret, body)
        payload = json.loads(body)
        self.assertEqual(payload["device"], {"model": "TS-X41", "firmware": "5.2.8", "build": "20251216"})
        self.assertNotIn("password", payload)
        self.assertEqual(set(payload["findings"][0]), {"code", "severity"})
        self.assertEqual(set(payload["unknowns"][0]), {"code"})
        _assert_payload_has_no_free_text_items(self, payload)

    def test_oversized_findings_are_truncated_and_body_is_capped(self):
        observation = {
            "status": "unhealthy",
            "findings": [
                {"code": "finding.{}.".format(i) + ("x" * 20 + ".") * 10, "message": "discarded"}
                for i in range(100)
            ],
            "unknowns": [
                {"code": "unknown.{}.".format(i) + ("y" * 20 + ".") * 10, "message": "discarded"}
                for i in range(100)
            ],
        }
        payload = build_payload("health.unhealthy", observation)
        body = json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        self.assertTrue(payload["truncated"])
        self.assertEqual(len(payload["findings"]), 8)
        self.assertEqual(len(payload["unknowns"]), 8)
        self.assertTrue(all(len(item["code"]) == 80 for item in payload["findings"] + payload["unknowns"]))
        _assert_payload_has_no_free_text_items(self, payload)
        self.assertLessEqual(len(body), MAX_BODY_BYTES)

    def test_body_size_reduction_sets_truncated(self):
        oversized_timestamp = ("x" * 20 + ".") * 500
        payload = build_payload("health.unhealthy", {"findings": [], "unknowns": []}, emitted_at=oversized_timestamp)
        body = json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        self.assertTrue(payload["truncated"])
        self.assertLessEqual(len(body), MAX_BODY_BYTES)

    def test_secret_signs_raw_body_and_signature_changes_with_body(self):
        calls = []

        def transport(request, timeout):
            calls.append((request, timeout))
            return _Response(204)

        result1 = deliver_webhook("https://hooks.example/a?token=SECRET_TOKEN", b'{"a":1}', secret="secret", transport=transport)
        result2 = deliver_webhook("https://hooks.example/a?token=SECRET_TOKEN", b'{"a":2}', secret="secret", transport=transport)
        self.assertEqual(result1["status"], "delivered")
        signature1 = calls[0][0].get_header("X-qts-webhook-signature")
        signature2 = calls[1][0].get_header("X-qts-webhook-signature")
        self.assertTrue(signature1.startswith("sha256="))
        self.assertEqual(signature1, "sha256=" + hmac.new(b"secret", b'{"a":1}', hashlib.sha256).hexdigest())
        self.assertNotEqual(signature1, signature2)
        self.assertEqual(calls[0][0].get_header("Content-type"), "application/json; charset=utf-8")

    def test_timeout_urlerror_and_http_500_are_fail_soft(self):
        cases = (
            (lambda request, timeout: (_ for _ in ()).throw(TimeoutError()), "timeout", None),
            (lambda request, timeout: (_ for _ in ()).throw(urllib.error.URLError("connection reset")), "connection_error", None),
            (lambda request, timeout: (_ for _ in ()).throw(urllib.error.HTTPError(request.full_url, 500, "bad", {}, None)), "http_500", 500),
        )
        for transport, error, status in cases:
            with self.subTest(error=error):
                result = deliver_webhook("https://hooks.example/notify", b"{}", transport=transport)
                self.assertEqual(result["status"], "error")
                self.assertEqual(result["error"], error)
                self.assertEqual(result["http_status"], status)

    def test_https_200_and_204_are_delivered(self):
        for status in (200, 204):
            result = deliver_webhook("https://hooks.example/path", b"{}", transport=lambda request, timeout: _Response(status))
            self.assertEqual(result, {"status": "delivered", "http_status": status, "error": None})

    def test_redirect_is_rejected_without_following_it(self):
        class Opener:
            def __init__(self):
                self.calls = 0

            def open(self, request, timeout):
                self.calls += 1
                raise urllib.error.HTTPError(request.full_url, 302, "redirect", {}, None)

        opener = Opener()
        with patch("qnap_nas_cli.webhook.urllib.request.build_opener", return_value=opener):
            result = deliver_webhook("https://hooks.example/path", b"{}")
        self.assertEqual(result["status"], "rejected")
        self.assertEqual(result["http_status"], 302)
        self.assertEqual(opener.calls, 1)

    def test_timeout_is_clamped_and_url_token_never_appears_in_result(self):
        target = "https://hooks.example/path?token=URL_QUERY_SECRET"
        seen = []

        def transport(request, timeout):
            seen.append(timeout)
            raise urllib.error.URLError("failure for {}".format(target))

        result = deliver_webhook(target, b"{}", timeout=99, transport=transport)
        self.assertEqual(seen, [10.0])
        self.assertNotIn("URL_QUERY_SECRET", json.dumps(result))
        self.assertNotIn(target, json.dumps(result))

    def test_indeterminate_requires_opt_in_and_healthy_never_fires(self):
        with patch("qnap_nas_cli.webhook.deliver_webhook", return_value={"status": "delivered", "http_status": 200, "error": None}) as deliver:
            result = maybe_notify_health({"status": "indeterminate"}, env={"QTS_WEBHOOK_URL": "https://hooks.example/x"})
            self.assertEqual(result["status"], "skipped")
            deliver.assert_not_called()
            result = maybe_notify_health(
                {"status": "indeterminate"},
                env={"QTS_WEBHOOK_URL": "https://hooks.example/x", "QTS_WEBHOOK_ON_INDETERMINATE": "yes"},
            )
            self.assertEqual(result["status"], "delivered")
            result = maybe_notify_health({"status": "healthy"}, env={"QTS_WEBHOOK_URL": "https://hooks.example/x"})
            self.assertEqual(result["status"], "skipped")
            self.assertEqual(deliver.call_count, 1)

    def test_suspected_incident_fires_from_either_assessment_location(self):
        with patch("qnap_nas_cli.webhook.deliver_webhook", return_value={"status": "delivered", "http_status": 200, "error": None}) as deliver:
            result = maybe_notify_incident(
                {"ransomware_scan": {"assessment": "suspected", "indicators": []}},
                env={"QTS_WEBHOOK_URL": "https://hooks.example/x"},
            )
        self.assertEqual(result["status"], "delivered")
        self.assertEqual(deliver.call_count, 1)

    def test_cli_flags_are_mutually_exclusive_and_available_after_command(self):
        self.assertTrue(parser().parse_args(["--webhook", "health"]).webhook)
        self.assertFalse(parser().parse_args(["incident", "scan", "--no-webhook"]).webhook)
        with self.assertRaises(SystemExit):
            parser().parse_args(["health", "--webhook", "--no-webhook"])

    def test_cli_health_and_incident_delivery_errors_keep_success_exit_and_output(self):
        class Client:
            def __enter__(self):
                return self

            def __exit__(self, exc_type, exc_value, traceback):
                return None

        env = {"QTS_WEBHOOK_URL": "https://hooks.example/path?token=CLI_QUERY_SECRET"}
        for argv, output_value, operation in (
            (["--json", "health"], {"status": "unhealthy", "findings": [], "unknowns": []}, "health"),
            (["incident", "scan", "--json"], {"assessment": "suspected", "ransomware_scan": {"assessment": "suspected", "indicators": []}}, "incident"),
        ):
            output = io.StringIO()
            errors = io.StringIO()
            with patch.dict("os.environ", env, clear=True), \
                 patch("qnap_nas_cli.cli._config", return_value=Config("https://nas.example", "ops")), \
                 patch("qnap_nas_cli.cli.QtsClient", return_value=Client()), \
                 patch("qnap_nas_cli.cli._login"), \
                 patch("qnap_nas_cli.cli.health", return_value=output_value), \
                 patch("qnap_nas_cli.cli.incident_report", return_value=output_value), \
                 patch("qnap_nas_cli.webhook.urllib.request.build_opener", side_effect=TimeoutError), \
                 patch.object(sys, "stdout", output), patch.object(sys, "stderr", errors):
                code = main(argv)
            self.assertEqual(code, 0, operation)
            rendered = json.loads(output.getvalue())
            self.assertEqual(rendered["status"], "unhealthy") if operation == "health" else self.assertEqual(rendered["assessment"], "suspected")
            self.assertEqual(rendered["webhook"]["status"], "error")
            self.assertIn("webhook warning", errors.getvalue())
            self.assertNotIn("CLI_QUERY_SECRET", errors.getvalue())


    def test_canary_free_text_never_appears_in_payload(self):
        canary = "CANARY_FINDING_TEXT_9f3a"
        health_payload = build_payload("health.unhealthy", {
            "status": "unhealthy " + canary,
            "system": {"model": "TS-X41"},
            "findings": [{"code": "disk_health", "severity": "warning", "message": canary, "details": canary}],
            "unknowns": [{"code": "sensor_unavailable", "message": canary}],
            "description": canary,
        })
        incident_payload = build_payload("incident.suspected", {
            "assessment": "suspected",
            "ransomware_scan": {
                "assessment": "suspected",
                "indicators": [{"code": "deadbolt_note", "family": canary, "message": canary, "count": 7}],
                "coverage": {"status": "partial", "issues": [canary]},
            },
            "collection_errors": [canary],
        })
        for payload in (health_payload, incident_payload):
            rendered = json.dumps(payload, ensure_ascii=False)
            self.assertNotIn(canary, rendered)
            _assert_payload_has_no_free_text_items(self, payload)
        self.assertEqual(health_payload["summary"], "Health outcome: unhealthy (1 finding(s), 1 unknown(s)).")
        self.assertEqual(incident_payload["summary"], "Incident scan assessment: suspected (1 indicator(s)).")
        self.assertEqual(set(incident_payload["findings"][0]), {"code", "severity"})
        self.assertEqual(incident_payload["findings"][0]["severity"], "info")
        self.assertEqual(incident_payload["unknowns"], [
            {"code": "incident_scan_incomplete"},
            {"code": "incident_collection_incomplete"},
        ])


    def test_long_application_codes_survive_redaction(self):
        payload = build_payload("health.unhealthy", {
            "status": "unhealthy",
            "system": {"model": "TS-X41"},
            "findings": [{"code": "storage_scope_unverified", "severity": "warning", "message": "discard"}],
            "unknowns": [{"code": "volume_status_unknown", "message": "discard"}],
        })
        self.assertEqual(payload["findings"][0]["code"], "storage_scope_unverified")
        self.assertEqual(payload["unknowns"][0]["code"], "volume_status_unknown")
        _assert_payload_has_no_free_text_items(self, payload)


if __name__ == "__main__":
    unittest.main()
