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
            "unknowns": [],
        }
        body = json.dumps(build_payload("health.unhealthy", observation), ensure_ascii=False)
        for secret in ("PASSWORD_SENTINEL", "SID_SENTINEL", "HOST_SENTINEL", "SERIAL_SENTINEL", "203.0.113.55"):
            self.assertNotIn(secret, body)
        payload = json.loads(body)
        self.assertEqual(payload["device"], {"model": "TS-X41", "firmware": "5.2.8", "build": "20251216"})
        self.assertNotIn("password", payload)
        self.assertEqual(set(payload["findings"][0]), {"code", "severity", "message"})

    def test_oversized_findings_are_truncated_and_body_is_capped(self):
        observation = {
            "status": "unhealthy",
            "findings": [{"code": "finding_{}".format(i), "message": "x" * 1000} for i in range(100)],
            "unknowns": [{"code": "unknown_{}".format(i), "message": "y" * 1000} for i in range(100)],
        }
        payload = build_payload("health.unhealthy", observation)
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


    def test_finding_messages_scrub_password_assignments(self):
        payload = build_payload("health.unhealthy", {
            "status": "unhealthy",
            "system": {"model": "TS-X41"},
            "findings": [{"code": "x", "severity": "warning", "message": "password=SUPERSECRET pwd=OTHER"}],
            "unknowns": [],
        })
        rendered = json.dumps(payload)
        self.assertNotIn("SUPERSECRET", rendered)
        self.assertNotIn("OTHER", rendered)
        self.assertIn("password=REDACTED", rendered)


if __name__ == "__main__":
    unittest.main()
