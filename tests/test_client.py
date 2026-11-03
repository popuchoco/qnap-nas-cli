import base64
import hashlib
import io
import tempfile
import threading
import unittest
from pathlib import Path
from unittest.mock import patch
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs

from qnap_nas_cli.client import QtsClient
from qnap_nas_cli.config import Config
from qnap_nas_cli.errors import AuthenticationError, QtsError, TwoFactorRequired


class Handler(BaseHTTPRequestHandler):
    password = "secret"
    last_body = b""

    def log_message(self, *_args):
        pass

    def do_POST(self):
        Handler.last_body = self.rfile.read(int(self.headers.get("Content-Length", "0")))
        fields = parse_qs(Handler.last_body.decode("ascii"))
        passed = fields.get("pwd", [""])[0] == base64.b64encode(self.password.encode()).decode()
        body = "<QDocRoot><authPassed>{}</authPassed><authSid>{}</authSid><errorValue>{}</errorValue></QDocRoot>".format(
            "1" if passed else "0", "abc123" if passed else "", "" if passed else "6"
        ).encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/xml")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        body = b"<QDocRoot><hostname>NAS</hostname></QDocRoot>"
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


class ClientTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = HTTPServer(("127.0.0.1", 0), Handler)
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()

    def client(self):
        return QtsClient(Config("http://127.0.0.1:{}".format(self.server.server_port), "admin"))

    def test_login_encodes_password_and_get_appends_sid(self):
        client = self.client()
        self.assertEqual(client.login("secret"), "abc123")
        root = client.get_xml("/cgi", {"subfunc": "sysinfo"})
        self.assertEqual(root.findtext("hostname"), "NAS")

    def test_wrong_password_is_clean_error(self):
        with self.assertRaises(AuthenticationError) as caught:
            self.client().login("wrong")
        self.assertIn("errorValue=6", str(caught.exception))
        self.assertNotIn("wrong", str(caught.exception))

    def test_two_factor_requirement_and_security_code(self):
        needs_2fa = b"<QDocRoot><authPassed>0</authPassed><need_2_step_verification>1</need_2_step_verification></QDocRoot>"
        success = b"<QDocRoot><authPassed>1</authPassed><authSid>twofactor</authSid></QDocRoot>"
        client = self.client()
        with patch.object(client, "_open", return_value=needs_2fa):
            with self.assertRaises(TwoFactorRequired) as caught:
                client.login("secret")
        self.assertIn("2FA", str(caught.exception))
        with patch.object(client, "_open", return_value=success) as opened:
            self.assertEqual(client.login("secret", "123456"), "twofactor")
        fields = parse_qs(opened.call_args.args[0].data.decode("ascii"))
        self.assertEqual(fields["security_code"], ["123456"])
        self.assertEqual(fields["dont_verify_2sv_again"], ["0"])

    def test_download_streams_selected_file_and_returns_hash(self):
        client = self.client()
        client.sid = "abc123"
        body = b"sample-data"
        class Response(io.BytesIO):
            headers = {"Content-Length": str(len(body)), "Content-Type": "application/octet-stream"}
            def __enter__(self):
                return self
            def __exit__(self, *_args):
                self.close()
        with tempfile.TemporaryDirectory() as temp:
            target = Path(temp) / "sample.deadbolt"
            with patch("qnap_nas_cli.client.urllib.request.urlopen", return_value=Response(body)) as opened:
                metadata = client.download_file("/Public", "sample.deadbolt", target)
            self.assertEqual(target.read_bytes(), body)
            self.assertEqual(metadata["sha256"], hashlib.sha256(body).hexdigest())
            request = opened.call_args.args[0]
            self.assertIn("source_path=%2FPublic", request.full_url)

    def test_download_limit_rejects_and_cleans_partial_file(self):
        client = self.client()
        client.sid = "abc123"
        class Response(io.BytesIO):
            headers = {"Content-Type": "application/octet-stream"}
            def __enter__(self):
                return self
            def __exit__(self, *_args):
                self.close()
        with tempfile.TemporaryDirectory() as temp:
            target = Path(temp) / "large.bin"
            with patch("qnap_nas_cli.client.urllib.request.urlopen", return_value=Response(b"12345")):
                with self.assertRaises(QtsError):
                    client.download_file("/Public", "large.bin", target, max_bytes=2)
            self.assertFalse(target.exists())

    def test_download_rejects_path_traversal_and_existing_local_file(self):
        client = self.client()
        client.sid = "abc123"
        with tempfile.TemporaryDirectory() as temp:
            target = Path(temp) / "sample.txt"
            target.write_text("keep", encoding="utf-8")
            with self.assertRaises(QtsError):
                client.download_file("/Public/../secret", "sample.txt", target)
            self.assertEqual(target.read_text(encoding="utf-8"), "keep")
            with self.assertRaises(QtsError):
                client.download_file("/Public", "sample.txt", target)
            self.assertEqual(target.read_text(encoding="utf-8"), "keep")


if __name__ == "__main__":
    unittest.main()
