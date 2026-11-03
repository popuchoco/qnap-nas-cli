import base64
import threading
import unittest
from unittest.mock import patch
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs

from qnap_nas_cli.client import QtsClient
from qnap_nas_cli.config import Config
from qnap_nas_cli.errors import AuthenticationError


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
            with self.assertRaises(AuthenticationError) as caught:
                client.login("secret")
        self.assertIn("2FA", str(caught.exception))
        with patch.object(client, "_open", return_value=success) as opened:
            self.assertEqual(client.login("secret", "123456"), "twofactor")
        fields = parse_qs(opened.call_args.args[0].data.decode("ascii"))
        self.assertEqual(fields["security_code"], ["123456"])
        self.assertEqual(fields["dont_verify_2sv_again"], ["0"])


if __name__ == "__main__":
    unittest.main()
