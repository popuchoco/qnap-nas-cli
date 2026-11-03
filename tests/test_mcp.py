import unittest

from qnap_nas_cli.config import Config
from qnap_nas_cli.mcp import TOOLS, handle_line, response


class McpTest(unittest.TestCase):
    config = Config("http://127.0.0.1:8080", "test")
    def test_tools_are_read_only_named(self):
        names = {tool["name"] for tool in TOOLS}
        self.assertEqual(names, {"qts_status", "qts_health", "qts_storage", "qts_network", "qts_tailscale"})

    def test_json_rpc_response(self):
        self.assertEqual(response(7, result={"ok": True})["id"], 7)
        self.assertTrue(response(7, result={"ok": True})["result"]["ok"])

    def test_parse_error_never_reuses_previous_request_id(self):
        first = handle_line('{"jsonrpc":"2.0","id":7,"method":"ping"}', self.config)
        invalid = handle_line('{not-json', self.config)
        self.assertEqual(first["id"], 7)
        self.assertIsNone(invalid["id"])
        self.assertEqual(invalid["error"]["code"], -32700)

    def test_non_object_and_invalid_params_are_rejected(self):
        scalar = handle_line('[]', self.config)
        params = handle_line('{"jsonrpc":"2.0","id":8,"method":"tools/list","params":[]}', self.config)
        self.assertEqual(scalar["error"]["code"], -32600)
        self.assertEqual(params["id"], 8)
        self.assertEqual(params["error"]["code"], -32602)

    def test_notification_has_no_response(self):
        self.assertIsNone(handle_line('{"jsonrpc":"2.0","method":"ping"}', self.config))


if __name__ == "__main__":
    unittest.main()
