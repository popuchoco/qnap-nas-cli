import unittest

from qnap_nas_cli.mcp import TOOLS, response


class McpTest(unittest.TestCase):
    def test_tools_are_read_only_named(self):
        names = {tool["name"] for tool in TOOLS}
        self.assertEqual(names, {"qts_status", "qts_health", "qts_storage", "qts_network", "qts_tailscale"})

    def test_json_rpc_response(self):
        self.assertEqual(response(7, result={"ok": True})["id"], 7)
        self.assertTrue(response(7, result={"ok": True})["result"]["ok"])


if __name__ == "__main__":
    unittest.main()
