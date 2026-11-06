import unittest
from pathlib import Path
from unittest.mock import patch

from qnap_nas_cli.config import Config
from qnap_nas_cli.mcp import TOOLS, call_tool, handle_line, response
from qnap_nas_cli.errors import QtsError


class McpTest(unittest.TestCase):
    config = Config("http://127.0.0.1:8080", "test")
    def test_tools_are_read_only_named(self):
        names = {tool["name"] for tool in TOOLS}
        self.assertEqual(names, {"qts_status", "qts_health", "qts_storage", "qts_network", "qts_tailscale", "qts_raid", "qts_smart_details", "qts_disk_topology", "qts_services", "qts_incident"})

    def test_smart_details_schema_requires_bounded_disk(self):
        tool = next(tool for tool in TOOLS if tool["name"] == "qts_smart_details")
        self.assertEqual(tool["inputSchema"]["properties"]["disk"], {"type": "integer", "minimum": 1, "maximum": 64})
        self.assertEqual(tool["inputSchema"]["required"], ["disk"])

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

    def test_storage_and_incident_arguments_are_bounded_before_network_access(self):
        with self.assertRaises(QtsError):
            call_tool(self.config, "qts_storage", {"volume_indices": [0]})
        with self.assertRaises(QtsError):
            call_tool(self.config, "qts_incident", {"max_items": 100001})
        with self.assertRaises(QtsError):
            call_tool(self.config, "qts_incident", {"apply": True})

    def test_smart_details_rejects_missing_and_extra_arguments(self):
        for arguments in ({}, {"disk": 2, "extra": True}):
            with self.subTest(arguments=arguments), self.assertRaises(QtsError):
                call_tool(self.config, "qts_smart_details", arguments)

    def test_smart_details_rejects_out_of_range_disk(self):
        for disk in (0, -1, 65):
            with self.subTest(disk=disk), self.assertRaises(QtsError):
                call_tool(self.config, "qts_smart_details", {"disk": disk})

    def test_smart_details_rejects_non_integer_disk(self):
        for disk in ("2", 1.5, True):
            with self.subTest(disk=disk), self.assertRaises(QtsError):
                call_tool(self.config, "qts_smart_details", {"disk": disk})

    def test_smart_details_calls_command_without_web_login(self):
        expected = {"backend": "ssh", "disk": 2, "attributes": []}
        with patch("qnap_nas_cli.mcp.smart_details", return_value=expected) as smart:
            result = call_tool(self.config, "qts_smart_details", {"disk": 2})
        self.assertEqual(result, expected)
        smart.assert_called_once_with(self.config, 2)


    def test_smart_details_uses_fixed_ssh_argv_not_shell(self):
        from qnap_nas_cli import ssh_backend

        captured = {}

        def fake_run(config, command_name, disk=0):
            captured["command_name"] = command_name
            captured["disk"] = disk
            self.assertEqual(command_name, "smart_attributes")
            self.assertTrue(1 <= disk <= 64)
            argv = ["/sbin/get_hd_smartinfo", "-d", str(disk)]
            captured["argv"] = argv
            self.assertNotIn("/bin/sh", argv)
            self.assertNotIn("-c", argv)
            return ""

        with patch("qnap_nas_cli.ssh_backend.run_ssh", side_effect=fake_run):
            result = call_tool(self.config, "qts_smart_details", {"disk": 3})
        self.assertEqual(captured["argv"], ["/sbin/get_hd_smartinfo", "-d", "3"])
        self.assertEqual(result["disk"], 3)
        self.assertEqual(result["backend"], "ssh")
        source = Path(ssh_backend.__file__).read_text(encoding="utf-8")
        self.assertIn('["/sbin/get_hd_smartinfo", "-d", str(disk)]', source)
        self.assertNotIn("/bin/sh -c", source)


if __name__ == "__main__":
    unittest.main()
