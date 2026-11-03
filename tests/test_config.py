import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from qnap_nas_cli.config import Config, load_config, save_config
from qnap_nas_cli.errors import QtsError


class ConfigTest(unittest.TestCase):
    def test_rejects_remote_http(self):
        with self.assertRaises(QtsError):
            Config("http://192.0.2.10:8080", "admin").validate()

    def test_accepts_local_http(self):
        self.assertEqual(Config("http://localhost:8080/", "admin").validate().origin, "http://localhost:8080")

    def test_roundtrip_does_not_contain_password(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "config.json"
            save_config(Config("https://nas.example", "ops"), path)
            raw = path.read_text(encoding="utf-8")
            self.assertNotIn("password", raw.lower())
            self.assertEqual(load_config(path).username, "ops")

    def test_roundtrip_keeps_non_secret_ssh_identity_path(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "config.json"
            save_config(Config("https://nas.example", "ops", ssh_identity_file="C:/keys/qnap"), path)
            self.assertEqual(load_config(path).ssh_identity_file, "C:/keys/qnap")


if __name__ == "__main__":
    unittest.main()
