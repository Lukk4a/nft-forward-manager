"""Installation tests: exercise file operations with no system mutations."""
import contextlib
import importlib.util
from pathlib import Path
import unittest
from unittest.mock import patch

import test_manager as tm

m, HERE = tm.m, tm.HERE

spec = importlib.util.spec_from_file_location("installer", HERE / "install.py")
installer = importlib.util.module_from_spec(spec)
spec.loader.exec_module(installer)


class InstallTests(unittest.TestCase):
    setUp = tm.ManagerTests.setUp
    fake_run = tm.ManagerTests.fake_run
    def test_update_keeps_configuration_and_live_firewall(self):
        m.DESIRED.write_text(m.json_text(self.c), encoding="utf-8")
        m.MANAGER.write_text("old-active-manager", encoding="utf-8")
        m.RULES.write_text("old-live-rules", encoding="utf-8")
        before = self.body
        with patch.object(installer, "RELEASES", Path(self.temp.name) / "releases"), \
             patch.object(installer, "LAUNCHER", Path(self.temp.name) / "nft-forward"):
            installer.install(HERE, manager=m)
            self.assertTrue(installer.LAUNCHER.exists())
            self.assertIn("--config /etc/po0-forwarding/desired.json", installer.LAUNCHER.read_text())
        self.assertEqual(m.load(m.DESIRED), self.c)
        self.assertEqual(m.MANAGER.read_text(), "old-active-manager")
        self.assertEqual(m.RULES.read_text(), "old-live-rules")
        self.assertEqual(self.body, before)
        self.assertEqual(self.calls, [])

    def test_existing_config_is_not_overwritten_by_config_argument(self):
        m.DESIRED.write_text(m.json_text(self.c), encoding="utf-8")
        with patch.object(installer, "RELEASES", Path(self.temp.name) / "releases"), \
             self.assertRaises(ValueError):
            installer.install(HERE, HERE / "tests/fixture.json", manager=m)
        self.assertEqual(m.load(m.DESIRED), self.c)
        self.assertFalse((Path(self.temp.name) / "releases").exists())

    def test_first_install_without_config_does_not_seed_empty_rules(self):
        with patch.object(installer, "RELEASES", Path(self.temp.name) / "releases"), \
             patch.object(installer, "LAUNCHER", Path(self.temp.name) / "nft-forward"):
            installer.install(HERE, manager=m)
        self.assertFalse(m.DESIRED.exists())
        self.assertFalse(m.RULES.exists())
        self.assertEqual(self.calls, [])

    def test_first_install_local_private_config(self):
        with patch.object(installer, "RELEASES", Path(self.temp.name) / "releases"), \
             patch.object(installer, "LAUNCHER", Path(self.temp.name) / "nft-forward"), \
             patch.object(m, "locked", return_value=contextlib.nullcontext()):
            installer.install(HERE, HERE / "tests/fixture.json", manager=m)
        self.assertEqual(m.load(m.DESIRED), self.c)
        self.assertFalse(m.RULES.exists())
        self.assertEqual(self.calls, [])
