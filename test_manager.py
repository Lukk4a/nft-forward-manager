"""Offline behavior tests. No kernel/network/systemd changes are performed."""
import base64
import contextlib
import copy
import importlib.util
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("po0_manager", HERE / "po0-nft-forward.py")
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)


class ManagerTests(unittest.TestCase):
    def setUp(self):
        self.c = m.load(HERE / "tests" / "fixture.json")
        self.temp = tempfile.TemporaryDirectory(prefix=".test-", dir=HERE)
        self.addCleanup(self.temp.cleanup)
        root = Path(self.temp.name)
        for name in ("RULES", "SYSCTL", "MANAGER", "SERVICE", "DESIRED", "ACTIVE", "IP_FORWARD"):
            original = getattr(m, name)
            p = patch.object(m, name, root / name.lower())
            p.start()
            self.addCleanup(p.stop)
            self.assertNotEqual(original, getattr(m, name))
        for name, value in (("OWNED", tuple(getattr(m, n) for n in ("RULES", "SYSCTL", "MANAGER", "SERVICE", "DESIRED", "ACTIVE"))),
                            ("BACKUPS", root / "backups")):
            p = patch.object(m, name, value)
            p.start()
            self.addCleanup(p.stop)
        m.IP_FORWARD.write_text("0\n")
        self.calls = []
        self.body = "table ip po0_forwarding {\n  chain old {}\n}\n"
        self.enabled, self.active = True, True
        self.listeners = {"tcp": "", "udp": ""}
        self.fail_enable = False
        self.host_patch = patch.object(m, "require_host")
        self.host_patch.start()
        self.addCleanup(self.host_patch.stop)
        p = patch.object(m, "run", side_effect=self.fake_run)
        p.start()
        self.addCleanup(p.stop)
        p = patch.dict(m.os.environ, {"SSH_CONNECTION": ""})
        p.start()
        self.addCleanup(p.stop)

    def fake_run(self, *args, data=None, ok=(0,)):
        self.calls.append((args, data))
        out = ""
        if args[:3] == ("nft", "-j", "list"):
            out = json.dumps({"nftables": [{"table": {"family": "ip", "name": m.TABLE}}] if self.body else []})
        elif args[:3] == ("nft", "-s", "list"):
            out = self.body
        elif args[:3] == ("nft", "-f", "-"):
            self.body = data.split("delete table ip po0_forwarding\n", 1)[1] or None
        elif args[:5] == ("ip", "-j", "-4", "address", "show"):
            out = json.dumps([{"addr_info": [{"family": "inet", "local": "192.0.2.10"}]}])
        elif args[:5] == ("ip", "-j", "-4", "route", "get"):
            out = '[{"dev":"eth0","gateway":"192.0.2.1"}]'
        elif args[0] == "ss":
            out = self.listeners["tcp" if args[-1] == "-lnt" else "udp"]
        elif args[0] == "sysctl":
            m.IP_FORWARD.write_text(args[-1].split("=")[1] + "\n")
        elif args[:2] == ("systemctl", "is-enabled"):
            out = "enabled\n" if self.enabled else "disabled\n"
        elif args[:2] == ("systemctl", "is-active"):
            out = "active\n" if self.active else "inactive\n"
        elif args[:2] == ("systemctl", "enable"):
            if self.fail_enable:
                self.fail_enable = False
                raise m.Error("injected systemd failure after live NAT replacement")
            self.enabled = True
        elif args[:2] == ("systemctl", "disable"):
            self.enabled = False
        elif args[:2] == ("systemctl", "start"):
            self.active = True
        elif args[:2] == ("systemctl", "stop"):
            self.active = False
        return subprocess.CompletedProcess(args, 0, out, "")

    def test_historical_routes_and_no_global_flush(self):
        self.assertEqual([(r["listen_port"], r["target_ip"], r["target_port"]) for r in self.c["rules"]], [
            (60001, "198.51.100.10", 58794), (60002, "198.51.100.10", 61001),
            (60003, "198.51.100.20", 61003), (60004, "198.51.100.10", 61002)])
        text = m.transaction(m.render(self.c))
        self.assertEqual(text.count("dnat to"), 8)
        self.assertEqual(text.count("snat to"), 8)
        self.assertEqual(text.count("delete table"), 1)
        self.assertNotIn("flush ruleset", text)
        self.assertNotIn("f2b", text)
        self.assertIn("fib daddr type local", text)

    def test_duplicate_protocol_port_and_ssh_are_rejected(self):
        r = copy.deepcopy(self.c["rules"][0])
        r["name"] = "duplicate"
        self.c["rules"].append(r)
        with self.assertRaises(m.Error):
            m.validate(self.c)
        self.c["rules"].pop()
        self.c["rules"][0]["listen_port"] = 30012
        with self.assertRaises(m.Error):
            m.validate(self.c)
        self.c["rules"][0]["protocol"] = "udp"
        m.validate(self.c)

    def test_rejects_rule_injection_and_invalid_types(self):
        for field, value in (("target_ip", "1.2.3.4; flush ruleset"), ("name", 'bad";'),
                             ("listen_port", True), ("target_ip", True)):
            c = copy.deepcopy(self.c)
            c["rules"][0][field] = value
            with self.subTest(field=field, value=value), self.assertRaises(m.Error):
                m.validate(c)

    def test_tcp_and_ipv6_listener_conflicts_are_detected_before_backup(self):
        for endpoint in ("0.0.0.0:60001", "[::]:60001", "127.0.0.1:60001"):
            self.listeners["tcp"] = "LISTEN 0 128 {} 0.0.0.0:*\n".format(endpoint)
            with self.subTest(endpoint=endpoint), self.assertRaises(m.Error):
                m.apply(self.c)
            self.assertFalse(m.BACKUPS.exists())

    def test_udp_listener_conflict_and_current_ssh_port(self):
        self.listeners["udp"] = "UNCONN 0 0 0.0.0.0:60003 0.0.0.0:*\n"
        with self.assertRaises(m.Error):
            m.preflight(self.c, m.render(self.c))
        self.listeners["udp"] = ""
        with patch.dict(m.os.environ, {"SSH_CONNECTION": "192.0.2.1 54321 192.0.2.10 60004"}):
            with self.assertRaises(m.Error):
                m.preflight(self.c, m.render(self.c))

    def test_wrong_snat_and_kernel_check_failure_have_no_writes(self):
        self.c["snat_ip"] = "203.0.113.10"
        with self.assertRaises(m.Error):
            m.apply(self.c)
        self.assertFalse(m.BACKUPS.exists())
        self.c["snat_ip"] = "192.0.2.10"
        real = self.fake_run
        def reject(*args, **kwargs):
            if args[:2] == ("nft", "-c"):
                raise m.Error("injected kernel syntax rejection")
            return real(*args, **kwargs)
        with patch.object(m, "run", side_effect=reject), self.assertRaises(m.Error):
            m.apply(self.c)
        self.assertFalse(m.BACKUPS.exists())

    def test_partial_failure_restores_files_runtime_and_service(self):
        m.RULES.write_text("old-rule-file")
        m.SERVICE.write_text("old-service")
        before = self.body
        self.fail_enable = True
        with self.assertRaises(m.Error):
            m.apply(self.c)
        self.assertEqual(self.body, before)
        self.assertEqual(m.RULES.read_text(), "old-rule-file")
        self.assertEqual(m.SERVICE.read_text(), "old-service")
        self.assertEqual(m.IP_FORWARD.read_text().strip(), "0")
        self.assertTrue(self.enabled and self.active)
        self.assertFalse(m.ACTIVE.exists())
        self.assertFalse(m.MANAGER.exists())

    def test_repeat_apply_and_restore_absent_table(self):
        self.body, self.enabled, self.active = None, False, False
        original = m.snapshot()
        m.apply(self.c)
        first_body = self.body
        m.apply(self.c)
        self.assertEqual(self.body, first_body)
        self.assertEqual(self.body.count("dnat to"), 8)
        self.assertEqual(m.load(m.ACTIVE), self.c)
        self.assertTrue(self.enabled and self.active)
        m.restore(original)
        self.assertIsNone(self.body)
        self.assertFalse(self.enabled or self.active)
        self.assertFalse(m.MANAGER.exists())
        self.assertEqual(m.IP_FORWARD.read_text().strip(), "0")

    def test_boot_load_does_not_reenter_apply_lock(self):
        m.RULES.write_text(m.render(self.c), encoding="utf-8")
        with patch.object(m.sys, "argv", ["manager", "boot-load"]), patch.object(m, "locked") as lock:
            m.main()
        lock.assert_not_called()
        self.assertEqual(self.body, m.render(self.c))
        self.assertEqual(m.IP_FORWARD.read_text().strip(), "1")

    def test_interrupt_after_file_change_also_restores(self):
        before = self.body
        real = self.fake_run
        interrupted = False
        def interrupt_once(*args, **kwargs):
            nonlocal interrupted
            if args[:2] == ("systemctl", "enable") and not interrupted:
                interrupted = True
                raise KeyboardInterrupt()
            return real(*args, **kwargs)
        with patch.object(m, "run", side_effect=interrupt_once), self.assertRaises(KeyboardInterrupt):
            m.apply(self.c)
        self.assertEqual(self.body, before)
        self.assertFalse(m.ACTIVE.exists())
        self.assertEqual(m.IP_FORWARD.read_text().strip(), "0")

    def test_manual_rollback_preserves_recovery_snapshot(self):
        before = self.body
        old = m.save_snapshot()
        m.apply(self.c)
        self.assertNotEqual(self.body, before)
        with patch.object(m, "locked", return_value=contextlib.nullcontext()):
            m.rollback(old)
        self.assertEqual(self.body, before)
        self.assertEqual(len(list(m.BACKUPS.glob("*/snapshot.json"))), 3)

    def test_corrupt_backup_is_rejected_and_edit_is_only_staged(self):
        m.RULES.write_text("old-data")
        backup = m.save_snapshot()
        saved = json.loads(backup.read_text())
        saved["files"][str(m.RULES)]["data"] = base64.b64encode(b"corrupted").decode()
        backup.write_text(json.dumps(saved))
        with self.assertRaises(m.Error):
            m.read_snapshot(backup)
        candidate = Path(self.temp.name) / "candidate.json"
        candidate.write_text(json.dumps(self.c))
        before = self.body
        m.edit(candidate, "hk-relay")
        self.assertEqual(len(m.load(candidate)["rules"]), 3)
        self.assertEqual(self.body, before)
        self.assertTrue(candidate.with_name("candidate.json.bak").is_file())


if __name__ == "__main__":
    unittest.main(verbosity=2)
