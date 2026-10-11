"""Regression tests for /api/exec hardening: real isolation, token auth,
allowlist, path traversal and symlink-safe commits."""
import json
import os
import socket
import tempfile
import unittest
import unittest.mock
import urllib.error
import urllib.request
from pathlib import Path

from agent_capsule_jail.capsule import (CapsuleConfig, CapsuleRunner, CapsuleSecurityError,
                                        build_bwrap_argv, sandbox_mode)
from agent_capsule_jail.server import CapsuleServer

HAS_BWRAP = sandbox_mode() == "bwrap"


@unittest.skipUnless(HAS_BWRAP, "bubblewrap not installed")
class TestIsolation(unittest.TestCase):
    def setUp(self):
        self.runner = CapsuleRunner()

    def test_home_is_hidden(self):
        home = str(Path.home())
        r = self.runner.run(["sh", "-c", f"ls -A {home} | wc -l"])
        self.assertEqual(r.stdout.strip(), "0", r.stderr)

    def test_host_files_read_only(self):
        r = self.runner.run(["sh", "-c", "touch /usr/capsule_probe 2>&1 || echo DENIED"])
        self.assertIn("DENIED", r.stdout)
        self.assertFalse(Path("/usr/capsule_probe").exists())

    def test_cannot_escalate_with_sudo(self):
        r = self.runner.run(["sh", "-c", "sudo -n id -u 2>&1; echo rc=$?"])
        self.assertNotIn("\n0\n", "\n" + r.stdout)
        self.assertNotIn("rc=0", r.stdout)

    def test_no_network_by_default(self):
        code = ("import socket\ns=socket.socket();s.settimeout(2)\n"
                "try:\n s.connect(('1.1.1.1',53));print('NET')\nexcept OSError:print('NONET')")
        r = self.runner.run(["python3", "-c", code])
        self.assertIn("NONET", r.stdout, r.stderr)

    def test_scratch_still_writable(self):
        r = self.runner.run(["sh", "-c", "echo hi > out.txt && cat out.txt"])
        self.assertEqual(r.stdout.strip(), "hi", r.stderr)
        self.assertEqual(r.fs_diff.to_dict()["created"][0]["path"] if hasattr(r.fs_diff, "to_dict") else "out.txt", "out.txt")


class TestPolicy(unittest.TestCase):
    def setUp(self):
        self.runner = CapsuleRunner()

    def test_initial_files_traversal_rejected(self):
        for bad in ("../escape.txt", "/etc/evil", "a/../../x"):
            with self.assertRaises(CapsuleSecurityError):
                self.runner.run(["true"], config=CapsuleConfig(initial_files={bad: "x"}))

    def test_commit_outside_roots_rejected(self):
        with tempfile.TemporaryDirectory() as root, tempfile.TemporaryDirectory() as other, \
                unittest.mock.patch.dict(os.environ, {"CAPSULE_COMMIT_ROOTS": root}):
            with self.assertRaises(CapsuleSecurityError):
                self.runner.run(["sh", "-c", "echo x > f"],
                                config=CapsuleConfig(commit=True, destination_dir=other))

    def test_commit_skips_symlinks(self):
        with tempfile.TemporaryDirectory() as root, \
                unittest.mock.patch.dict(os.environ, {"CAPSULE_COMMIT_ROOTS": root}):
            r = self.runner.run(["sh", "-c", "ln -s /etc/hostname leak && echo ok > real.txt"],
                                config=CapsuleConfig(commit=True, destination_dir=root))
            self.assertTrue(r.committed)
            self.assertTrue((Path(root) / "real.txt").exists())
            self.assertFalse((Path(root) / "leak").exists())

    def test_allowlist(self):
        with unittest.mock.patch.dict(os.environ, {"CAPSULE_ALLOWED_COMMANDS": "echo"}):
            self.assertEqual(self.runner.run(["echo", "ok"]).stdout.strip(), "ok")
            with self.assertRaises(CapsuleSecurityError):
                self.runner.run(["python3", "-c", "1"])
            with self.assertRaises(CapsuleSecurityError):
                self.runner.run("echo a; rm -rf x")  # shell form needs 'sh' allowed

    def test_refuses_without_sandbox_unless_opted_in(self):
        env = {"CAPSULE_DISABLE_BWRAP": "1"}
        with unittest.mock.patch.dict(os.environ, env):
            os.environ.pop("CAPSULE_ALLOW_UNSANDBOXED", None)
            with self.assertRaises(CapsuleSecurityError):
                self.runner.run(["true"])
        with unittest.mock.patch.dict(os.environ, {**env, "CAPSULE_ALLOW_UNSANDBOXED": "1"}):
            self.assertEqual(self.runner.run(["true"]).exit_code, 0)

    def test_bwrap_argv_network_toggle(self):
        off = build_bwrap_argv(["true"], Path("/tmp/x"), False)
        on = build_bwrap_argv(["true"], Path("/tmp/x"), True)
        self.assertNotIn("--share-net", off)
        self.assertIn("--share-net", on)
        self.assertIn("--unshare-all", off)
        self.assertIn("--cap-drop", off)


class TestExecAuth(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        s = socket.socket(); s.bind(("127.0.0.1", 0)); cls.port = s.getsockname()[1]; s.close()
        with unittest.mock.patch.dict(os.environ, {"CAPSULE_TOKEN": "s3cret"}):
            cls.server = CapsuleServer(host="127.0.0.1", port=cls.port)
        cls.server.start(block=False)

    @classmethod
    def tearDownClass(cls):
        cls.server.stop()

    def _post(self, headers, body=None):
        req = urllib.request.Request(f"http://127.0.0.1:{self.port}/api/exec",
                                     data=json.dumps(body or {"command": "echo hi"}).encode(),
                                     headers={"Content-Type": "application/json", **headers}, method="POST")
        try:
            with urllib.request.urlopen(req, timeout=10) as r:
                return r.status, json.loads(r.read())
        except urllib.error.HTTPError as e:
            return e.code, json.loads(e.read() or b"{}")

    def test_missing_token_401(self):
        self.assertEqual(self._post({})[0], 401)

    def test_wrong_token_401(self):
        self.assertEqual(self._post({"X-Capsule-Token": "nope"})[0], 401)

    def test_bearer_token_ok(self):
        code, data = self._post({"Authorization": "Bearer s3cret"})
        self.assertEqual(code, 200)
        self.assertEqual(data["stdout"].strip(), "hi")

    def test_policy_violation_400(self):
        code, data = self._post({"X-Capsule-Token": "s3cret"},
                                {"command": "true", "initial_files": {"../x": "y"}})
        self.assertEqual(code, 400)
        self.assertTrue(data.get("policy_violation"))

    def test_cross_origin_blocked_even_with_token(self):
        self.assertEqual(self._post({"X-Capsule-Token": "s3cret", "Origin": "https://evil.example"})[0], 403)


if __name__ == "__main__":
    unittest.main()
