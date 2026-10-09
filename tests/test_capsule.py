"""Automated unit and integration test suite for agent-capsule-jail.

Engineered by Neal Frazier Tech (@1nc0gn30) • NullAI Platform.
100% Python Standard Library — Zero External Dependencies.
"""

from __future__ import annotations

import json
import os
import shutil
import tempfile
import time
import unittest
import urllib.request
from pathlib import Path

from agent_capsule_jail.capsule import (
    CapsuleConfig,
    CapsuleResult,
    CapsuleRunner,
    FilesystemDelta,
    ResourceLimits,
)
from agent_capsule_jail.server import CapsuleServer
from agent_capsule_jail.telemetry import TelemetryRegistry


class TestCapsuleCore(unittest.TestCase):
    """Test sandboxed execution and resource quota enforcement."""

    def setUp(self) -> None:
        self.runner = CapsuleRunner()

    def test_basic_execution_success(self) -> None:
        result = self.runner.run(["python3", "-c", "print('hello from sandbox')"])
        self.assertEqual(result.exit_code, 0)
        self.assertEqual(result.status, "success")
        self.assertIn("hello from sandbox", result.stdout)
        self.assertFalse(result.timed_out)
        self.assertFalse(result.memory_exceeded)
        self.assertGreater(result.duration_ms, 0)

    def test_environment_sanitization_strips_secrets(self) -> None:
        os.environ["OPENAI_API_KEY"] = "sk-secret-leaked-key"
        os.environ["STRIPE_KEY"] = "rk_live_9999"
        os.environ["AWS_SECRET_ACCESS_KEY"] = "wJalrXUtnFEMI/K7MDENG/bPxRfiCY"
        os.environ["GITHUB_TOKEN"] = "ghp_1234567890"
        os.environ["SAFE_CUSTOM_VAR"] = "should_be_stripped_by_default"

        try:
            # 1. Without allowed_env
            result = self.runner.run([
                "python3", "-c",
                "import os; "
                "print('OPENAI:', os.environ.get('OPENAI_API_KEY')); "
                "print('STRIPE:', os.environ.get('STRIPE_KEY')); "
                "print('AWS:', os.environ.get('AWS_SECRET_ACCESS_KEY')); "
                "print('GH:', os.environ.get('GITHUB_TOKEN')); "
                "print('SAFE:', os.environ.get('SAFE_CUSTOM_VAR'))"
            ])
            self.assertEqual(result.exit_code, 0)
            self.assertIn("OPENAI: None", result.stdout)
            self.assertIn("STRIPE: None", result.stdout)
            self.assertIn("AWS: None", result.stdout)
            self.assertIn("GH: None", result.stdout)
            self.assertIn("SAFE: None", result.stdout)

            # 2. With safe variable explicitly allowed
            cfg = CapsuleConfig(allowed_env=["SAFE_CUSTOM_VAR"])
            result2 = self.runner.run([
                "python3", "-c",
                "import os; print('SAFE:', os.environ.get('SAFE_CUSTOM_VAR'))"
            ], config=cfg)
            self.assertEqual(result2.exit_code, 0)
            self.assertIn("SAFE: should_be_stripped_by_default", result2.stdout)

        finally:
            os.environ.pop("OPENAI_API_KEY", None)
            os.environ.pop("STRIPE_KEY", None)
            os.environ.pop("AWS_SECRET_ACCESS_KEY", None)
            os.environ.pop("GITHUB_TOKEN", None)
            os.environ.pop("SAFE_CUSTOM_VAR", None)

    def test_timeout_enforcement(self) -> None:
        cfg = CapsuleConfig(limits=ResourceLimits(timeout_sec=0.8))
        result = self.runner.run([
            "python3", "-c", "import time; time.sleep(4)"
        ], config=cfg)
        self.assertTrue(result.timed_out)
        self.assertEqual(result.status, "timeout")
        self.assertLess(result.duration_ms, 3000)

    def test_filesystem_delta_diffing(self) -> None:
        cfg = CapsuleConfig(initial_files={"pre_existing.txt": "initial data"})
        code = (
            "import os\n"
            "with open('created_file.json', 'w') as f: f.write('{\"key\": 1}')\n"
            "with open('pre_existing.txt', 'w') as f: f.write('mutated data')\n"
        )
        result = self.runner.run(["python3", "-c", code], config=cfg)
        self.assertEqual(result.exit_code, 0)
        fs = result.fs_diff
        self.assertEqual(len(fs["created"]), 1)
        self.assertEqual(fs["created"][0]["path"], "created_file.json")
        self.assertEqual(len(fs["modified"]), 1)
        self.assertEqual(fs["modified"][0]["path"], "pre_existing.txt")
        self.assertEqual(fs["total_changes"], 2)

    def test_commit_vs_discard(self) -> None:
        with tempfile.TemporaryDirectory() as dest_dir:
            dest_path = Path(dest_dir)

            # Case A: Commit enabled
            cfg_commit = CapsuleConfig(
                commit=True,
                destination_dir=str(dest_path),
            )
            res_commit = self.runner.run([
                "python3", "-c",
                "open('persisted.txt', 'w').write('persisted content')"
            ], config=cfg_commit)
            self.assertEqual(res_commit.exit_code, 0)
            self.assertTrue(res_commit.committed)
            self.assertTrue((dest_path / "persisted.txt").exists())
            self.assertEqual((dest_path / "persisted.txt").read_text(), "persisted content")

            # Case B: Discard (default)
            cfg_discard = CapsuleConfig(commit=False, destination_dir=str(dest_path))
            res_discard = self.runner.run([
                "python3", "-c",
                "open('ephemeral.txt', 'w').write('transient content')"
            ], config=cfg_discard)
            self.assertEqual(res_discard.exit_code, 0)
            self.assertFalse(res_discard.committed)
            self.assertFalse((dest_path / "ephemeral.txt").exists())

    def test_initial_files_provisioning(self) -> None:
        cfg = CapsuleConfig(initial_files={
            "src/module.py": "def add(a, b): return a + b",
            "main.py": "from src.module import add; print('SUM:', add(40, 2))"
        })
        result = self.runner.run(["python3", "main.py"], config=cfg)
        self.assertEqual(result.exit_code, 0)
        self.assertIn("SUM: 42", result.stdout)


class TestCapsuleApiAndTelemetry(unittest.TestCase):
    """Test REST API and Telemetry Registry."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.port = 8195  # Test port (different from 8105)
        cls.server = CapsuleServer(host="127.0.0.1", port=cls.port)
        cls.server.start(block=False)
        time.sleep(0.3)

    @classmethod
    def tearDownClass(cls) -> None:
        cls.server.stop()

    def test_health_endpoint(self) -> None:
        req = urllib.request.Request(f"http://127.0.0.1:{self.port}/api/health")
        with urllib.request.urlopen(req, timeout=2.0) as resp:
            self.assertEqual(resp.status, 200)
            data = json.loads(resp.read().decode("utf-8"))
            self.assertEqual(data["status"], "healthy")
            self.assertEqual(data["service"], "agent-capsule-jail")

    def test_stats_endpoint(self) -> None:
        req = urllib.request.Request(f"http://127.0.0.1:{self.port}/api/stats")
        with urllib.request.urlopen(req, timeout=2.0) as resp:
            self.assertEqual(resp.status, 200)
            data = json.loads(resp.read().decode("utf-8"))
            self.assertIn("total_capsules", data)
            self.assertIn("uptime_seconds", data)

    def test_api_exec_post(self) -> None:
        payload = {
            "command": "python3 -c \"print('REST API capsule active')\"",
            "timeout_sec": 5.0,
            "memory_mb": 256,
        }
        req = urllib.request.Request(
            f"http://127.0.0.1:{self.port}/api/exec",
            data=json.dumps(payload).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=5.0) as resp:
            self.assertEqual(resp.status, 200)
            data = json.loads(resp.read().decode("utf-8"))
            self.assertEqual(data["exit_code"], 0)
            self.assertIn("REST API capsule active", data["stdout"])
            self.assertEqual(data["status"], "success")

    def test_api_capsules_list(self) -> None:
        # Execute a command first to guarantee history contains an item
        payload = {"command": "echo 'capsule history test'"}
        req_post = urllib.request.Request(
            f"http://127.0.0.1:{self.port}/api/exec",
            data=json.dumps(payload).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(req_post, timeout=5.0) as _:
            pass

        req = urllib.request.Request(f"http://127.0.0.1:{self.port}/api/capsules")
        with urllib.request.urlopen(req, timeout=2.0) as resp:
            self.assertEqual(resp.status, 200)
            data = json.loads(resp.read().decode("utf-8"))
            self.assertIn("capsules", data)
            self.assertGreaterEqual(len(data["capsules"]), 1)


if __name__ == "__main__":
    unittest.main()
