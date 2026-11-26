"""v2.6.0 remediation regression tests (whiteboard audit #005).

Covers: strict origin/host policy, CORS hygiene on the token page, input validation (400 never 000),
limit clamps, secret env denylist, network operator gate, OOM classification, per-run os.wait4
rusage, SHA-256 receipts, traversal 404 and the stdio MCP server.
"""
import hashlib
import http.client
import io
import json
import os
import socket
import subprocess
import sys
import unittest
import unittest.mock
from pathlib import Path

from agent_capsule_jail import __version__
from agent_capsule_jail.capsule import (CapsuleConfig, CapsuleNetworkDenied, CapsuleRunner, ResourceLimits,
                                        compute_receipt, pids_enforcement, sandbox_mode)
from agent_capsule_jail.mcp_server import McpServer
from agent_capsule_jail.server import CapsuleServer, _is_local_origin, host_allowed, origin_allowed

HAS_BWRAP = sandbox_mode() == "bwrap"
TOKEN = "v2-test-token"
SRC = str(Path(__file__).resolve().parent.parent / "src")


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class TestOriginAndHostUnits(unittest.TestCase):
    def test_hostname_spoof_rejected(self):
        for bad in ("http://127.0.0.1:8105.example.invalid", "http://localhost:3000.evil.test",
                    "http://127.0.0.1:0", "http://127.0.0.1:99999", "http://127.0.0.1:abc",
                    "http://127.0.0.1:8105/", "null", "https://evil.example"):
            self.assertFalse(origin_allowed(bad, 8105), bad)
        self.assertFalse(_is_local_origin("http://127.0.0.1:8105.example.invalid"))
        self.assertFalse(_is_local_origin("http://127.0.0.1:70000"))

    def test_exact_allowlist(self):
        for ok in ("http://127.0.0.1:8105", "http://localhost:8105", "http://127.0.0.1:3000",
                   "http://localhost:3000", "https://zoth.nullai.tech", None, ""):
            self.assertTrue(origin_allowed(ok, 8105), ok)
        # other local dev servers are no longer trusted
        self.assertFalse(origin_allowed("http://localhost:9999", 8105))
        self.assertFalse(origin_allowed("http://127.0.0.1:5173", 8105))

    def test_extra_origins_operator_opt_in(self):
        with unittest.mock.patch.dict(os.environ, {"CAPSULE_EXTRA_ORIGINS": "http://127.0.0.1:5173"}):
            self.assertTrue(origin_allowed("http://127.0.0.1:5173", 8105))

    def test_host_header(self):
        self.assertTrue(host_allowed("127.0.0.1:8105", 8105))
        self.assertTrue(host_allowed("localhost:8105", 8105))
        self.assertTrue(host_allowed("[::1]:8105", 8105))
        for bad in ("evil.example:8105", "127.0.0.1:8106", "localhost", "127.0.0.1.nip.io:8105", "attacker.test"):
            self.assertFalse(host_allowed(bad, 8105), bad)


class LiveServerCase(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.port = _free_port()
        with unittest.mock.patch.dict(os.environ, {"CAPSULE_TOKEN": TOKEN}):
            cls.server = CapsuleServer(host="127.0.0.1", port=cls.port, flight_recorder_url="")
        cls.server.start(block=False)

    @classmethod
    def tearDownClass(cls):
        cls.server.stop()

    def req(self, method, path, body=None, headers=None, raw=None):
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=30)
        hdrs = {"Host": f"127.0.0.1:{self.port}"}
        hdrs.update(headers or {})
        data = raw if raw is not None else (json.dumps(body).encode() if body is not None else None)
        if data is not None:
            hdrs.setdefault("Content-Type", "application/json")
        conn.putrequest(method, path, skip_host=True, skip_accept_encoding=True)
        for k, v in hdrs.items():
            conn.putheader(k, v)
        if data is not None:
            conn.putheader("Content-Length", str(len(data)))
        conn.endheaders(data)
        resp = conn.getresponse()
        payload = resp.read()
        headers = {k.lower(): v for k, v in resp.getheaders()}
        conn.close()
        try:
            parsed = json.loads(payload) if payload else None
        except ValueError:
            parsed = payload.decode("utf-8", "replace")
        return resp.status, headers, parsed

    def exec(self, body, headers=None):
        h = {"X-Capsule-Token": TOKEN}
        h.update(headers or {})
        return self.req("POST", "/api/exec", body=body, headers=h)


class TestCorsAndHost(LiveServerCase):
    def test_get_root_never_sends_acao(self):
        for origin in (None, "http://127.0.0.1:3000", f"http://127.0.0.1:{self.port}"):
            h = {"Origin": origin} if origin else {}
            code, headers, body = self.req("GET", "/", headers=h)
            self.assertEqual(code, 200)
            self.assertNotIn("access-control-allow-origin", headers, origin)
            self.assertEqual(headers.get("vary"), "Origin")
            self.assertIn('name="capsule-token"', body)

    def test_foreign_origin_get_root_403_no_token(self):
        code, headers, body = self.req("GET", "/", headers={"Origin": "http://localhost:9999"})
        self.assertEqual(code, 403)
        self.assertNotIn("access-control-allow-origin", headers)
        self.assertNotIn(TOKEN, json.dumps(body))

    def test_spoofed_origin_403_everywhere(self):
        spoof = f"http://127.0.0.1:{self.port}.example.invalid"
        self.assertEqual(self.req("OPTIONS", "/api/exec", headers={"Origin": spoof})[0], 403)
        self.assertEqual(self.req("GET", "/api/capsules", headers={"Origin": spoof})[0], 403)
        self.assertEqual(self.exec({"command": "echo hi"}, headers={"Origin": spoof})[0], 403)

    def test_options_allowed_vs_foreign(self):
        code, headers, _ = self.req("OPTIONS", "/api/exec", headers={"Origin": "http://127.0.0.1:3000"})
        self.assertEqual(code, 204)
        self.assertEqual(headers.get("access-control-allow-origin"), "http://127.0.0.1:3000")
        self.assertEqual(headers.get("vary"), "Origin")
        code, headers, _ = self.req("OPTIONS", "/api/exec", headers={"Origin": "https://evil.example"})
        self.assertEqual(code, 403)
        self.assertNotIn("access-control-allow-origin", headers)

    def test_api_vary_and_exact_acao(self):
        code, headers, _ = self.req("GET", "/api/stats", headers={"Origin": "https://zoth.nullai.tech"})
        self.assertEqual(code, 200)
        self.assertEqual(headers.get("access-control-allow-origin"), "https://zoth.nullai.tech")
        self.assertEqual(headers.get("vary"), "Origin")
        code, headers, _ = self.req("GET", "/api/health")
        self.assertNotIn("access-control-allow-origin", headers)
        self.assertEqual(headers.get("vary"), "Origin")

    def test_foreign_host_403(self):
        for host in ("evil.example", f"attacker.test:{self.port}", "127.0.0.1:1"):
            code, _, _ = self.req("GET", "/", headers={"Host": host})
            self.assertEqual(code, 403, host)
            self.assertEqual(self.req("GET", "/api/health", headers={"Host": host})[0], 403)

    def test_health_version_and_fields(self):
        code, _, data = self.req("GET", "/api/health")
        self.assertEqual(code, 200)
        self.assertEqual(data["version"], __version__)
        self.assertEqual(__version__, "2.6.0")
        self.assertEqual(data["port"], self.port)
        self.assertIn(data["pids_enforcement"], ("cgroup-tasksmax", "rlimit-nproc", "none"))
        self.assertFalse(data["network_opt_in_enabled"])

    def test_401_hint_has_no_filesystem_path(self):
        code, _, data = self.req("POST", "/api/exec", body={"command": "true"})
        self.assertEqual(code, 401)
        self.assertIn("agent-capsule-jail token", data["hint"])
        self.assertNotIn("/", data["hint"].replace("agent-capsule-jail", ""))

    def test_traversal_paths_404(self):
        for p in ("/../server.py", "/%2e%2e/server.py", "/..%2fserver.py", "/../../../../etc/passwd",
                  "/assets/../../server.py"):
            self.assertEqual(self.req("GET", p)[0], 404, p)
        self.assertEqual(self.req("GET", "/does-not-exist.js")[0], 404)


class TestInputValidation(LiveServerCase):
    def test_limit_validation(self):
        self.assertEqual(self.req("GET", "/api/capsules?limit=abc")[0], 400)
        code, _, data = self.req("GET", "/api/capsules?limit=-1")
        self.assertEqual(code, 200)
        self.assertEqual(data["limit"], 1)
        self.assertEqual(self.req("GET", "/api/capsules?limit=99999")[2]["limit"], 200)

    def test_non_object_bodies_400(self):
        for raw in (b"[1]", b"\"str\"", b"42", b"null", b"{bad json"):
            code, _, data = self.req("POST", "/api/exec", raw=raw, headers={"X-Capsule-Token": TOKEN})
            self.assertEqual(code, 400, raw)
            self.assertIn("error", data)

    def test_bad_numeric_fields_400(self):
        for field in ("timeout_sec", "memory_mb", "max_procs", "max_file_size_mb"):
            for bad in ("abc", True, [1], {"x": 1}):
                code, _, data = self.exec({"command": "true", field: bad})
                self.assertEqual(code, 400, (field, bad))
                self.assertIn(field, data["error"])

    def test_bad_types_400(self):
        for body in ({"command": 5}, {"command": ["echo", 1]}, {"command": "true", "allowed_env": "HOME"},
                     {"command": "true", "initial_files": ["a"]}, {"command": "true", "allow_network": "yes"},
                     {"script": 12}):
            self.assertEqual(self.exec(body)[0], 400, body)

    def test_bad_content_length_400(self):
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
        conn.putrequest("POST", "/api/exec", skip_host=True)
        conn.putheader("Host", f"127.0.0.1:{self.port}")
        conn.putheader("X-Capsule-Token", TOKEN)
        conn.putheader("Content-Length", "abc")
        conn.endheaders()
        self.assertEqual(conn.getresponse().status, 400)
        conn.close()

    def test_numeric_clamps(self):
        code, _, data = self.exec({"command": "true", "max_procs": 99999999, "timeout_sec": 0.01,
                                   "memory_mb": 999999, "max_file_size_mb": 0})
        self.assertEqual(code, 200, data)
        self.assertEqual(data["limits"]["max_procs"], 512)
        self.assertEqual(data["limits"]["timeout_sec"], 0.5)
        self.assertEqual(data["limits"]["memory_mb"], 4096)
        self.assertEqual(data["limits"]["max_file_size_mb"], 1)
        self.assertEqual(data["clamped"]["max_procs"], 512)

    def test_allow_network_403_without_operator_opt_in(self):
        code, _, data = self.exec({"command": "true", "allow_network": True})
        self.assertEqual(code, 403)
        self.assertTrue(data["policy_violation"])
        self.assertIn("CAPSULE_ALLOW_NETWORK", data["hint"])

    def test_exec_receipt_and_flight_flag(self):
        code, _, data = self.exec({"command": "echo receipt-check"})
        self.assertEqual(code, 200)
        self.assertRegex(data["receipt_sha256"], r"^[0-9a-f]{64}$")
        canonical = json.dumps({k: data[k] for k in ("capsule_id", "command", "exit_code", "stdout", "stderr", "fs_diff")},
                               sort_keys=True, separators=(",", ":"), ensure_ascii=False)
        self.assertEqual(hashlib.sha256(canonical.encode()).hexdigest(), data["receipt_sha256"])
        self.assertIs(data["flight_recorder_dispatched"], False)  # recorder disabled in this server
        self.assertNotIn("scratch_dir", data)
        self.assertEqual(data["command"], "echo receipt-check")


class TestCapsulePolicy(unittest.TestCase):
    def setUp(self):
        self.runner = CapsuleRunner()

    def test_allowed_env_cannot_bypass_denylist(self):
        env = {"OPENAI_API_KEY": "sk-leak", "MY_SERVICE_TOKEN": "tok", "SAFE_FLAG": "ok"}
        with unittest.mock.patch.dict(os.environ, env):
            r = self.runner.run(["python3", "-c", "import os;print(os.environ.get('OPENAI_API_KEY'),"
                                 "os.environ.get('MY_SERVICE_TOKEN'),os.environ.get('SAFE_FLAG'))"],
                                config=CapsuleConfig(allowed_env=["OPENAI_API_KEY", "MY_SERVICE_TOKEN", "SAFE_FLAG"]))
            self.assertEqual(r.stdout.split(), ["None", "None", "ok"], r.stderr)
            self.assertEqual(r.env_denied, ["MY_SERVICE_TOKEN", "OPENAI_API_KEY"])
        with unittest.mock.patch.dict(os.environ, {**env, "CAPSULE_FORCE_SENSITIVE_ENV": "1"}):
            r = self.runner.run(["python3", "-c", "import os;print(os.environ.get('OPENAI_API_KEY'))"],
                                config=CapsuleConfig(allowed_env=["OPENAI_API_KEY"]))
            self.assertEqual(r.stdout.strip(), "sk-leak")

    def test_path_user_are_fixed(self):
        r = self.runner.run(["python3", "-c", "import os;print(os.environ['PATH']);print(os.environ['USER'])"])
        self.assertEqual(r.stdout.split(), ["/usr/local/bin:/usr/bin:/bin", "capsule"])
        self.assertNotIn(str(Path.home()), r.stdout)

    def test_network_gate(self):
        with unittest.mock.patch.dict(os.environ, {"CAPSULE_ALLOW_NETWORK": ""}):
            with self.assertRaises(CapsuleNetworkDenied):
                self.runner.run(["true"], config=CapsuleConfig(allow_network=True))

    def test_memory_error_is_oom_killed(self):
        cfg = CapsuleConfig(limits=ResourceLimits(memory_mb=128, timeout_sec=10))
        r = self.runner.run(["python3", "-c", "b = bytearray(400 * 1024 * 1024)"], config=cfg)
        self.assertEqual(r.status, "oom_killed", r.stderr)
        self.assertTrue(r.memory_exceeded)
        self.assertNotEqual(r.exit_code, 0)

    def test_per_run_rusage_not_cumulative(self):
        heavy = self.runner.run(["python3", "-c", "x=0\nfor i in range(6_000_000): x+=i\n"],
                                config=CapsuleConfig(limits=ResourceLimits(timeout_sec=20)))
        light = self.runner.run(["true"])
        light2 = self.runner.run(["true"])
        self.assertGreater(heavy.cpu_time_user_s, 0.15, heavy)
        self.assertLess(light.cpu_time_user_s, heavy.cpu_time_user_s / 3)
        self.assertLess(light2.cpu_time_user_s, 0.1)
        self.assertLess(light2.cpu_time_user_s + light2.cpu_time_sys_s, heavy.cpu_time_user_s)
        self.assertGreater(heavy.max_rss_kb, 0)

    def test_receipt_is_real_sha256(self):
        r = self.runner.run(["sh", "-c", "echo hi > f.txt; echo done"])
        self.assertRegex(r.receipt_sha256, r"^[0-9a-f]{64}$")
        self.assertTrue(r.verify_receipt())
        self.assertEqual(r.receipt_sha256, compute_receipt(r.capsule_id, r.command, r.exit_code, r.stdout, r.stderr, r.fs_diff))
        r.stdout = "tampered"
        self.assertFalse(r.verify_receipt())
        self.assertEqual(r.to_dict()["cpu_time_system_s"], r.cpu_time_sys_s)

    @unittest.skipUnless(HAS_BWRAP, "bubblewrap not installed")
    def test_max_procs_enforced_per_capsule(self):
        code = ("import os,time\nn=0\ntry:\n for i in range(200):\n  if os.fork()==0:\n   time.sleep(3);os._exit(0)\n"
                "  n+=1\nexcept OSError: pass\nprint(n)")
        r = self.runner.run(["python3", "-c", code], config=CapsuleConfig(limits=ResourceLimits(max_procs=16, timeout_sec=15)))
        forked = int(r.stdout.strip() or 0)
        self.assertEqual(r.pids_enforcement, pids_enforcement())
        if r.pids_enforcement == "cgroup-tasksmax":
            self.assertLessEqual(forked, 16, r)
            self.assertGreater(forked, 5)
        else:
            self.assertLess(forked, 200)


class TestMcpServer(unittest.TestCase):
    def _session(self, messages):
        out = io.StringIO()
        McpServer().serve(io.StringIO("".join(json.dumps(m) + "\n" for m in messages)), out)
        return [json.loads(line) for line in out.getvalue().splitlines() if line.strip()]

    def test_initialize_list_and_calls(self):
        replies = self._session([
            {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": "2024-11-05"}},
            {"jsonrpc": "2.0", "method": "notifications/initialized"},
            {"jsonrpc": "2.0", "id": 2, "method": "tools/list"},
            {"jsonrpc": "2.0", "id": 3, "method": "tools/call",
             "params": {"name": "capsule_jail_exec", "arguments": {"command": "echo mcp-ok", "timeout_sec": 5}}},
            {"jsonrpc": "2.0", "id": 4, "method": "tools/call",
             "params": {"name": "capsule_jail_status", "arguments": {"port": _free_port()}}},
            {"jsonrpc": "2.0", "id": 5, "method": "nope"},
        ])
        self.assertEqual([r["id"] for r in replies], [1, 2, 3, 4, 5])
        self.assertEqual(replies[0]["result"]["protocolVersion"], "2024-11-05")
        self.assertEqual(replies[0]["result"]["serverInfo"]["version"], "2.6.0")
        names = sorted(t["name"] for t in replies[1]["result"]["tools"])
        self.assertEqual(names, ["capsule_jail_exec", "capsule_jail_status"])
        ex = replies[2]["result"]["structuredContent"]
        self.assertEqual(sorted(ex), sorted(["capsule_id", "status", "exit_code", "stdout", "stderr", "duration_ms",
                                             "fs_diff", "cpu_time_user_s", "cpu_time_system_s", "max_rss_kb",
                                             "receipt_sha256", "sandbox_mode"]))
        self.assertEqual(ex["stdout"].strip(), "mcp-ok")
        self.assertRegex(ex["receipt_sha256"], r"^[0-9a-f]{64}$")
        st = replies[3]["result"]["structuredContent"]
        self.assertFalse(st["daemon_online"])
        self.assertEqual(st["version"], "2.6.0")
        self.assertEqual(replies[4]["error"]["code"], -32601)

    def test_tool_errors_are_reported(self):
        replies = self._session([
            {"jsonrpc": "2.0", "id": 1, "method": "tools/call",
             "params": {"name": "capsule_jail_exec", "arguments": {"command": "true", "allow_network": True}}},
            {"jsonrpc": "2.0", "id": 2, "method": "tools/call",
             "params": {"name": "capsule_jail_exec", "arguments": {"timeout_sec": "x", "command": "true"}}},
        ])
        self.assertTrue(replies[0]["result"]["isError"])
        self.assertTrue(replies[1]["result"]["isError"])

    def test_cli_mcp_subprocess(self):
        msgs = "".join(json.dumps(m) + "\n" for m in [
            {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}},
            {"jsonrpc": "2.0", "id": 2, "method": "tools/list"},
        ])
        env = {**os.environ, "PYTHONPATH": SRC}
        p = subprocess.run([sys.executable, "-m", "agent_capsule_jail.cli", "mcp"], input=msgs,
                           capture_output=True, text=True, env=env, timeout=30)
        lines = [json.loads(x) for x in p.stdout.splitlines()]
        self.assertEqual(lines[0]["result"]["serverInfo"]["name"], "agent-capsule-jail")
        self.assertEqual(len(lines[1]["result"]["tools"]), 2)


if __name__ == "__main__":
    unittest.main()
