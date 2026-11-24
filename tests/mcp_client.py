"""Test harness: runs the server in an OpenWrt rootfs container (or on a real router)
and talks MCP to it over stdio.

Environment:
  OPENWRT_IMAGE      container image     default openwrt/rootfs:x86-64-24.10.4
  OPENWRT_PLATFORM   docker --platform   default linux/amd64
  OPENWRT_MCP_TARGET user@host of a real router; then the tests run through
                     bin/openwrt-mcp against it, and tests that need a container
                     (fixtures, writes) are skipped, and so is every request that
                     names the exec tool. Never point it at a router you do not own.

Usage in a test module:

  from mcp_client import OpenWrtTestCase, needs_container

  class TestThing(OpenWrtTestCase):
      def test_x(self):
          text, is_error = self.tool("system_info")
          self.assertFalse(is_error, text)

      @needs_container
      def test_fixture(self):
          self.sh("mkdir -p /fixture/rom/bin")       # runs inside the container
          text, _ = self.tool("x", env={"MCP_ROM": "/fixture/rom"}, path="/etc")

One container per test class (setUpClass); one server session per distinct env,
reused across tests. Pass env= to get a fresh session with those variables.
"""

from __future__ import annotations

import json
import os
import pathlib
import queue
import subprocess
import tempfile
import threading
import unittest
import uuid

ROOT = pathlib.Path(__file__).resolve().parent.parent
IMAGE = os.environ.get("OPENWRT_IMAGE", "openwrt/rootfs:x86-64-24.10.4")
PLATFORM = os.environ.get("OPENWRT_PLATFORM", "linux/amd64")
TARGET = os.environ.get("OPENWRT_MCP_TARGET") or None
REMOTE_SCRIPT = "/tmp/openwrt-mcp-test.sh"
# admin mode (write tools) for a session: tool(..., env=ADMIN_ENV). The tools that change
# the router; requests naming one are never sent to a real router.
ADMIN_ENV = {"MCP_ADMIN": "1"}
ADMIN_TOOLS = ("glinet_api", "uci_change", "service_control")
TIMEOUT = float(os.environ.get("OPENWRT_MCP_TEST_TIMEOUT", "180"))


def build_server(admin: bool = True) -> bytes:
    """The server as the launcher ships it: server/NN-*.sh in name order; without admin
    the write modules (NN-admin-*.sh) are left out, as the launcher does without --admin.
    The containers get the admin build: the write tools still register only when a
    session sets MCP_ADMIN=1 (ADMIN_ENV)."""
    parts = sorted((ROOT / "server").glob("[0-9][0-9]-*.sh"))
    if not admin:
        parts = [p for p in parts if not p.name[2:].startswith("-admin-")]
    return b"".join(p.read_bytes() for p in parts)


def needs_container(fn):
    return unittest.skipIf(TARGET is not None, "needs a container, not a real router")(fn)


class Container:
    def __init__(self, image: str = IMAGE):
        self.name = f"openwrt-mcp-test-{uuid.uuid4().hex[:10]}"
        subprocess.run(
            ["docker", "run", "-d", "--rm", "--platform", PLATFORM, "--name", self.name,
             image, "/bin/sleep", "7200"],
            check=True, capture_output=True,
        )
        self.push_server()

    def push_server(self, extra: str = "") -> None:
        """Copy the server into the container. extra: shell code (test tool modules)
        inserted before the final mcp_main call."""
        script = build_server()
        if extra:
            head, sep, tail = script.rpartition(b"\nmcp_main\n")
            assert sep, "server has no final mcp_main line"
            script = head + b"\n" + extra.encode() + sep + tail
        with tempfile.NamedTemporaryFile(suffix=".sh") as f:
            f.write(script)
            f.flush()
            subprocess.run(["docker", "cp", f.name, f"{self.name}:{REMOTE_SCRIPT}"],
                           check=True, capture_output=True)

    def put(self, path: str, data: bytes) -> None:
        """Write bytes to a file inside the container."""
        subprocess.run(["docker", "exec", "-i", self.name, "/bin/sh", "-c", 'cat > "$1"', "sh", path],
                       input=data, check=True, capture_output=True, timeout=TIMEOUT)

    def procs(self) -> list[tuple[int, int, str, str]]:
        """Live processes in the container: (pid, ppid, state, cmdline). Zombies are left
        out: the containers' pid 1 (sleep) never reaps orphans."""
        out = self.sh(r"""for d in /proc/[0-9]*; do
            s=$(cat "$d/stat" 2>/dev/null) || continue
            c=$(tr '\000\n' '  ' < "$d/cmdline" 2>/dev/null)
            printf '%s|%s|%s\n' "${d#/proc/}" "${s##*) }" "$c"; done""")
        res = []
        for line in out.splitlines():
            pid, _, rest = line.partition("|")
            stat, _, cmd = rest.partition("|")
            f = stat.split()
            if not pid.isdigit() or len(f) < 2 or f[0] == "Z":
                continue
            res.append((int(pid), int(f[1]), f[0], cmd))
        return res

    def sh(self, script: str, check: bool = True) -> str:
        """Run a shell script inside the container as root, return stdout."""
        r = subprocess.run(["docker", "exec", "-i", self.name, "/bin/sh", "-c", script],
                           capture_output=True, timeout=TIMEOUT)
        if check and r.returncode != 0:
            raise AssertionError(f"container sh failed ({r.returncode}): {script}\n"
                                 f"{r.stdout.decode(errors='replace')}{r.stderr.decode(errors='replace')}")
        return r.stdout.decode(errors="replace")

    def server_cmd(self, env: dict[str, str]) -> list[str]:
        e = []
        for k, v in env.items():
            e += ["-e", f"{k}={v}"]
        return ["docker", "exec", "-i", *e, self.name, "/bin/sh", REMOTE_SCRIPT]

    def stop(self) -> None:
        subprocess.run(["docker", "rm", "-f", self.name], capture_output=True)


class Session:
    """One running server process. Lines in, lines out."""

    def __init__(self, cmd: list[str], env: dict[str, str] | None = None):
        """env: environment of the local process (default: inherited)."""
        self.proc = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                     stderr=subprocess.PIPE, env=env)
        self.lines: queue.Queue[bytes | None] = queue.Queue()
        self.stderr = bytearray()
        threading.Thread(target=self._pump, daemon=True).start()
        threading.Thread(target=self._pump_err, daemon=True).start()
        self._next = 0

    def _pump(self) -> None:
        for line in self.proc.stdout:
            self.lines.put(line)
        self.lines.put(None)

    def _pump_err(self) -> None:
        for chunk in self.proc.stderr:
            self.stderr += chunk

    def send_raw(self, data: bytes) -> None:
        # Against a real router the tests stay read-only: anything that names the exec
        # tool is skipped before it leaves this process.
        if TARGET and b'"exec"' in data:
            raise unittest.SkipTest("exec is never run against a real router")
        if TARGET and any(b'"%s"' % t.encode() in data for t in ADMIN_TOOLS):
            raise unittest.SkipTest("write tools are never run against a real router")
        self.proc.stdin.write(data)
        self.proc.stdin.flush()

    def read_raw(self, timeout: float = TIMEOUT) -> bytes:
        """The next line the server wrote, as bytes."""
        line = self.lines.get(timeout=timeout)
        if line is None:
            raise EOFError(f"server exited; stderr: {self.stderr.decode(errors='replace')}")
        return line

    def read_message(self, timeout: float = TIMEOUT) -> dict:
        line = self.lines.get(timeout=timeout)
        if line is None:
            raise EOFError(f"server exited; stderr: {self.stderr.decode(errors='replace')}")
        return json.loads(line)  # raises on anything that is not one JSON object per line

    def request(self, method: str, params: dict | None = None, timeout: float = TIMEOUT) -> dict:
        self._next += 1
        msg = {"jsonrpc": "2.0", "id": self._next, "method": method}
        if params is not None:
            msg["params"] = params
        self.send_raw(json.dumps(msg).encode() + b"\n")
        while True:
            reply = self.read_message(timeout)
            if reply.get("id") == self._next:
                return reply

    def notify(self, method: str, params: dict | None = None) -> None:
        msg = {"jsonrpc": "2.0", "method": method}
        if params is not None:
            msg["params"] = params
        self.send_raw(json.dumps(msg).encode() + b"\n")

    def initialize(self, version: str = "2025-06-18") -> dict:
        r = self.request("initialize", {"protocolVersion": version, "capabilities": {},
                                        "clientInfo": {"name": "tests", "version": "0"}})
        self.notify("notifications/initialized")
        return r

    def call_tool(self, name: str, args: dict | None = None, timeout: float = TIMEOUT) -> tuple[str, bool]:
        r = self.request("tools/call", {"name": name, "arguments": args or {}}, timeout)
        if "error" in r:
            raise AssertionError(f"tools/call {name} -> JSON-RPC error {r['error']}")
        res = r["result"]
        text = "".join(c["text"] for c in res["content"] if c["type"] == "text")
        return text, bool(res.get("isError"))

    def close(self) -> int:
        try:
            self.proc.stdin.close()
        except BrokenPipeError:
            pass
        try:
            rc = self.proc.wait(timeout=30)
        except subprocess.TimeoutExpired:
            self.proc.kill()
            self.proc.wait()
            rc = -9
        for f in (self.proc.stdout, self.proc.stderr):
            try:
                f.close()
            except Exception:
                pass
        return rc


class OpenWrtTestCase(unittest.TestCase):
    container: Container | None = None
    sessions: dict

    @classmethod
    def setUpClass(cls) -> None:
        cls.sessions = {}
        cls.container = None if TARGET else Container()

    @classmethod
    def tearDownClass(cls) -> None:
        for s in cls.sessions.values():
            s.close()
        if cls.container:
            cls.container.stop()

    def sh(self, script: str, check: bool = True) -> str:
        if not self.container:
            self.skipTest("needs a container")
        return self.container.sh(script, check)

    def new_session(self, env: dict[str, str] | None = None) -> Session:
        env = dict(env or {})
        if TARGET:
            cmd = [str(ROOT / "bin" / "openwrt-mcp"), TARGET]
            if env.get("MCP_REDACT") == "0":
                cmd.insert(1, "--no-redact")
            if env.get("MCP_ADMIN") == "1":
                cmd.insert(1, "--admin")
        else:
            cmd = self.container.server_cmd(env)
        return Session(cmd)

    def session(self, env: dict[str, str] | None = None) -> Session:
        key = tuple(sorted((env or {}).items()))
        s = self.sessions.get(key)
        if s is None or s.proc.poll() is not None:
            s = self.new_session(env)
            s.initialize()
            self.sessions[key] = s
        return s

    def tool(self, name: str, env: dict[str, str] | None = None, timeout: float = TIMEOUT,
             **args) -> tuple[str, bool]:
        return self.session(env).call_tool(name, args, timeout)

    def tool_ok(self, name: str, env: dict[str, str] | None = None, **args) -> str:
        text, is_error = self.tool(name, env, **args)
        self.assertFalse(is_error, f"{name} returned isError:\n{text}")
        return text
