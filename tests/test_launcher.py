"""bin/openwrt-mcp: options, --build, --print-config, and real SSH runs against a
container that runs dropbear with a throwaway key."""

import json
import os
import pathlib
import shlex
import shutil
import signal
import subprocess
import tempfile
import time
import unittest
import uuid

from mcp_client import (IMAGE, PLATFORM, ROOT, TARGET, Container, OpenWrtTestCase, Session,
                        build_server)

LAUNCHER = str(ROOT / "bin" / "openwrt-mcp")


def run(*args, **kw):
    return subprocess.run([LAUNCHER, *args], capture_output=True, text=True, timeout=60, **kw)


class TestLauncherLocal(unittest.TestCase):
    def test_build(self):
        with tempfile.TemporaryDirectory() as d:
            out = pathlib.Path(d) / "server.sh"
            r = run("--build", str(out))
            self.assertEqual(r.returncode, 0, r.stderr)
            self.assertEqual(out.read_bytes(), build_server())

    def test_usage_errors(self):
        for args in ((), ("--bogus", "host"), ("-p",), ("--max-output", "x", "host"),
                     ("--call-timeout", "0", "host"), ("a", "b")):
            with self.subTest(args=args):
                r = run(*args)
                self.assertEqual(r.returncode, 2, r)
        r = run("--help")
        self.assertEqual(r.returncode, 0)
        for opt in ("-p PORT", "-i KEY", "-o OPTION", "--no-redact", "--max-output", "--call-timeout",
                    "--build FILE", "--print-config NAME"):
            self.assertIn(opt, r.stdout)

    def test_print_config(self):
        with tempfile.TemporaryDirectory() as d:
            key = pathlib.Path(d) / "my key"
            key.write_text("x")
            r = run("-p", "2222", "-i", "my key", "-o", "ConnectTimeout=5", "--no-redact",
                    "--max-output", "9000", "--print-config", "my router", "root@192.168.8.1", cwd=d)
        self.assertEqual(r.returncode, 0, r.stderr)
        want_args = ["-p", "2222", "-i", str(key.resolve()), "-o", "ConnectTimeout=5", "--no-redact",
                     "--max-output", "9000", "root@192.168.8.1"]
        cmd_line = [x for x in r.stdout.splitlines() if x.startswith("claude mcp add")][0]
        self.assertEqual(shlex.split(cmd_line), ["claude", "mcp", "add", "my router", "--",
                                                 os.path.realpath(LAUNCHER), *want_args])
        cfg = json.loads(r.stdout[r.stdout.index("{"):])
        self.assertEqual(cfg["mcpServers"]["my router"],
                         {"command": os.path.realpath(LAUNCHER), "args": want_args})


class SSHContainer(Container):
    """A container with dropbear on a random local port, root key login with a
    throwaway key, and a root password set so that only the key gets in."""

    def __init__(self, keydir: pathlib.Path):
        self.name = f"openwrt-mcp-test-{uuid.uuid4().hex[:10]}"
        subprocess.run(["docker", "run", "-d", "--rm", "--platform", PLATFORM, "--name", self.name,
                        "-p", "127.0.0.1::22", IMAGE, "/bin/sleep", "7200"],
                       check=True, capture_output=True)
        self.push_server()
        self.port = subprocess.run(["docker", "port", self.name, "22"], check=True, capture_output=True,
                                   text=True).stdout.split()[0].rsplit(":", 1)[1]
        self.put("/etc/dropbear/authorized_keys", (keydir / "id.pub").read_bytes())
        # 21.02.7 ships empty host key files that dropbear chokes on; -R makes new ones
        self.sh("rm -f /etc/dropbear/dropbear_*_host_key;"
                "chmod 700 /etc/dropbear; chmod 600 /etc/dropbear/authorized_keys;"
                r"sed -i 's|^root:[^:]*:|root:$1$abcdefgh$0123456789abcdefghijkl:|' /etc/shadow")
        subprocess.run(["docker", "exec", "-d", self.name, "/bin/sh", "-c",
                        "/usr/sbin/dropbear -F -E -R -p 22 2>/tmp/dropbear.log"], check=True)

    def logins(self) -> int:
        return int(self.sh("grep -ci 'auth succeeded' /tmp/dropbear.log; true").split()[0])


@unittest.skipIf(TARGET is not None, "needs a container, not a real router")
@unittest.skipUnless(shutil.which("ssh") and shutil.which("ssh-keygen"), "needs ssh and ssh-keygen")
class TestLauncherSSH(OpenWrtTestCase):
    @classmethod
    def setUpClass(cls):
        cls.sessions = {}
        cls.tmp = pathlib.Path(tempfile.mkdtemp(prefix="omcp-"))
        for k in ("id", "bad"):
            subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(cls.tmp / k)], check=True)
        cls.container = SSHContainer(cls.tmp)
        cls.known = cls.tmp / "known_hosts"
        # wait until dropbear answers and record its host key
        for _ in range(60):
            r = subprocess.run(["ssh", *cls.ssh_args(cls.known, "accept-new"), "root@127.0.0.1", "true"],
                               capture_output=True, timeout=60)
            if r.returncode == 0:
                break
            time.sleep(1)
        else:
            raise AssertionError(f"dropbear did not come up: {r.stderr!r}")

    @classmethod
    def tearDownClass(cls):
        super().tearDownClass()
        shutil.rmtree(cls.tmp, ignore_errors=True)

    @classmethod
    def ssh_args(cls, known, strict="yes", key="id"):
        return ["-p", cls.container.port, "-i", str(cls.tmp / key), "-o", "IdentitiesOnly=yes",
                "-o", f"UserKnownHostsFile={known}", "-o", f"StrictHostKeyChecking={strict}"]

    def launcher(self, *extra, key="id", known=None, ctl=None):
        """argv and env for a launcher run; ctl: TMPDIR for the control socket."""
        # short: the launcher falls back to /tmp when TMPDIR is too long for a socket path
        ctl = ctl or pathlib.Path(tempfile.mkdtemp(prefix="omcp-", dir="/tmp"))
        self.addCleanup(shutil.rmtree, ctl, True)
        argv = [LAUNCHER, *self.ssh_args(known or self.known, key=key), *extra, "root@127.0.0.1"]
        return argv, {**os.environ, "TMPDIR": str(ctl)}, ctl

    def start(self, *extra):
        argv, env, ctl = self.launcher(*extra)
        s = Session(argv, env=env)
        self.addCleanup(s.close)
        s.initialize()
        return s, ctl

    def remote_servers(self):
        return [p for p in self.container.procs() if "/tmp/openwrt-mcp." in p[3]]

    def wait_remote_gone(self):
        for _ in range(40):
            if not self.remote_servers():
                break
            time.sleep(0.5)
        self.assertEqual(self.remote_servers(), [])
        self.assertEqual(self.container.sh("ls -d /tmp/openwrt-mcp.* 2>/dev/null; true"), "")

    def test_session_over_ssh(self):
        before = self.container.logins()
        s, ctl = self.start("--no-redact", "--max-output", "5000", "--call-timeout", "77")
        info, err = s.call_tool("server_info")
        self.assertFalse(err, info)
        self.assertIn("redaction     off", info)
        self.assertIn("max output    5000 bytes", info)
        self.assertIn("call timeout  77 s", info)
        # the copied script deleted itself; only the server's temp dir is left
        text, _ = s.call_tool("exec", {"command": "ls -d /tmp/openwrt-mcp.*"})
        self.assertNotIn(".sh", text)
        self.assertRegex(text, r"/tmp/openwrt-mcp\.[A-Za-z0-9]{6}\n")
        self.assertEqual(len(os.listdir(ctl)), 1)  # one private dir with the socket
        self.assertEqual(self.container.logins() - before, 1, "more than one SSH login")
        self.assertEqual(s.close(), 0)
        self.assertEqual(os.listdir(ctl), [], "control dir left behind")
        self.wait_remote_gone()

    def test_sigterm_to_launcher(self):
        s, ctl = self.start()
        self.assertTrue(self.remote_servers())
        s.proc.send_signal(signal.SIGTERM)
        s.proc.wait(timeout=30)
        self.assertEqual(os.listdir(ctl), [], "control dir left behind")
        self.wait_remote_gone()
        s.close()

    def test_unknown_host_key(self):
        argv, env, ctl = self.launcher(known=self.tmp / "empty_known_hosts")
        r = subprocess.run(argv, input=b"", capture_output=True, env=env, timeout=120)
        self.assertEqual(r.returncode, 1)
        err = r.stderr.decode()
        self.assertIn("host key is not known", err)
        self.assertIn("Log in once by hand", err)
        self.assertEqual(os.listdir(ctl), [])

    def test_key_rejected(self):
        argv, env, ctl = self.launcher(key="bad")
        r = subprocess.run(argv, input=b"", capture_output=True, env=env, timeout=120)
        self.assertEqual(r.returncode, 1)
        err = r.stderr.decode()
        self.assertIn("Permission denied", err)
        self.assertIn("key authentication to root@127.0.0.1 failed", err)
        self.assertEqual(os.listdir(ctl), [])

    def test_checksum_mismatch(self):
        # a sha256sum that lies, first in the SSH session's PATH
        self.container.sh("printf '#!/bin/sh\\necho 0000 \"$1\"\\n' > /usr/sbin/sha256sum; chmod 755 /usr/sbin/sha256sum")
        try:
            argv, env, ctl = self.launcher()
            r = subprocess.run(argv, input=b"", capture_output=True, env=env, timeout=120)
        finally:
            self.container.sh("rm -f /usr/sbin/sha256sum")
        self.assertEqual(r.returncode, 1)
        self.assertIn("does not match its sha256 (got 0000); not started", r.stderr.decode())
        self.assertEqual(self.container.sh("ls /tmp/openwrt-mcp.*.sh 2>/dev/null; true"), "")
        self.assertEqual(os.listdir(ctl), [])


if __name__ == "__main__":
    unittest.main()
