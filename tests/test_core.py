"""Core tests: JSON/UTF-8 safety, the output cap, timeouts and process trees, the
JSON-RPC error paths, argument checks and the server's own lifecycle."""

import json
import random
import time
import unittest

from mcp_client import OpenWrtTestCase, needs_container

# test tool modules, inserted before mcp_main
SHIM = r"""
mcp_register t_hang <<'EOF'
{"name":"t_hang","description":"test: prints, then hangs with a pipeline and a daemonized child","inputSchema":{"type":"object","properties":{},"additionalProperties":false}}
EOF
tool_t_hang() {
	echo started
	( sleep 913 >/dev/null 2>&1 & )
	sleep 911 | cat
}
mcp_register t_args <<'EOF'
{"name":"t_args","description":"test: typed arguments","inputSchema":{"type":"object","properties":{"s":{"type":"string"},"n":{"type":"integer"},"b":{"type":"boolean"},"l":{"type":"array"},"x":{"type":"number"}},"required":["s"],"additionalProperties":false}}
EOF
tool_t_args() { arg s s; echo "s=$s"; }
mcp_register t_bytes <<'EOF'
{"name":"t_bytes","description":"test: prints a file","inputSchema":{"type":"object","properties":{"path":{"type":"string"}},"additionalProperties":false}}
EOF
tool_t_bytes() { arg p path; cat "$p"; }
"""


def expected_text(data: bytes) -> str:
    """What the server must make of raw bytes: invalid UTF-8 replaced like Python does
    (one U+FFFD per maximal invalid subpart), NUL dropped, one trailing newline dropped."""
    text = data.decode("utf-8", "replace").replace("\x00", "")
    return text[:-1] if text.endswith("\n") else text


def live(procs, needle):
    return [p for p in procs if needle in p[3]]


class TestEncoding(OpenWrtTestCase):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        if cls.container:
            cls.container.push_server(SHIM)

    def check_bytes(self, data: bytes, name: str = "/tmp/bytes.bin"):
        self.container.put(name, data)
        s = self.session()
        s.send_raw(json.dumps({"jsonrpc": "2.0", "id": 4242, "method": "tools/call",
                               "params": {"name": "t_bytes", "arguments": {"path": name}}}).encode() + b"\n")
        raw = s.read_raw()
        raw.decode("utf-8")  # strict: the line itself must be valid UTF-8
        self.assertEqual(raw.count(b"\n"), 1)
        msg = json.loads(raw)
        self.assertEqual(msg["id"], 4242)
        text = msg["result"]["content"][0]["text"]
        text.encode("utf-8")  # no lone surrogates
        return text

    @needs_container
    def test_crafted_bytes(self):
        cases = [
            b"plain ascii",
            b"\xc3\xa4\xe2\x82\xac\xf0\x9f\x98\x80 valid",
            b"\xff\xfe lone bytes",
            b"\xc0\xaf overlong",
            b"\xed\xa0\x80 surrogate",
            b"\xe2\x82A truncated",
            b"\xf4\x90\x80\x80 above U+10FFFF",
            b"cr\r del\x7f nul\x00 tab\t quote\" backslash\\ ctl\x01\x1b",
            b"\x80\x80\xbf continuation only",
            b"ends with lead \xe2",
            b"\n\nleading newlines and two trailing\n\n",
        ]
        for data in cases:
            with self.subTest(data=data):
                self.assertEqual(self.check_bytes(data), expected_text(data))

    @needs_container
    def test_random_bytes(self):
        rnd = random.Random(7)
        for n in (1, 3, 1000, 20000):
            data = bytes(rnd.randrange(256) for _ in range(n))
            with self.subTest(n=n):
                self.assertEqual(self.check_bytes(data), expected_text(data))

    @needs_container
    def test_real_binary(self):
        text, err = self.tool("exec", command="cat /bin/busybox /usr/bin/jsonfilter")
        self.assertFalse(err)
        self.assertIn("ELF", text[:10])
        self.assertIn("[output cut at 60000 bytes", text)

    @needs_container
    def test_multibyte_cut_at_limit(self):
        env = {"MCP_MAX_OUTPUT": "1000"}
        # 1 + 2*600 bytes: the limit falls in the middle of an a-umlaut
        self.container.put("/tmp/umlaut.txt", b"x" + "ä".encode() * 600)
        text, err = self.tool("t_bytes", env=env, path="/tmp/umlaut.txt")
        self.assertFalse(err)
        body, _, note = text.partition("\n[output cut at 1000 bytes")
        self.assertEqual(body, "x" + "ä" * 499)
        self.assertIn("narrow the request", note)
        # a 4-byte character cut after 1, 2, 3 bytes
        for pad in (1, 2, 3):
            self.container.put("/tmp/emoji.txt", b"y" * (1000 - pad) + "\U0001F600".encode() * 3)
            text, _ = self.tool("t_bytes", env=env, path="/tmp/emoji.txt")
            self.assertEqual(text.partition("\n[output")[0], "y" * (1000 - pad))

    @needs_container
    def test_json_str_and_quote_helpers(self):
        out = self.sh(r"""sed '/^mcp_main$/d' /tmp/openwrt-mcp-test.sh > /tmp/lib.sh
            . /tmp/lib.sh
            printf 'a\303\244\377\n' | json_str; echo
            json_quote "$(printf 'x\ny')"; echo
            json_quote ''; echo
            printf '\n' | json_str; echo""")
        lines = out.splitlines()
        self.assertEqual([json.loads(x) for x in lines], ["aä�", "x\ny", "", ""])

    @needs_container
    def test_no_output(self):
        text, err = self.tool("exec", command="true")
        self.assertEqual(text.strip(), "[exit 0]")
        self.container.put("/tmp/empty.txt", b"")
        text, err = self.tool("t_bytes", path="/tmp/empty.txt")
        self.assertEqual(text, "(no output)")


class TestLimits(OpenWrtTestCase):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        if cls.container:
            cls.container.push_server(SHIM)

    @needs_container
    def test_cap_stops_producer(self):
        # sample the size of /tmp inside the container while the call runs
        self.sh("rm -f /root/stop /root/samples; (while [ ! -e /root/stop ]; do du -sk /tmp | cut -f1; done"
                " > /root/samples 2>/dev/null &)")
        base = int(self.sh("du -sk /tmp | cut -f1"))
        t0 = time.time()
        text, err = self.session().call_tool(
            "exec", {"command": "head -c 30000000 /dev/urandom; cat /dev/urandom; echo never", "timeout": 100})
        elapsed = time.time() - t0
        self.sh("touch /root/stop; sleep 1")
        samples = [int(x) for x in self.sh("cat /root/samples").split()]
        self.assertGreater(len(samples), 3)
        self.assertLess(max(samples) - base, 1000, "/tmp grew while the call ran")
        self.assertLess(elapsed, 60)
        self.assertFalse(err)
        self.assertIn("[output cut at 60000 bytes and the tool was stopped", text)
        self.assertNotIn("[exit", text)
        self.assertEqual(live(self.container.procs(), "/dev/urandom"), [])

    @needs_container
    def test_cap_with_zero_bytes(self):
        # 20 MB of NUL bytes: counted for the cap, dropped from the text
        text, err = self.tool("exec", command="head -c 20000000 /dev/zero")
        self.assertIn("(no output)", text)
        self.assertIn("[output cut at", text)

    @needs_container
    def test_run_timeout_kills_tree(self):
        out = self.sh(r"""sed '/^mcp_main$/d' /tmp/openwrt-mcp-test.sh > /tmp/lib.sh
            . /tmp/lib.sh
            run_timeout 1 sh -c 'sleep 921 | cat; echo no'; echo "rc=$?"
            run_timeout 5 sh -c 'exit 3'; echo "rc=$?"
            run_timeout 5 echo through | cat
            run_timeout 5 sh -c 'exit 124'; echo "rc=$? fired=$_rt_fired"
            f() { echo func; return 2; }; run_timeout 5 f; echo "rc=$?"
            """, check=False)
        self.assertEqual(out.split(), ["rc=124", "rc=3", "through", "rc=124", "fired=0", "func", "rc=2"])
        self.assertEqual(live(self.container.procs(), "sleep 921"), [])

    @needs_container
    def test_run_timeout_does_not_hold_pipes(self):
        # the watchdog must not keep a $(...) or a pipe open until the limit
        out = self.sh(r"""sed '/^mcp_main$/d' /tmp/openwrt-mcp-test.sh > /tmp/lib.sh
            . /tmp/lib.sh
            s=$(date +%s)
            x=$(run_timeout 30 sh -c 'echo fast')
            run_timeout 30 echo piped | cat
            y=$(run_timeout 30 echo sub | awk '{print "awk:" $0}')
            echo "$x $y $(( $(date +%s) - s ))"
            """)
        lines = out.split()
        self.assertEqual(lines[:3], ["piped", "fast", "awk:sub"])
        self.assertLess(int(lines[3]), 10, "run_timeout held a pipe open")
        self.assertEqual(live(self.container.procs(), "sleep 30"), [])

    @needs_container
    def test_call_timeout(self):
        env = {"MCP_CALL_TIMEOUT": "3"}
        s = self.session(env)
        t0 = time.time()
        text, err = s.call_tool("t_hang")
        self.assertLess(time.time() - t0, 30)
        self.assertTrue(err)
        self.assertTrue(text.startswith("started\n"), text)
        self.assertIn("[timeout: the call was stopped after 3 s", text)
        procs = self.container.procs()
        self.assertEqual(live(procs, "sleep 911"), [], procs)
        self.assertEqual(live(procs, "sleep 913"), [], "daemonized child survived")
        self.assertEqual(s.request("ping")["result"], {})
        self.assertIn("call timeout  3 s", s.call_tool("server_info")[0])

    @needs_container
    def test_exec_timeout_extends_call_timeout(self):
        env = {"MCP_CALL_TIMEOUT": "2"}
        text, err = self.session(env).call_tool("exec", {"command": "sleep 4; echo done", "timeout": 10})
        self.assertFalse(err, text)
        self.assertIn("done", text)

    @needs_container
    def test_background_holder(self):
        t0 = time.time()
        text, err = self.tool("exec", command="echo early; (sleep 6; echo late) &")
        self.assertLess(time.time() - t0, 6)
        self.assertIn("early", text)
        self.assertNotIn("late", text)
        self.assertIn("still holds its output open", text)


class TestProtocolErrors(OpenWrtTestCase):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        if cls.container:
            cls.container.push_server(SHIM)

    def raw(self, s, data: bytes) -> dict:
        s.send_raw(data)
        return s.read_message()

    def test_error_codes(self):
        s = self.session()
        cases = [
            (b"{not json\n", None, -32700),
            (b'[{"jsonrpc":"2.0","id":1,"method":"ping"}]\n', None, -32600),
            (b'"just a string"\n', None, -32600),
            (b'{"jsonrpc":"2.0","id":{"a":1},"method":"ping"}\n', None, -32600),
            (b'{"jsonrpc":"2.0","id":true,"method":"ping"}\n', None, -32600),
            (b'{"jsonrpc":"2.0","id":null,"method":"ping"}\n', None, -32600),
            (b'{"jsonrpc":"2.0","id":11}\n', 11, -32600),
            (b'{"jsonrpc":"2.0","id":12,"method":7}\n', 12, -32600),
            (b'{"id":13,"method":"ping"}\n', 13, -32600),
            (b'{"jsonrpc":"2.0","id":14,"method":"resources/list"}\n', 14, -32601),
            (b'{"jsonrpc":"2.0","id":15,"method":"tools/call","params":{"name":"nope"}}\n', 15, -32602),
            (b'{"jsonrpc":"2.0","id":16,"method":"tools/call","params":{"name":5}}\n', 16, -32602),
            (b'{"jsonrpc":"2.0","id":17,"method":"tools/call","params":{}}\n', 17, -32602),
            (b'{"jsonrpc":"2.0","id":18,"method":"tools/list","params":[1]}\n', 18, -32602),
        ]
        for data, want_id, code in cases:
            with self.subTest(data=data):
                r = self.raw(s, data)
                self.assertEqual(r.get("jsonrpc"), "2.0")
                self.assertEqual(r["id"], want_id)
                self.assertEqual(r["error"]["code"], code)
                self.assertTrue(r["error"]["message"])
        self.assertEqual(s.request("ping")["result"], {})

    def test_ids(self):
        s = self.session()
        for i in ("x", "ä \"q\" \\ /", "", 0, -5, 1.5, 9007199254740991):
            with self.subTest(id=i):
                r = self.raw(s, json.dumps({"jsonrpc": "2.0", "id": i, "method": "ping"}).encode() + b"\n")
                self.assertEqual(r["id"], i)

    def test_notifications_get_no_reply(self):
        s = self.session()
        for n in ({"jsonrpc": "2.0", "method": "notifications/cancelled", "params": {"requestId": 1}},
                  {"jsonrpc": "2.0", "method": "notifications/initialized"},
                  {"jsonrpc": "2.0", "method": "no/such/notification"},
                  {"jsonrpc": "2.0", "method": "tools/call", "params": {"name": "nope"}}):
            s.send_raw(json.dumps(n).encode() + b"\n")
        s.send_raw(b'{"jsonrpc":"2.0","id":"after","method":"ping"}\n')
        self.assertEqual(s.read_message()["id"], "after")

    def test_crlf_and_blank_lines(self):
        s = self.session()
        s.send_raw(b"\n\r\n   \t\n" b'{"jsonrpc":"2.0","id":21,"method":"ping"}\r\n')
        self.assertEqual(s.read_message(), {"jsonrpc": "2.0", "id": 21, "result": {}})

    def test_huge_lines(self):
        s = self.session()
        pad = "a" * 1_000_000
        s.send_raw(json.dumps({"jsonrpc": "2.0", "id": 31, "method": "ping",
                               "params": {"pad": pad}}).encode() + b"\n")
        self.assertEqual(s.read_message()["id"], 31)
        s.send_raw(b"{" + b"x" * 1_000_000 + b"\n")
        self.assertEqual(s.read_message()["error"]["code"], -32700)
        self.assertEqual(s.request("ping")["result"], {})

    def test_initialize_versions(self):
        s = self.new_session()
        for v, want in (("2024-11-05", "2024-11-05"), ("2025-03-26", "2025-03-26"),
                        ("2099-01-01", "2025-11-25")):
            r = s.request("initialize", {"protocolVersion": v, "capabilities": {},
                                         "clientInfo": {"name": "t", "version": "0"}})
            self.assertEqual(r["result"]["protocolVersion"], want)
        s.close()

    @needs_container
    def test_invalid_arguments_are_tool_errors(self):
        s = self.session()
        cases = [
            ({"s": "ok"}, False, "s=ok"),
            ({"s": "ok", "n": 3, "b": True, "l": [1], "x": 1.5}, False, "s=ok"),
            ({"s": "ok", "x": 2}, False, "s=ok"),
            ({"s": "ok", "n": None}, False, "s=ok"),
            ({}, True, 'missing required argument "s"'),
            ({"s": 5}, True, 'argument "s" must be a string, got an integer'),
            ({"s": "ok", "n": "5"}, True, 'argument "n" must be an integer, got a string'),
            ({"s": "ok", "n": 1.5}, True, 'argument "n" must be an integer, got a number'),
            ({"s": "ok", "b": "true"}, True, 'argument "b" must be a boolean'),
            ({"s": "ok", "l": "x"}, True, 'argument "l" must be an array'),
            ({"s": "ok", "typo": 1}, True, 'unknown argument "typo"'),
        ]
        for args, want_err, want in cases:
            with self.subTest(args=args):
                text, err = s.call_tool("t_args", args)
                self.assertEqual(err, want_err, text)
                self.assertIn(want, text)
                if want_err:
                    self.assertIn("This tool takes: s (string), n (integer)", text)
        r = s.request("tools/call", {"name": "t_args", "arguments": [1, 2]})
        self.assertTrue(r["result"]["isError"])
        self.assertIn("must be a JSON object", r["result"]["content"][0]["text"])

    @needs_container
    def test_stdout_only_protocol(self):
        # a tool that writes to fd 3 or to the server's stdout must not reach the client
        s = self.session()
        text, err = s.call_tool("exec", {"command": "echo junk >&3; echo fine"})
        self.assertIn("fine", text)
        self.assertEqual(s.request("ping")["result"], {})


class TestLifecycle(OpenWrtTestCase):
    def server_main_pid(self, mark: str) -> int:
        """pid of the server's main shell: has the mark, its parent does not."""
        out = self.sh(f"grep -lsF MCP_TEST_MARK={mark} /proc/[0-9]*/environ | cut -d/ -f3")
        pids = {int(p) for p in out.split()}
        procs = {p[0]: p for p in self.container.procs()}
        mains = [p for p in pids if p in procs and procs[p][1] not in pids]
        self.assertEqual(len(mains), 1, (pids, mains))
        return mains[0]

    def start(self, mark: str):
        s = self.new_session({"MCP_TEST_MARK": mark})
        s.initialize()
        tmp = [line.split()[-1] for line in s.call_tool("server_info")[0].splitlines()
               if line.startswith("temp dir")][0]
        self.assertTrue(self.sh(f"[ -d {tmp} ] && echo yes"))
        return s, tmp

    def assert_gone(self, tmp: str, mark: str, needle: str = "") -> None:
        for _ in range(20):
            left = self.sh(f"grep -lsF MCP_TEST_MARK={mark} /proc/[0-9]*/environ | cut -d/ -f3").split()
            alive = {p[0] for p in self.container.procs()}
            left = [p for p in left if int(p) in alive]
            if not left:
                break
            time.sleep(0.5)
        self.assertEqual(left, [], "server processes left")
        self.assertEqual(self.sh(f"ls -d {tmp} 2>/dev/null; true"), "")
        if needle:
            self.assertEqual(live(self.container.procs(), needle), [])

    @needs_container
    def test_eof_exits_zero_and_cleans_up(self):
        s, tmp = self.start("eof1")
        self.assertEqual(s.close(), 0)
        self.assert_gone(tmp, "eof1")

    @needs_container
    def test_eof_after_pending_request_still_answers(self):
        s = self.new_session()
        s.send_raw(b'{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"exec","arguments":{"command":"sleep 1; echo ok"}}}\n')
        s.proc.stdin.close()
        self.assertIn("ok", s.read_message()["result"]["content"][0]["text"])
        self.assertEqual(s.proc.wait(timeout=30), 0)

    @needs_container
    def test_sigterm_and_sighup_during_a_call(self):
        for sig, mark, secs in (("TERM", "term1", 931), ("HUP", "hup1", 932)):
            with self.subTest(sig=sig):
                s, tmp = self.start(mark)
                s.send_raw(json.dumps({"jsonrpc": "2.0", "id": 99, "method": "tools/call", "params": {
                    "name": "exec", "arguments": {"command": f"sleep {secs} | cat", "timeout": 300}}}).encode() + b"\n")
                for _ in range(40):
                    if live(self.container.procs(), f"sleep {secs}"):
                        break
                    time.sleep(0.25)
                pid = self.server_main_pid(mark)
                self.sh(f"kill -{sig} {pid}")
                self.assertEqual(s.proc.wait(timeout=30), 0)
                self.assert_gone(tmp, mark, f"sleep {secs}")
                s.close()

    @needs_container
    def test_sigterm_while_idle(self):
        s, tmp = self.start("idle1")
        self.sh(f"kill -TERM {self.server_main_pid('idle1')}")
        self.assertEqual(s.proc.wait(timeout=30), 0)
        self.assert_gone(tmp, "idle1")
        s.close()


if __name__ == "__main__":
    unittest.main()
