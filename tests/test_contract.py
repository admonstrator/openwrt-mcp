"""Contract tests: the protocol basics and the shared helpers every module relies on."""

import json
import unittest

from mcp_client import ADMIN_ENV, ADMIN_TOOLS, REMOTE_SCRIPT, OpenWrtTestCase, build_server, needs_container

# the core helpers, called from a throwaway tool module that tests add to the server
HELPER_SHIM = r"""
mcp_register t_helpers <<'EOF'
{"name":"t_helpers","description":"test","inputSchema":{"type":"object"}}
EOF
tool_t_helpers() {
	arg s s dflt; printf 's=[%s]\n' "$s"
	arg_int n n 5 1 10 || return 1; printf 'n=[%s]\n' "$n"
	if arg_bool b false; then echo b=true; else echo b=false; fi
	arg_list l | sed 's/^/l=/'
	arg_has s && echo has_s
}
"""


class TestProtocol(OpenWrtTestCase):
    def test_initialize(self):
        s = self.new_session()
        r = s.initialize("2025-06-18")
        self.assertEqual(r["result"]["protocolVersion"], "2025-06-18")
        self.assertEqual(r["result"]["serverInfo"]["name"], "openwrt-mcp")
        self.assertIn("tools", r["result"]["capabilities"])
        s.close()

    def test_unknown_protocol_version_gets_latest(self):
        s = self.new_session()
        r = s.initialize("1999-01-01")
        self.assertEqual(r["result"]["protocolVersion"], "2025-11-25")
        s.close()

    def test_tools_list_is_valid(self):
        r = self.session().request("tools/list")
        tools = r["result"]["tools"]
        names = [t["name"] for t in tools]
        self.assertIn("server_info", names)
        self.assertEqual(len(names), len(set(names)), "duplicate tool names")
        for t in tools:
            self.assertRegex(t["name"], r"^[a-z0-9_]+$")
            self.assertTrue(t.get("description"), t["name"])
            self.assertEqual(t["inputSchema"]["type"], "object", t["name"])

    def test_server_info(self):
        text = self.tool_ok("server_info")
        self.assertIn("openwrt-mcp", text)

    def test_ping(self):
        self.assertEqual(self.session().request("ping")["result"], {})

    def test_unknown_method_and_tool(self):
        s = self.session()
        self.assertEqual(s.request("nope/nope")["error"]["code"], -32601)
        r = s.request("tools/call", {"name": "no_such_tool", "arguments": {}})
        self.assertEqual(r["error"]["code"], -32602)

    def test_parse_error_keeps_server_alive(self):
        s = self.new_session()
        s.initialize()
        s.send_raw(b"{not json\n")
        self.assertEqual(s.read_message()["error"]["code"], -32700)
        self.assertEqual(s.request("ping")["result"], {})
        s.close()

    def test_string_id_is_echoed(self):
        s = self.session()
        s.send_raw(b'{"jsonrpc":"2.0","id":"a\\"b","method":"ping"}\n')
        self.assertEqual(s.read_message()["id"], 'a"b')


class TestHelpers(OpenWrtTestCase):
    @needs_container
    def test_arguments(self):
        self.sh(f"cat >> /tmp/openwrt-mcp-test.sh <<'SHIM'\n{HELPER_SHIM}\nSHIM\n"
                # the shim must come before mcp_main: move the main call to the end
                "sed -i '/^mcp_main$/d' /tmp/openwrt-mcp-test.sh && echo mcp_main >> /tmp/openwrt-mcp-test.sh")
        s = self.new_session()
        s.initialize()
        text, err = s.call_tool("t_helpers", {"s": "a b", "n": 7, "b": True, "l": ["x", "y z"]})
        self.assertFalse(err, text)
        self.assertEqual(text.splitlines(), ["s=[a b]", "n=[7]", "b=true", "l=x", "l=y z", "has_s"])
        text, err = s.call_tool("t_helpers", {})
        self.assertEqual(text.splitlines(), ["s=[dflt]", "n=[5]", "b=false"])
        text, err = s.call_tool("t_helpers", {"n": 99})
        self.assertTrue(err)
        self.assertIn("between 1 and 10", text)
        s.close()
        self.container.push_server()

    @needs_container
    def test_json_str_escapes(self):
        out = self.sh(r"""sed '/^mcp_main$/d' /tmp/openwrt-mcp-test.sh > /tmp/lib.sh
            . /tmp/lib.sh; printf 'a\\b "q"\ttab\001\n\nlast' | json_str""")
        self.assertEqual(json.loads(out), 'a\\b "q"\ttab\x01\n\nlast')

    @needs_container
    def test_redact(self):
        out = self.sh(r"""sed '/^mcp_main$/d' /tmp/openwrt-mcp-test.sh > /tmp/lib.sh
            . /tmp/lib.sh
            printf "%s\n" "wireless.default_radio0.key='hunter2'" "wireless.default_radio0.ssid='home'" \
              "	option key 'hunter2'" 'root:$1$abc$def:19000:0:99999:7:::' \
              "network.wg0.private_key='AAAA'" "wireless.wep0.key2='wepsecret'" \
              "	option key1 's:wepsecret'" | redact""")
        self.assertNotIn("wepsecret", out)
        self.assertNotIn("hunter2", out)
        self.assertNotIn("$abc$def", out)
        self.assertNotIn("AAAA", out)
        self.assertIn("ssid='home'", out)
        self.assertIn("$1>", out)

    @needs_container
    def test_redact_one_line_key(self):
        # a whole PEM block inside one JSON line must not swallow the lines after it
        out = self.sh(r"""sed '/^mcp_main$/d' /tmp/openwrt-mcp-test.sh > /tmp/lib.sh
            . /tmp/lib.sh
            printf '%s\n' '"cert": "-----BEGIN PRIVATE KEY-----\\nMIIsecret\\n-----END PRIVATE KEY-----\\n", "x": 1' \
              '"after": "visible"' | redact""")
        self.assertNotIn("MIIsecret", out)
        self.assertIn("<redacted private key>", out)
        self.assertIn('"x": 1', out)
        self.assertIn('"after": "visible"', out)
        # a second BEGIN without END on that line starts a block: what follows is hidden
        out = self.sh(r"""sed '/^mcp_main$/d' /tmp/openwrt-mcp-test.sh > /tmp/lib.sh
            . /tmp/lib.sh
            printf '%s\n' 'a -----BEGIN PRIVATE KEY-----k1-----END PRIVATE KEY----- b -----BEGIN PRIVATE KEY-----' \
              'MIIsecond' '-----END PRIVATE KEY-----' 'tail' | redact""")
        self.assertNotIn("k1", out)
        self.assertNotIn("MIIsecond", out)
        self.assertIn("tail", out)
        # the rest of a masked line still goes through the other rules (uci show)
        out = self.sh(r"""sed '/^mcp_main$/d' /tmp/openwrt-mcp-test.sh > /tmp/lib.sh
            . /tmp/lib.sh
            printf '%s\n' "x.y.key='-----BEGIN PRIVATE KEY-----k-----END PRIVATE KEY----- hunter2'" | redact""")
        self.assertNotIn("hunter2", out)

    @needs_container
    def test_lib_sockets(self):
        # a listener we know: busybox nc may be missing, so use the server itself? no:
        # just check format on whatever /proc/net has
        out = self.sh(r"""sed '/^mcp_main$/d' /tmp/openwrt-mcp-test.sh > /tmp/lib.sh
            . /tmp/lib.sh; lib_sockets; echo END""")
        for line in out.splitlines():
            if line == "END":
                break
            f = line.split("\t")
            self.assertEqual(len(f), 9, line)
            self.assertIn(f[0], ("tcp", "tcp6", "udp", "udp6", "raw", "raw6"))


ADMIN_SHIM = r"""
mcp_register_admin t_admin <<'EOF'
{"name":"t_admin","description":"test","inputSchema":{"type":"object"}}
EOF
tool_t_admin() { echo changed; }
"""


class TestAdminMode(OpenWrtTestCase):
    def test_read_only_by_default(self):
        names = [t["name"] for t in self.session().request("tools/list")["result"]["tools"]]
        for t in ADMIN_TOOLS:
            self.assertNotIn(t, names)
        self.assertIn("mode          read-only (no write tools)", self.tool_ok("server_info"))

    @needs_container
    def test_admin_registration(self):
        self.sh(f"cat >> /tmp/openwrt-mcp-test.sh <<'SHIM'\n{ADMIN_SHIM}\nSHIM\n"
                "sed -i '/^mcp_main$/d' /tmp/openwrt-mcp-test.sh && echo mcp_main >> /tmp/openwrt-mcp-test.sh")
        try:
            for env, on in (({}, False), ({"MCP_ADMIN": "yes"}, False), (ADMIN_ENV, True)):
                with self.subTest(env=env):
                    s = self.new_session(env)
                    r = s.initialize()
                    names = [t["name"] for t in s.request("tools/list")["result"]["tools"]]
                    self.assertEqual("t_admin" in names, on)
                    self.assertEqual(r["result"]["serverInfo"]["title"], "OpenWrt (admin)" if on else "OpenWrt")
                    self.assertEqual("Admin mode" in r["result"]["instructions"], on)
                    if on:
                        self.assertEqual(s.call_tool("t_admin")[0].strip(), "changed")
                        self.assertIn("admin (write tools on)", s.call_tool("server_info")[0])
                    else:
                        r = s.request("tools/call", {"name": "t_admin", "arguments": {}})
                        self.assertEqual(r["error"]["code"], -32602)
                    s.close()
        finally:
            self.container.push_server()

    @needs_container
    def test_read_only_build_runs(self):
        # the script the launcher ships without --admin: no write tool, even if MCP_ADMIN
        # were set by hand, and the read-only tools work
        self.container.put(REMOTE_SCRIPT, build_server(admin=False))
        try:
            for env in ({}, ADMIN_ENV):
                with self.subTest(env=env):
                    s = self.new_session(env)
                    s.initialize()
                    names = [t["name"] for t in s.request("tools/list")["result"]["tools"]]
                    for t in ADMIN_TOOLS:
                        self.assertNotIn(t, names)
                    self.assertIn("glinet", names)
                    self.assertEqual(names[-1], "exec")
                    text, err = s.call_tool("system_info")
                    self.assertFalse(err, text)
                    s.close()
        finally:
            self.container.push_server()

    @needs_container
    def test_cfg_changes(self):
        out = self.sh(r"""sed '/^mcp_main$/d' /tmp/openwrt-mcp-test.sh > /tmp/lib.sh
            . /tmp/lib.sh
            mkdir -p /tmp/cc && cd /tmp/cc && rm -rf snap snap.after
            printf "config t 'a'\n\toption name 'one'\n\toption key 'hunter2'\n\tlist l 'x'\n" > /etc/config/zztest
            lib_cfg_snapshot snap
            lib_cfg_changes snap; echo ==
            uci set zztest.a.name=two; uci set zztest.a.key=s3cret; uci add_list zztest.a.l=y
            uci set zztest.b=t; uci commit zztest
            printf "config x\n" > /etc/config/zznew
            lib_cfg_changes snap; echo ==
            lib_cfg_changes snap 2
            rm -f /etc/config/zztest /etc/config/zznew""")
        first, second, third = out.split("==\n")
        self.assertEqual(first.strip(), "no change in /etc/config")
        self.assertIn("config zztest: 3 removed, 4 added", second)
        self.assertIn("  - zztest.a.name='one'", second)
        self.assertIn("  + zztest.a.name='two'", second)
        self.assertIn("  + zztest.b=t", second)
        self.assertIn("config zznew: new package", second)
        self.assertNotIn("hunter2", second)
        self.assertNotIn("s3cret", second)
        self.assertIn("zztest.a.key='<redacted>'", second)
        self.assertIn("  ... 5 more lines", third)


if __name__ == "__main__":
    unittest.main()
