"""Admin tools uci_change and service_control (server/65-admin-uci.sh). Container only:
every test writes; the harness never sends these tools to a real router."""

import unittest

from mcp_client import ADMIN_ENV, OpenWrtTestCase, needs_container

FIXTURE = b"""config main 'main'
\toption enabled '1'
\toption password 'hunter2'
\tlist server 'a.example'
\tlist server 'b.example'

config item
\toption name 'one'

config item
\toption name 'two'
"""

NETWORK = b"""config interface 'lan'
\toption proto 'static'
\toption ipaddr '192.168.1.1'
"""

INIT = b"""#!/bin/sh /etc/rc.common
START=99
start() { touch /tmp/zzmcp.on; echo started; echo "password=hunter2"; }
stop() { rm -f /tmp/zzmcp.on; echo stopped; }
reload() { sleep 30; }
"""


class TestUciChange(OpenWrtTestCase):
    def setUp(self):
        if not self.container:
            self.skipTest("needs a container")
        self.container.put("/etc/config/mcptest", FIXTURE)
        self.sh("rm -rf /tmp/.uci /etc/glversion; [ -e /sbin/reload_config.off ] && "
                "mv /sbin/reload_config.off /sbin/reload_config; :")

    def uc(self, changes, **kw):
        return self.tool("uci_change", env=ADMIN_ENV, package=kw.pop("package", "mcptest"),
                         changes=changes, **kw)

    def config(self, pkg="mcptest"):
        return self.sh(f"cat /etc/config/{pkg}")

    def assertUnchanged(self):
        self.assertEqual(self.config().encode(), FIXTURE)
        self.assertEqual(self.sh("uci -q changes mcptest; :"), "")

    @needs_container
    def test_set_commits_and_reports(self):
        text, err = self.uc([{"op": "set", "path": "main.enabled", "value": "0"}])
        self.assertFalse(err, text)
        self.assertIn("== Plan: 1 operation(s) on /etc/config/mcptest", text)
        self.assertIn("1 set mcptest.main.enabled='0'", text)
        self.assertIn("committed /etc/config/mcptest (1 operation(s))", text)
        self.assertIn("== Changes in /etc/config", text)
        self.assertIn("config mcptest: 1 removed, 1 added", text)
        self.assertIn("  - mcptest.main.enabled='1'", text)
        self.assertIn("  + mcptest.main.enabled='0'", text)
        self.assertIn("option enabled '0'", self.config())
        self.assertEqual(self.sh("uci -q changes mcptest; :"), "")

    @needs_container
    def test_every_op(self):
        text, err = self.uc([
            {"op": "add", "value": "item"},
            {"op": "set", "path": "@item[-1].name", "value": "three"},
            {"op": "add_list", "path": "main.server", "value": "c.example"},
            {"op": "del_list", "path": "main.server", "value": "a.example"},
            {"op": "delete", "path": "@item[0].name"},
            {"op": "set", "path": "extra", "value": "item"},
            {"op": "set", "path": "extra.name", "value": "four"},
        ])
        self.assertFalse(err, text)
        self.assertRegex(text, r"change 1 \(add\): new section cfg[0-9a-f]+")
        show = self.sh("uci show mcptest")
        self.assertIn("mcptest.main.server='b.example' 'c.example'", show)
        self.assertIn("mcptest.@item[2].name='three'", show)
        self.assertNotIn("mcptest.@item[0].name", show)
        self.assertIn("mcptest.extra=item", show)
        self.assertIn("mcptest.extra.name='four'", show)

    @needs_container
    def test_values_are_literal(self):
        value = "a b; $(touch /tmp/pwned) `touch /tmp/pwned2` \"dq\" 'sq' \\ |&>< *\tend"
        text, err = self.uc([{"op": "set", "path": "main.weird", "value": value},
                             {"op": "add_list", "path": "main.server", "value": "-x $HOME"}])
        self.assertFalse(err, text)
        self.assertEqual(self.sh("uci -q get mcptest.main.weird"), value + "\n")
        self.assertIn("'-x $HOME'", self.sh("uci show mcptest.main.server"))
        self.assertEqual(self.sh("ls /tmp/pwned /tmp/pwned2 2>/dev/null; :"), "")

    @needs_container
    def test_line_break_refused(self):
        for v in ("a\nb", "a\r", "end\n"):
            with self.subTest(value=v):
                text, err = self.uc([{"op": "set", "path": "main.x", "value": v}])
                self.assertTrue(err, text)
                self.assertIn("line break", text)
        self.assertUnchanged()

    @needs_container
    def test_dry_run_touches_nothing(self):
        before = self.sh("md5sum /etc/config/mcptest")
        text, err = self.uc([{"op": "set", "path": "main.enabled", "value": "0"},
                             {"op": "delete", "path": "@item[1].name"}], dry_run=True)
        self.assertFalse(err, text)
        self.assertIn("== Dry run: lines that would change (nothing was written)", text)
        self.assertIn("config mcptest: 2 removed, 1 added", text)
        self.assertIn("  + mcptest.main.enabled='0'", text)
        self.assertIn("  - mcptest.@item[1].name='two'", text)
        self.assertNotIn("== Changes in /etc/config", text)
        self.assertEqual(self.sh("md5sum /etc/config/mcptest"), before)
        self.assertEqual(self.sh("ls -A /tmp/.uci 2>/dev/null; :"), "")
        self.assertUnchanged()

    @needs_container
    def test_bad_operation_changes_nothing(self):
        text, err = self.uc([{"op": "set", "path": "main.enabled", "value": "0"},
                             {"op": "set", "path": "nosuch.x", "value": "1"}])
        self.assertTrue(err, text)
        self.assertIn("invalid operation, nothing was changed: change 2 (set): uci refused it", text)
        self.assertUnchanged()
        bad = [
            ([{"op": "rename", "path": "main.x", "value": "y"}], "unknown op 'rename'"),
            ([{"path": "main.x", "value": "y"}], "needs an op"),
            ([{"op": "set", "path": "main.x.y", "value": "1"}], "is not a uci option name"),
            ([{"op": "set", "path": "ma-in.x", "value": "1"}], "is not a uci section name"),
            ([{"op": "set", "path": "@item[x].name", "value": "1"}], "is not a uci section name"),
            ([{"op": "set", "path": "main.x", "value": 1}], "must be strings"),
            ([{"op": "set", "path": ["main.x"], "value": "1"}], "must be strings"),
            ([{"op": "set", "path": "main.x", "value": None}], "must not be null"),
            ([{"op": "set", "path": "main.x"}], "needs a value"),
            ([{"op": "set", "path": "main.x", "value": "1", "extra": 1}], "unknown"),
            ([{"op": "delete", "path": "main.enabled", "value": "1"}], "takes no value"),
            ([{"op": "add", "path": "main", "value": "item"}], "takes no path"),
            ([{"op": "add", "value": "bad type"}], "not a section type name"),
            ([{"op": "add_list", "path": "main", "value": "x"}], "needs a path section.option"),
            ([{"op": "set", "path": "main", "value": "bad type"}], "not a type name"),
            (["set main.x=1"], "must be an object"),
            ([], "at least one operation"),
        ]
        for changes, msg in bad:
            with self.subTest(changes=changes):
                text, err = self.uc(changes)
                self.assertTrue(err, text)
                self.assertIn(msg, text)
        for pkg, msg in (("nosuchpkg", "does not exist"), ("../etc/passwd", "letters, digits"),
                         ("-q", "not starting with -")):
            with self.subTest(package=pkg):
                text, err = self.uc([{"op": "set", "path": "main.x", "value": "1"}], package=pkg)
                self.assertTrue(err, text)
                self.assertIn(msg, text)
        text, err = self.uc([{"op": "set", "path": "main.x", "value": "1"}] * 101)
        self.assertTrue(err, text)
        self.assertIn("at most 100", text)
        self.assertUnchanged()

    @needs_container
    def test_pending_changes_refused(self):
        self.sh("uci set mcptest.main.enabled=5")
        try:
            text, err = self.uc([{"op": "set", "path": "main.other", "value": "1"}])
            self.assertTrue(err, text)
            self.assertIn("uncommitted changes that are not from this call", text)
            self.assertIn("mcptest.main.enabled='5'", text)
            self.assertEqual(self.config().encode(), FIXTURE)
            self.assertEqual(self.sh("uci changes mcptest"), "mcptest.main.enabled='5'\n")
            # a dry run still works and warns
            text, err = self.uc([{"op": "set", "path": "main.other", "value": "1"}], dry_run=True)
            self.assertFalse(err, text)
            self.assertIn("A real run is refused until these are committed or reverted", text)
            self.assertIn("  + mcptest.main.other='1'", text)
            self.assertNotIn("enabled='5'\n  +", text)
            self.assertEqual(self.sh("uci changes mcptest"), "mcptest.main.enabled='5'\n")
        finally:
            self.sh("uci revert mcptest")

    @needs_container
    def test_risky_needs_confirm(self):
        self.container.put("/etc/config/network", NETWORK)
        change = [{"op": "set", "path": "lan.ipaddr", "value": "192.168.8.1"}]
        text, err = self.uc(change, package="network")
        self.assertTrue(err, text)
        self.assertIn("risky change, not applied: package network", text)
        self.assertIn("confirm: true", text)
        self.assertIn("1 set network.lan.ipaddr='192.168.8.1'", text)
        self.assertEqual(self.config("network").encode(), NETWORK)
        text, err = self.uc(change, package="network", dry_run=True)
        self.assertFalse(err, text)
        self.assertIn("== Risk", text)
        self.assertEqual(self.config("network").encode(), NETWORK)
        text, err = self.uc(change, package="network", confirm=True)
        self.assertFalse(err, text)
        self.assertIn("config network: 1 removed, 1 added", text)
        self.assertIn("option ipaddr '192.168.8.1'", self.config("network"))
        # deleting a whole section is risky in any package
        text, err = self.uc([{"op": "delete", "path": "@item[0]"}])
        self.assertTrue(err, text)
        self.assertIn("deletes the whole section mcptest.@item[0]", text)
        self.assertUnchanged()
        text, err = self.uc([{"op": "delete", "path": "@item[0]"}], confirm=True)
        self.assertFalse(err, text)
        self.assertNotIn("'one'", self.config())

    @needs_container
    def test_secrets_redacted(self):
        text, err = self.uc([{"op": "set", "path": "main.password", "value": "newsecret"},
                             {"op": "set", "path": "main.key", "value": "otherkey"}])
        self.assertFalse(err, text)
        self.assertIn("1 set mcptest.main.password='<redacted>'", text)
        self.assertIn("  + mcptest.main.password='<redacted>'", text)
        for s in ("newsecret", "hunter2", "otherkey"):
            self.assertNotIn(s, text)
        self.assertIn("option password 'newsecret'", self.config())

    @needs_container
    def test_reload_messages(self):
        change = [{"op": "set", "path": "main.enabled", "value": "0"}]
        text, err = self.uc(change)
        self.assertFalse(err, text)
        self.assertIn("reload_config  /sbin/reload_config", text)
        self.assertIn("procd/ubus     not running", text)
        self.assertIn("NOT APPLIED: the change is committed to /etc/config/mcptest", text)
        self.sh("mv /sbin/reload_config /sbin/reload_config.off")
        text, err = self.uc([{"op": "set", "path": "main.enabled", "value": "1"}])
        self.assertFalse(err, text)
        self.assertIn("reload_config  not available on this firmware", text)
        text, err = self.uc(change, reload=False)
        self.assertFalse(err, text)
        self.assertIn("not reloaded (reload: false)", text)

    @needs_container
    def test_glinet_note(self):
        change = [{"op": "set", "path": "main.enabled", "value": "0"}]
        text = self.tool_ok("uci_change", env=ADMIN_ENV, package="mcptest", changes=change, dry_run=True)
        self.assertNotIn("glinet_api", text)
        self.sh("echo 4.11.0 > /etc/glversion")
        text = self.tool_ok("uci_change", env=ADMIN_ENV, package="mcptest", changes=change)
        self.assertIn("== Note", text)
        self.assertIn("glinet_api", text)


class TestServiceControl(OpenWrtTestCase):
    def setUp(self):
        if not self.container:
            self.skipTest("needs a container")
        self.container.put("/etc/init.d/zzmcp", INIT)
        self.sh("chmod 755 /etc/init.d/zzmcp; rm -f /tmp/zzmcp.on /etc/rc.d/S99zzmcp")

    def sc(self, service, action, **kw):
        return self.tool("service_control", env=ADMIN_ENV, service=service, action=action, **kw)

    @needs_container
    def test_status_start_stop(self):
        text, err = self.sc("zzmcp", "status")
        self.assertFalse(err, text)
        self.assertIn("enabled  no (no /etc/rc.d/S??zzmcp link)", text)
        self.assertIn("running  unknown (ubus or procd not available)", text)
        text, err = self.sc("zzmcp", "start")
        self.assertFalse(err, text)
        self.assertIn("== /etc/init.d/zzmcp start", text)
        self.assertIn("started\npassword=<redacted>", text)
        self.assertNotIn("hunter2", text)
        self.assertIn("[exit 0]", text)
        self.assertEqual(self.sh("ls /tmp/zzmcp.on"), "/tmp/zzmcp.on\n")
        text, err = self.sc("zzmcp", "stop")
        self.assertFalse(err, text)
        self.assertIn("stopped", text)
        self.assertEqual(self.sh("ls /tmp/zzmcp.on 2>/dev/null; :"), "")

    @needs_container
    def test_enable_disable(self):
        text, err = self.sc("zzmcp", "enable")
        self.assertFalse(err, text)
        self.assertIn("enabled  yes (/etc/rc.d/S99zzmcp)", text)
        text, err = self.sc("zzmcp", "disable")
        self.assertFalse(err, text)
        self.assertIn("enabled  no", text)

    @needs_container
    def test_bad_names_refused(self):
        for name, msg in (("nosuch", "no init script /etc/init.d/nosuch"),
                          ("../init.d/zzmcp", "letters, digits"), ("/etc/init.d/zzmcp", "letters, digits"),
                          ("..", "not starting with ."), (".", "not starting with ."),
                          ("-zz", "not starting with"), ("zz mcp", "letters, digits")):
            with self.subTest(name=name):
                text, err = self.sc(name, "status")
                self.assertTrue(err, text)
                self.assertIn(msg, text)
        text, err = self.sc("zzmcp", "kill")
        self.assertTrue(err, text)
        self.assertIn("action must be one of", text)

    @needs_container
    def test_risky_and_refused(self):
        self.container.put("/etc/init.d/tailscale", INIT)
        self.sh("chmod 755 /etc/init.d/tailscale; touch /tmp/zzmcp.on")
        text, err = self.sc("tailscale", "stop")
        self.assertTrue(err, text)
        self.assertIn("risky action, not run: stop of tailscale", text)
        self.assertEqual(self.sh("ls /tmp/zzmcp.on"), "/tmp/zzmcp.on\n")
        text, err = self.sc("tailscale", "start")
        self.assertFalse(err, text)
        text, err = self.sc("tailscale", "stop", confirm=True)
        self.assertFalse(err, text)
        self.assertEqual(self.sh("ls /tmp/zzmcp.on 2>/dev/null; :"), "")
        self.sh("rm -f /etc/init.d/tailscale")
        for action in ("start", "disable"):
            text, err = self.sc("boot", action, confirm=True)
            self.assertTrue(err, text)
            self.assertIn("refused: /etc/init.d/boot runs only at boot or shutdown", text)
        self.assertIn("S10boot", self.sh("ls /etc/rc.d"))
        text, err = self.sc("boot", "status")
        self.assertFalse(err, text)
        self.assertIn("enabled  yes (/etc/rc.d/S10boot)", text)

    @needs_container
    def test_timeout(self):
        # timeout= of self.tool is the harness' own limit: send the argument directly
        text, err = self.session(ADMIN_ENV).call_tool(
            "service_control", {"service": "zzmcp", "action": "reload", "timeout": 1})
        self.assertTrue(err, text)
        self.assertIn("[timeout after 1 s]", text)


class TestAdminOff(OpenWrtTestCase):
    @needs_container
    def test_unknown_without_admin(self):
        s = self.session()
        names = [t["name"] for t in s.request("tools/list")["result"]["tools"]]
        for t in ("uci_change", "service_control"):
            self.assertNotIn(t, names)
            r = s.request("tools/call", {"name": t, "arguments": {}})
            self.assertEqual(r["error"]["code"], -32602)
            self.assertIn("Unknown tool", r["error"]["message"])
        names = [t["name"] for t in self.session(ADMIN_ENV).request("tools/list")["result"]["tools"]]
        self.assertIn("uci_change", names)
        self.assertIn("service_control", names)
        self.assertEqual(names[-1], "exec")


if __name__ == "__main__":
    unittest.main()
