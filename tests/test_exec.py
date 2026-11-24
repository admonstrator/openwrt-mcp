"""The exec tool: output, exit status, timeout, cwd, trusted tools and its definition."""

import time
import unittest

from mcp_client import OpenWrtTestCase, needs_container

# A fake firmware busybox: answers "true" and "--list" (one applet, mcpfake) and, when
# run as mcpfake through the server's symlink, says where it comes from.
FAKE_BUSYBOX = r"""#!/bin/sh
case ${0##*/} in
mcpfake) echo "fake applet from the firmware image" ;;
*) case $1 in --list) echo mcpfake ;; true) exit 0 ;; *) exit 1 ;; esac ;;
esac
"""


class TestExec(OpenWrtTestCase):
    def run_exec(self, env=None, **args):
        return self.session(env).call_tool("exec", args)

    def test_definition(self):
        tools = {t["name"]: t for t in self.session().request("tools/list")["result"]["tools"]}
        t = tools["exec"]
        self.assertEqual(list(tools)[-1], "exec", "exec should come last")
        a = t["annotations"]
        self.assertIs(a["readOnlyHint"], False)
        self.assertIs(a["destructiveHint"], True)
        self.assertIs(a["openWorldHint"], True)
        d = t["description"]
        for words in ("as root", "approved by the user", "dedicated read-only tools", "netstat",
                      "gl-helper", "not redacted"):
            self.assertIn(words, d)
        props = t["inputSchema"]["properties"]
        self.assertEqual(set(props), {"command", "timeout", "trusted_tools", "cwd"})
        self.assertEqual(t["inputSchema"]["required"], ["command"])
        self.assertIs(t["inputSchema"]["additionalProperties"], False)

    def test_output_and_exit_status(self):
        text, err = self.run_exec(command="echo out; echo err >&2; exit 3")
        self.assertFalse(err, text)
        self.assertEqual(text, "out\nerr\n\n[exit 3]")
        text, err = self.run_exec(command="printf 'no newline'")
        self.assertEqual(text, "no newline\n[exit 0]")

    def test_stdin_is_empty(self):
        text, _ = self.run_exec(command="cat; echo end")
        self.assertEqual(text, "end\n\n[exit 0]")

    def test_cwd(self):
        text, err = self.run_exec(command="pwd", cwd="/etc")
        self.assertEqual(text, "/etc\n\n[exit 0]")
        text, err = self.run_exec(command="pwd")
        self.assertTrue(text.startswith("/\n"), text)
        text, err = self.run_exec(command="pwd", cwd="/no/such/dir")
        self.assertTrue(err)
        self.assertIn("/no/such/dir", text)

    def test_bad_arguments(self):
        for args, want in (({"command": "true", "timeout": 0}, "between 1 and 600"),
                           ({"command": "true", "timeout": 601}, "between 1 and 600"),
                           ({"command": "true", "timeout": "5"}, "must be an integer"),
                           ({"command": ""}, "command is empty"),
                           ({}, 'missing required argument "command"')):
            with self.subTest(args=args):
                text, err = self.run_exec(**args)
                self.assertTrue(err)
                self.assertIn(want, text)

    def test_not_redacted(self):
        text, _ = self.run_exec(command="echo \"option key 'hunter2'\"")
        self.assertIn("hunter2", text)

    @needs_container
    def test_timeout_kills_tree(self):
        t0 = time.time()
        text, err = self.run_exec(command="echo before; sleep 941 | cat; echo after", timeout=2)
        self.assertLess(time.time() - t0, 30)
        self.assertTrue(err)
        self.assertEqual(text, "before\n\n[timeout after 2 s]")
        self.assertEqual([p for p in self.container.procs() if "sleep 941" in p[3]], [])
        # the server keeps serving
        self.assertIn("[exit 0]", self.run_exec(command="true")[0])

    # A firmware image like OpenWrt's: busybox without the "busybox" applet (so no
    # --list), reached through relative links in bin, sbin, usr/bin and usr/sbin. The
    # containers' own /bin/busybox and links have exactly that shape; copy them.
    OPENWRT_ROM = r"""rm -rf /fixture/owrt && for d in bin sbin usr/bin usr/sbin; do mkdir -p /fixture/owrt/$d; done
        cp /bin/busybox /fixture/owrt/bin/
        for f in $(find /bin /sbin /usr/bin /usr/sbin -type l); do
            [ "$(readlink -f "$f")" = /bin/busybox ] && cp -a "$f" "/fixture/owrt$f"
        done
        /fixture/owrt/bin/busybox --list | wc -l; find /fixture/owrt -type l | wc -l"""

    @needs_container
    def test_trusted_tools_openwrt_image(self):
        listed, links = (int(x) for x in self.sh(self.OPENWRT_ROM).split())
        self.assertEqual(listed, 0, "the fixture busybox must not answer --list, like OpenWrt's")
        self.assertGreater(links, 50)
        env = {"MCP_ROM": "/fixture/owrt"}
        info, _ = self.session(env).call_tool("server_info")
        self.assertIn(f"trusted tools yes (/fixture/owrt/bin/busybox, {links} applets)", info)
        # the image's links win, and they run the image's busybox
        text, _ = self.run_exec(env, command="for c in ls sleep head ifconfig; do command -v $c; done;"
                                             " readlink -f $(command -v ls); ls /fixture >/dev/null && echo ok")
        lines = text.splitlines()
        for line in lines[:4]:
            self.assertRegex(line, r"^/tmp/openwrt-mcp\.[^/]+/bin/(ls|sleep|head|ifconfig)$")
        self.assertEqual(lines[4], "/fixture/owrt/bin/busybox")
        self.assertEqual(lines[5], "ok")
        # trusted_tools=false: the router's own PATH
        text, _ = self.run_exec(env, command="command -v ls", trusted_tools=False)
        self.assertTrue(text.startswith("/bin/ls\n"), text)

        # the image's jsonfilter is used too when it works
        self.sh("mkdir -p /fixture/owrt/usr/bin && cp /usr/bin/jsonfilter /fixture/owrt/usr/bin/")
        env2 = {"MCP_ROM": "/fixture/owrt", "MCP_DEBUG": "0"}
        info, _ = self.session(env2).call_tool("server_info")
        self.assertIn(f"trusted tools yes (/fixture/owrt/bin/busybox, {links} applets;"
                      " /fixture/owrt/usr/bin/jsonfilter)", info)
        text, _ = self.run_exec(env2, command="readlink $(command -v jsonfilter)")
        self.assertIn("/fixture/owrt/usr/bin/jsonfilter\n", text)

    @needs_container
    def test_trusted_tools_none_found(self):
        # a busybox that runs but has neither links nor --list: not "yes"
        self.sh("rm -rf /fixture/bare && mkdir -p /fixture/bare/bin && cp /bin/busybox /fixture/bare/bin/")
        env = {"MCP_ROM": "/fixture/bare"}
        info, _ = self.session(env).call_tool("server_info")
        self.assertIn("trusted tools no (/fixture/bare/bin/busybox runs, but no applet links", info)
        text, _ = self.run_exec(env, command="command -v ls")
        self.assertTrue(text.startswith("/bin/ls\n"), text)

    @needs_container
    def test_trusted_tools_list_fallback(self):
        # a busybox that does answer --list (not OpenWrt's) still works
        self.sh("mkdir -p /fixture/rom/bin && cat > /fixture/rom/bin/busybox <<'EOF'\n"
                f"{FAKE_BUSYBOX}EOF\nchmod 755 /fixture/rom/bin/busybox")
        env = {"MCP_ROM": "/fixture/rom"}
        info, _ = self.session(env).call_tool("server_info")
        self.assertIn("trusted tools yes (/fixture/rom/bin/busybox, 1 applets)", info)
        text, err = self.run_exec(env, command="mcpfake; echo $PATH")
        self.assertIn("fake applet from the firmware image", text)
        self.assertRegex(text, r"\n/tmp/openwrt-mcp\.[^/]+/bin:")
        text, err = self.run_exec(env, command="mcpfake; echo $PATH", trusted_tools=False)
        self.assertNotIn("fake applet", text)
        self.assertIn("not found", text)
        self.assertNotIn("/tmp/openwrt-mcp.", text)
        # without a firmware busybox the normal PATH
        text, _ = self.run_exec(command="echo $PATH")
        self.assertNotIn("/tmp/openwrt-mcp.", text)


if __name__ == "__main__":
    unittest.main()
