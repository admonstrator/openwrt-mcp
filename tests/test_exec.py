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

    @needs_container
    def test_trusted_tools(self):
        self.sh("mkdir -p /fixture/rom/bin && cat > /fixture/rom/bin/busybox <<'EOF'\n"
                f"{FAKE_BUSYBOX}EOF\nchmod 755 /fixture/rom/bin/busybox")
        env = {"MCP_ROM": "/fixture/rom"}
        info, _ = self.session(env).call_tool("server_info")
        self.assertIn("trusted tools yes (/fixture/rom/bin/busybox)", info)

        text, err = self.run_exec(env, command="mcpfake; echo $PATH")
        self.assertIn("fake applet from the firmware image", text)
        self.assertRegex(text, r"\n/tmp/openwrt-mcp\.[^/]+/bin:")
        self.assertIn("[exit 0]", text)

        text, err = self.run_exec(env, command="mcpfake; echo $PATH", trusted_tools=False)
        self.assertNotIn("fake applet", text)
        self.assertIn("not found", text)
        self.assertNotIn("/tmp/openwrt-mcp.", text)

        # without a firmware busybox both settings use the normal PATH
        text, _ = self.run_exec(command="echo $PATH")
        self.assertNotIn("/tmp/openwrt-mcp.", text)


if __name__ == "__main__":
    unittest.main()
