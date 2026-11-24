"""System inventory tools: system_info, processes, services, packages, logs,
kernel_modules, uci (server/10-system.sh) and the helpers in server/05-lib.sh.

The containers run no procd or ubusd and have no firmware image in /rom, so the tests
build fixtures: a fake firmware root passed as MCP_ROM, and a fake `ubus` early in PATH
that answers from canned JSON (with a real ubusd running so the socket exists).
"""

import json
import re
import unittest

from mcp_client import OpenWrtTestCase, needs_container

WIFI_KEY = "SuperSecretWifiKey123"
ENV_SECRET = "hunter2envsecret"
FAKE_PATH = "/fixture/bin:/usr/sbin:/usr/bin:/sbin:/bin"

WIRELESS = f"""config wifi-device 'radio0'
\toption type 'mac80211'
\toption channel '36'

config wifi-iface 'default_radio0'
\toption device 'radio0'
\toption mode 'ap'
\toption ssid 'HomeNet'
\toption encryption 'psk2'
\toption key '{WIFI_KEY}'
"""


def write_file(tc: OpenWrtTestCase, path: str, content: str, mode: str = "644") -> None:
    """Write content to path inside the container (heredoc, no shell expansion)."""
    assert "__FIXTURE_EOF__" not in content
    tc.sh(f"mkdir -p \"$(dirname '{path}')\" && cat > '{path}' <<'__FIXTURE_EOF__'\n{content}\n__FIXTURE_EOF__\n"
          f"chmod {mode} '{path}'")


def fake_ubus(tc: OpenWrtTestCase, answers: dict) -> None:
    """Install /fixture/bin/ubus answering 'ubus call OBJ METHOD' from answers
    {"obj method": python_object}, printed tab-indented like the real ubus, and start a
    real ubusd so the socket the server checks for exists."""
    for key, obj in answers.items():
        write_file(tc, f"/fixture/ubus/{key.replace(' ', '.')}.json", json.dumps(obj, indent="\t"))
    write_file(tc, "/fixture/bin/ubus",
               '#!/bin/sh\n[ "$1" = call ] || exit 1\nf="/fixture/ubus/$2.$3.json"\n'
               '[ -f "$f" ] || exit 4\ncat "$f"', mode="755")
    tc.sh("mkdir -p /var/run/ubus; [ -S /var/run/ubus/ubus.sock ] || "
          "{ (ubusd -s /var/run/ubus/ubus.sock >/dev/null 2>&1 &); sleep 1; }; "
          "[ -S /var/run/ubus/ubus.sock ]")


def fake_rom(tc: OpenWrtTestCase) -> None:
    """A firmware image root at /fixture/rom: a copy of /etc, /bin, /lib/modules and the
    package database as they are now, so files added afterwards are 'not in the image'."""
    tc.sh("mkdir -p /fixture/rom/usr/lib /fixture/rom/lib && cp -a /etc /bin /fixture/rom/ "
          "&& { [ -d /usr/lib/opkg ] && cp -a /usr/lib/opkg /fixture/rom/usr/lib/ || true; } "
          "&& { [ -d /lib/apk ] && cp -a /lib/apk /fixture/rom/lib/ || true; }")


def flagged_line(text: str, pid: str) -> str:
    for line in text.splitlines():
        if line.split()[:1] == [pid] and "!!" in line:
            return line
    return ""


class TestSystemInfo(OpenWrtTestCase):
    def test_sections(self):
        text = self.tool_ok("system_info")
        for head in ("== Identity", "== Firmware", "== Kernel", "== CPU", "== Uptime and load",
                     "== Memory", "== Storage", "== Mounts", "== Root filesystem", "== Time"):
            self.assertIn(head, text)
        self.assertIn("DISTRIB_RELEASE=", text)
        self.assertRegex(text, r"uptime\s+\d+d \d\d:\d\d:\d\d")
        self.assertRegex(text, r"booted\s+20\d\d-\d\d-\d\d \d\d:\d\d:\d\d")
        self.assertRegex(text, r"\n/\s+\S+\s+\S+\s+r[ow]")  # root mount with its flags
        self.assertRegex(text, r"layout\s+\S")

    @needs_container
    def test_missing_sources_say_so(self):
        text = self.tool_ok("system_info")
        self.assertIn("board.json       not present", text)
        self.assertIn("ubus board       not available", text)
        self.assertIn("glversion        not present", text)
        self.assertIn("not usable", text)  # no firmware image in the container

    @needs_container
    def test_glinet_and_board(self):
        self.sh("mkdir -p /tmp/sysinfo && echo 'GL.iNet GL-MT3000' > /tmp/sysinfo/model && "
                "echo glinet,mt3000 > /tmp/sysinfo/board_name && echo 4.7.0 > /etc/glversion && "
                "echo release > /etc/version.type")
        fake_ubus(self, {"system board": {"model": "GL.iNet GL-MT3000", "board_name": "glinet,mt3000",
                                          "kernel": "5.4.211", "release": {"description": "OpenWrt 21.02-SNAPSHOT"}}})
        text = self.tool_ok("system_info", env={"PATH": FAKE_PATH})
        self.assertIn("model            GL.iNet GL-MT3000", text)
        self.assertIn("glversion 4.7.0", text)
        self.assertIn("version.type release", text)
        self.assertIn("ubus release.description OpenWrt 21.02-SNAPSHOT", text)
        self.sh("rm -f /etc/glversion /etc/version.type; rm -rf /tmp/sysinfo")


class TestProcesses(OpenWrtTestCase):
    @needs_container
    def test_list_and_deleted_exe(self):
        # a busybox copy whose file is deleted while it runs (applet name from argv[0])
        pid = self.sh("cp /bin/busybox /tmp/sleep && (/tmp/sleep 300 >/dev/null 2>&1 & echo $! >/tmp/dpid); "
                      "sleep 1; rm /tmp/sleep; cat /tmp/dpid").strip()
        text = self.tool_ok("processes")
        self.assertIn("== Flagged processes", text)
        self.assertIn("== Process list", text)
        self.assertRegex(text, r"\d+ processes: \d+ user, \d+ kernel threads")
        line = flagged_line(text, pid)
        # native: exe-deleted; under qemu emulation /proc/PID/exe is the emulator and the
        # deleted program shows as a mapping
        self.assertRegex(line, r"(exe-deleted|mapped-deleted:/tmp/sleep)", text)
        self.assertRegex(line, r"\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d")
        # the server's own pipeline is left out
        me = re.search(r"this server \(pid (\d+)\)", text).group(1)
        self.assertFalse([l for l in text.splitlines() if l.split()[:1] == [me]], text)

    @needs_container
    def test_filter_and_cap(self):
        self.sh("(sleep 301 >/dev/null 2>&1 &); (sleep 302 >/dev/null 2>&1 &)")
        text = self.tool_ok("processes", filter="sleep 30")
        self.assertIn("sleep 301", text)
        self.assertNotIn("uhttpd", text)
        text = self.tool_ok("processes", filter="sleep 30", max_results=1)
        self.assertIn("more not shown (max_results=1", text)

    @needs_container
    def test_detail_masks_environment(self):
        pid = self.sh(f"(env DB_PASSWORD={ENV_SECRET} API_TOKEN={ENV_SECRET} PLAIN=visible sleep 303 "
                      ">/dev/null 2>&1 & echo $! >/tmp/epid); sleep 1; cat /tmp/epid").strip()
        text = self.tool_ok("processes", pid=int(pid))
        for head in ("== Process " + pid, "== Command line", "== Open files", "== Sockets of this process",
                     "== Mapped files", "== Environment"):
            self.assertIn(head, text)
        self.assertIn("argv[", text)
        self.assertIn("DB_PASSWORD=<redacted>", text)
        self.assertIn("API_TOKEN=<redacted>", text)
        self.assertIn("PLAIN=visible", text)
        self.assertNotIn(ENV_SECRET, text)
        # with redaction off the value is shown: the masking is what hides it
        text = self.tool_ok("processes", env={"MCP_REDACT": "0"}, pid=int(pid))
        self.assertIn(ENV_SECRET, text)

    @needs_container
    def test_detail_sockets(self):
        pid = self.sh("(uhttpd -f -p 0.0.0.0:8091 -h /www >/dev/null 2>&1 & echo $! >/tmp/upid); sleep 2; "
                      "cat /tmp/upid").strip()
        text = self.tool_ok("processes", pid=int(pid))
        self.assertRegex(text, r"tcp6?\s+LISTEN\s+\S+:8091")

    def test_bad_pid(self):
        text, err = self.tool("processes", pid=99999998)
        self.assertTrue(err)
        self.assertIn("no process", text)


class TestServices(OpenWrtTestCase):
    @needs_container
    def test_process_fallback(self):
        self.sh("uhttpd -p 0.0.0.0:8092 -h /www")
        text = self.tool_ok("services")
        self.assertIn("running state from: process list", text)
        self.assertIn("== Init scripts (/etc/init.d)", text)
        self.assertRegex(text, r"\nuhttpd\s+enabled\s+S50\s+running \(pid \d+\)")
        self.assertRegex(text, r"\ndnsmasq\s+enabled\s+S19\s+not running\s+starts /usr/sbin/dnsmasq")
        self.assertIn("== procd services and instances\nnot available", text)

    @needs_container
    def test_procd_and_persistence_flags(self):
        fake_rom(self)
        # persistence planted after the image: an init script, its boot link, a stray rc.d file
        write_file(self, "/etc/init.d/gl_evil",
                   "#!/bin/sh /etc/rc.common\nSTART=99\nUSE_PROCD=1\nPROG=/tmp/evil\n"
                   "start_service() {\n\tprocd_open_instance\n\tprocd_set_param command $PROG -d\n"
                   "\tprocd_close_instance\n}", mode="755")
        self.sh("ln -sf ../init.d/gl_evil /etc/rc.d/S99gl_evil && echo '/tmp/x &' > /etc/rc.d/S98stray")
        fake_ubus(self, {"service list": {
            "dnsmasq": {"instances": {"cfg01411c": {
                "running": True, "pid": 1234,
                "command": ["/usr/sbin/dnsmasq", "-C", "/var/etc/dnsmasq.conf.cfg01411c", "-k"],
                "term_timeout": 5, "data": {"pid": 99}}}, "triggers": [["config.change", ["if"]]]},
            "gl_evil": {"instances": {"instance1": {"running": True, "pid": 4321, "command": ["/tmp/evil", "-d"]}}},
            "hidden_svc": {"instances": {"main": {"running": False, "command": ["/tmp/.h"]}}},
        }})
        text = self.tool_ok("services", env={"PATH": FAKE_PATH, "MCP_ROM": "/fixture/rom"})
        self.assertIn("running state from: procd", text)
        self.assertRegex(text, r"\ndnsmasq\s+enabled\s+S19\s+running \(1/1 instances\)")
        self.assertRegex(text, r"\ngl_evil\s+enabled\s+S99\s+running \(1/1 instances\)\s+!! not in firmware image; starts /tmp/evil")
        self.assertNotRegex(text, r"\ndnsmasq .*not in firmware image")
        self.assertRegex(text, r"S98stray\s+!! not a symlink")
        self.assertIn("cfg01411c      running=true  pid=1234    /usr/sbin/dnsmasq -C /var/etc/dnsmasq.conf.cfg01411c -k", text)
        self.assertIn("hidden_svc   !! no /etc/init.d/hidden_svc", text)
        text = self.tool_ok("services", env={"PATH": FAKE_PATH, "MCP_ROM": "/fixture/rom"}, filter="gl_")
        self.assertNotIn("dnsmasq", text)
        self.sh("rm -f /etc/init.d/gl_evil /etc/rc.d/S99gl_evil /etc/rc.d/S98stray")


class TestPackages(OpenWrtTestCase):
    def db(self) -> str:
        return "apk" if self.sh("[ -f /lib/apk/db/installed ] && echo apk || echo opkg").strip() == "apk" else "opkg"

    @needs_container
    def test_list(self):
        text = self.tool_ok("packages")
        self.assertRegex(text, r"== Packages \((opkg|apk)\)")
        self.assertRegex(text, r"\nbusybox\s+\S+")
        self.assertIn("== Config files changed against their package", text)
        text = self.tool_ok("packages", filter="dropbear")
        self.assertRegex(text, r"\ndropbear\s+\S+")
        self.assertNotRegex(text, r"\nbusybox\s")

    @needs_container
    def test_origin_against_image(self):
        fake_rom(self)
        if self.db() == "opkg":
            self.sh("awk 'BEGIN{RS=\"\"; ORS=\"\\n\\n\"} !/(^|\\n)Package: uhttpd\\n/' /usr/lib/opkg/status "
                    "> /fixture/rom/usr/lib/opkg/status")
        else:
            self.sh("awk 'BEGIN{RS=\"\"; ORS=\"\\n\\n\"} !/(^|\\n)P:uhttpd\\n/' /lib/apk/db/installed "
                    "> /fixture/rom/lib/apk/db/installed")
        env = {"MCP_ROM": "/fixture/rom"}
        text = self.tool_ok("packages", env=env)
        self.assertIn("compared with the firmware image", text)
        self.assertRegex(text, r"\nuhttpd\s+\S+\s+user")
        self.assertRegex(text, r"\nbusybox\s+\S+\s+image")
        text = self.tool_ok("packages", env=env, user_installed_only=True)
        self.assertRegex(text, r"\nuhttpd\s+\S+\s+user")
        self.assertNotRegex(text, r"\nbusybox\s")

    @needs_container
    def test_changed_config_and_audit(self):
        self.sh("echo '# changed by test' >> /etc/config/dropbear")
        if self.db() == "opkg":
            text = self.tool_ok("packages", audit=True, filter="none-such")
            self.assertRegex(text, r"/etc/config/dropbear\s+changed\s+dropbear")
            self.assertIn("opkg keeps hashes only for config files", text)
        else:
            self.sh("echo '# changed by test' >> /usr/share/libubox/jshn.sh")
            text = self.tool_ok("packages", audit=True, filter="none-such")
            self.assertIn("U etc/config/dropbear", text)
            self.assertIn("== Package files changed against the package database", text)
            self.assertIn("U usr/share/libubox/jshn.sh", text)


class TestLogs(OpenWrtTestCase):
    @needs_container
    def test_sources(self):
        text = self.tool_ok("logs")
        self.assertIn("== System log", text)
        self.assertIn("logread: not available", text)  # no logd in the container
        text = self.tool_ok("logs", source="kernel")
        self.assertIn("== Kernel ring buffer", text)

    @needs_container
    def test_files(self):
        self.sh("mkdir -p /tmp/log && printf 'a dropbear line\\nother\\nroot:$1$abc$def:1:0:::::\\n' > /tmp/log/auth.log")
        text = self.tool_ok("logs", source="file")
        self.assertIn("/tmp/log/auth.log", text)
        text = self.tool_ok("logs", source="file", file="auth.log", pattern="drop(bear|x)")
        self.assertIn("a dropbear line", text)
        self.assertNotIn("other", text)
        self.assertIn("(1 matching lines", text)
        text = self.tool_ok("logs", source="file", file="auth.log", lines=1)
        self.assertNotIn("$abc$def", text)  # log lines pass through redact
        text, err = self.tool("logs", source="file", file="../../etc/shadow")
        self.assertTrue(err)
        text, err = self.tool("logs", source="nope")
        self.assertTrue(err)
        text, err = self.tool("logs", lines=99999)
        self.assertTrue(err)


class TestKernelModules(OpenWrtTestCase):
    def test_runs(self):
        text = self.tool_ok("kernel_modules")
        for head in ("== Loaded modules", "== Kernel taint", "== Boot module lists"):
            self.assertIn(head, text)
        self.assertRegex(text, r"value \d+")

    @needs_container
    def test_no_modules_dir_and_not_in_rom(self):
        text = self.tool_ok("kernel_modules")
        rel = self.sh("uname -r").strip()
        if self.sh(f"[ -d /lib/modules/{rel} ] && echo y || echo n").strip() == "n":
            self.assertIn(f"no /lib/modules/{rel}", text)
        mod = self.sh("awk 'NR == 1 { print $1 }' /proc/modules 2>/dev/null").strip()
        if not mod:
            self.skipTest("no loaded modules visible in this container")
        fake_rom(self)
        self.sh(f"mkdir -p /lib/modules/{rel}/extra /fixture/rom/lib/modules/{rel} && "
                f"echo x > /lib/modules/{rel}/extra/{mod}.ko && echo m > /etc/modules.d/99-test-{mod}")
        text = self.tool_ok("kernel_modules", env={"MCP_ROM": "/fixture/rom"})
        self.assertRegex(text, rf"\n{mod}\s.*!! /lib/modules/{re.escape(rel)}/extra/{mod}.ko not in firmware image")
        self.assertRegex(text, rf"/etc/modules.d/99-test-{mod}\s+m\s+!! not in firmware image")
        self.sh(f"rm -rf /lib/modules/{rel} /etc/modules.d/99-test-{mod}")


class TestUci(OpenWrtTestCase):
    @needs_container
    def test_list_show_changes(self):
        write_file(self, "/etc/config/wireless", WIRELESS)
        text = self.tool_ok("uci")
        self.assertRegex(text, r"\nfirewall\s+\d+ sections")
        self.assertRegex(text, r"\nwireless\s+2 sections")
        text = self.tool_ok("uci", package="wireless")
        self.assertIn("wireless.default_radio0.ssid='HomeNet'", text)
        self.assertIn("wireless.default_radio0.key='<redacted>'", text)
        self.assertNotIn(WIFI_KEY, text)
        text = self.tool_ok("uci", package="wireless.default_radio0.ssid")
        self.assertIn("HomeNet", text)
        text = self.tool_ok("uci", changes=True)
        self.assertIn("none", text)
        self.sh("uci set dropbear.@dropbear[0].Port=2200")  # staged in /tmp/.uci, not committed
        text = self.tool_ok("uci", changes=True)
        self.assertRegex(text, r"dropbear\.\S+\.Port='2200'")
        self.assertEqual(self.sh("grep -c 2200 /etc/config/dropbear || true").strip(), "0")
        self.sh("uci revert dropbear")
        text, err = self.tool("uci", package="nope")
        self.assertTrue(err)
        text, err = self.tool("uci", package="a;reboot")
        self.assertTrue(err)

    @needs_container
    def test_without_uci_binary(self):
        write_file(self, "/etc/config/wireless", WIRELESS)
        text = self.tool_ok("uci", env={"PATH": "/usr/bin:/bin"}, package="wireless")
        self.assertIn("uci: not available", text)
        self.assertIn("option ssid 'HomeNet'", text)
        self.assertNotIn(WIFI_KEY, text)


class TestNoSecretsAnywhere(OpenWrtTestCase):
    @needs_container
    def test_every_tool(self):
        write_file(self, "/etc/config/wireless", WIRELESS)
        pid = self.sh(f"(env WIFI_PSK={WIFI_KEY} sleep 304 >/dev/null 2>&1 & echo $! >/tmp/spid); sleep 1; "
                      f"mkdir -p /tmp/log && echo 'option key {WIFI_KEY}' > /tmp/log/x.log; cat /tmp/spid").strip()
        names = [t["name"] for t in self.session().request("tools/list")["result"]["tools"]]
        mine = ["system_info", "processes", "services", "packages", "logs", "kernel_modules", "uci",
                "network", "connections", "firewall"]
        for name in mine:
            if name not in names:
                continue
            for args in ({}, {"package": "wireless"} if name == "uci" else {},
                         {"source": "file", "file": "x.log"} if name == "logs" else {}):
                text, _ = self.tool(name, **args)
                self.assertNotIn(WIFI_KEY, text, f"{name} {args}")
        text = self.tool_ok("processes", pid=int(pid))
        self.assertIn("WIFI_PSK=<redacted>", text)
        self.assertNotIn(WIFI_KEY, text)


class TestLibHelpers(OpenWrtTestCase):
    @needs_container
    def test_lib_procs_and_uci_dump(self):
        out = self.sh(r"""sed '/^mcp_main$/d' /tmp/openwrt-mcp-test.sh > /tmp/lib.sh
            . /tmp/lib.sh; lib_procs; echo END; lib_uci_dump firewall > /tmp/a
            have() { [ "$1" != uci ] && command -v "$1" >/dev/null 2>&1; }; lib_uci_dump firewall > /tmp/b
            cmp /tmp/a /tmp/b && echo SAME; grep -c . /tmp/a""")
        procs, rest = out.split("END\n", 1)
        rows = [l.split("\t") for l in procs.splitlines()]
        self.assertTrue(rows)
        for r in rows:
            self.assertEqual(len(r), 10, r)
            self.assertTrue(r[0].isdigit())
            self.assertIn(r[6], ("0", "1"))
        self.assertEqual([int(r[0]) for r in rows], sorted(int(r[0]) for r in rows))
        self.assertIn("SAME", rest)  # uci and the /etc/config parser agree
        self.assertGreater(int(rest.split()[-1]), 10)


if __name__ == "__main__":
    unittest.main()
