"""glinet_api (server/60-admin-glinet.sh, catalog in server/61-admin-glinet-catalog.sh).

The containers are plain OpenWrt: no GL.iNet firmware, no ubusd. The tests build the GL
side as fixtures: /etc/glversion, the RPC object files in /usr/lib/oui-httpd/rpc and a
fake `ubus` early in PATH (the seam test_system uses) that answers `list gl-session`
and `call gl-session call JSON` from files, logs every request and can run a hook that
changes the configuration the way the firmware would.
"""

import json
import os
import re
import subprocess
import tempfile
import unittest
from pathlib import Path

from mcp_client import ADMIN_ENV, ROOT, OpenWrtTestCase, needs_container
from test_system import FAKE_PATH, write_file

GL_ENV = {**ADMIN_ENV, "PATH": FAKE_PATH}
CATALOG = ROOT / "server" / "61-admin-glinet-catalog.sh"
GENERATOR = ROOT / "scripts" / "glinet-methods.sh"

# objects of the fake router: some of the catalog, one the catalog does not have
OBJECTS = ["system", "wifi", "firewall", "wg-server", "tailscale", "upgrade", "diag", "lan", "security-scan"]

WIFI_KEY = "CorrectHorseBattery9"
WG_PRIVATE = "yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk="
WG_PSK = "FpCyhws9cxwWoV4xELtfJvjJN+zQVRPISllRWgeopVE="
PEM = "-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASC\nBKcwggSjAgEAAoIBAQC7\n-----END PRIVATE KEY-----\n"

FAKE_UBUS = r"""#!/bin/sh
# test double for ubus on a GL.iNet router
G=/fixture/gl
[ "$1" = -t ] && shift 2
case $1 in
list)
	[ -f $G/session-on ] || exit 4
	[ "$2" = gl-session ] && echo gl-session
	exit 0 ;;
call) ;;
*) exit 1 ;;
esac
[ -f $G/session-on ] || { echo "Command failed: Not found" >&2; exit 4; }
[ "$2" = gl-session ] && [ "$3" = call ] || exit 4
printf '%s\n' "$4" >>$G/calls.log
m=$(jsonfilter -s "$4" -e @.module) f=$(jsonfilter -s "$4" -e @.func)
if [ -x "$G/hooks/$m.$f" ]; then "$G/hooks/$m.$f" "$4" || exit $?; fi
if [ -f "$G/answers/$m.$f.json" ]; then cat "$G/answers/$m.$f.json"; exit 0; fi
printf '{\n\t"error": {\n\t\t"code": -32601,\n\t\t"message": "Method not found"\n\t}\n}\n'
"""


def gl_fixture(tc) -> None:
    """Make the container look like a GL.iNet router for glinet_api. tc: anything with
    sh(script), a test case or its container."""
    tc.sh("mkdir -p /fixture/gl/answers /fixture/gl/hooks /usr/lib/oui-httpd/rpc && "
          "echo 4.8.5 > /etc/glversion && echo release1 > /etc/version.type && touch /fixture/gl/session-on && "
          ": > /fixture/gl/calls.log && cd /usr/lib/oui-httpd/rpc && touch " +
          " ".join(o + (".so" if o in ("upgrade", "wg-server") else "") for o in OBJECTS))
    write_file(tc, "/fixture/bin/ubus", FAKE_UBUS.rstrip("\n"), mode="755")
    # a config package of our own for the hooks to change (the rootfs images have no
    # /etc/config/system before first boot)
    write_file(tc, "/etc/config/gltest", "config t 'main'\n\toption zonename 'UTC'")


def answer(tc: OpenWrtTestCase, name: str, obj) -> None:
    """The reply of OBJECT.METHOD, printed the way ubus prints (tab-indented)."""
    write_file(tc, f"/fixture/gl/answers/{name}.json", json.dumps(obj, indent="\t"))


def hook(tc: OpenWrtTestCase, name: str, script: str) -> None:
    write_file(tc, f"/fixture/gl/hooks/{name}", "#!/bin/sh\n" + script, mode="755")


def api(tc: OpenWrtTestCase, args: dict, env: dict | None = None) -> tuple[str, bool]:
    """glinet_api with these arguments (also "timeout", which tc.tool keeps for itself)."""
    return tc.session(env or GL_ENV).call_tool("glinet_api", args)


def calls(tc: OpenWrtTestCase) -> list[dict]:
    return [json.loads(line) for line in tc.sh("cat /fixture/gl/calls.log").splitlines() if line.strip()]


def catalog() -> dict[str, tuple[str, str]]:
    """object.method -> (class, reason) from the generated catalog file."""
    res = {}
    for line in CATALOG.read_text().splitlines():
        f = line.split("\t")
        if f[0] == "M":
            res[f"{f[1]}.{f[2]}"] = (f[3], f[4])
    return res


class TestCatalog(unittest.TestCase):
    """The generated catalog and its generator; no container."""

    def test_records_are_well_formed(self):
        text = CATALOG.read_text()
        self.assertTrue(text.isascii())
        body = text.split("cat <<'GLINET_CATALOG_END'\n", 1)[1].split("\nGLINET_CATALOG_END\n", 1)[0]
        seen = set()
        for line in body.splitlines():
            f = line.split("\t")
            self.assertIn(f[0], ("O", "M", "P"), line)
            self.assertEqual(len(f), 4 if f[0] == "O" else 6, line)
            if f[0] == "M":
                self.assertRegex(f[1], r"^[a-z0-9_-]+$")
                self.assertRegex(f[2], r"^[a-z0-9_]+$")
                self.assertIn(f[3], ("q", "a", "r"))
                self.assertTrue(f[5], line)
                if f[3] == "r":
                    self.assertTrue(f[4], f"risky without a reason: {line}")
                self.assertNotIn((f[1], f[2]), seen)
                seen.add((f[1], f[2]))
        self.assertGreater(len(seen), 300)

    def test_what_must_be_risky_is(self):
        cat = catalog()
        for name in ("system.reboot", "system.reset_firmware", "system.set_password", "ui.init",
                     "upgrade.upgrade_online", "upgrade.upgrade_local", "upgrade.upgrade_cellular_online",
                     "local-access.set_config", "netmode.set_mode", "lan.set_config",
                     "cloud.bind_device", "cloud.rebind", "cloud.unbind", "cloud.set_config", "rtty.run",
                     "rtty.set_config", "firewall.set_wan_access", "firewall.set_dmz", "firewall.add_port_forward",
                     "firewall.remove_rule", "vpn-client.set_options", "vpn-client.set_default_tunnel",
                     "wifi.set_config", "tailscale.set_config", "tailscale.logout", "plugins.install_package",
                     "plugins.remove_package", "modem.send_at_command", "modem.send_sms", "wg-server.remove_peer",
                     "ovpn-client.remove_config", "acl.add_user", "nas-web.disk_format"):
            self.assertEqual(cat[name][0], "r", name)

    def test_queries_with_side_effects_are_not_queries(self):
        cat = catalog()
        for name in ("tailscale.get_auth_url", "ddns.get_status", "upgrade.check_firmware_online",
                     "upgrade.check_cellular_online", "diag.ping", "diag.traceroute", "repeater.scan",
                     "ui.get_remote_langs", "plugins.update_repository"):
            self.assertEqual(cat[name][0], "a", name)
        for name in ("system.get_info", "wifi.get_config", "firewall.get_rule_list", "ui.check_initialized",
                     "ui.load_locales", "network.check_wan_cable"):
            self.assertEqual(cat[name][0], "q", name)
        # every query is named like one; nothing named remove/clear/reset/set is a query
        for name, (cls, _) in cat.items():
            if cls == "q":
                self.assertRegex(name.split(".")[1], r"^(get|check|load)_", name)

    def run_generator(self, yaml: dict[str, str], stubs: bool = False) -> subprocess.CompletedProcess:
        """Run the generator on a documentation tree made of yaml {"category/object.yaml":
        text}. stubs: add a stub for every method the rules table names and yaml does
        not define, so the "rule matches nothing" check passes."""
        with tempfile.TemporaryDirectory() as d:
            have = set()
            for rel, text in yaml.items():
                p = Path(d) / "src/data/api" / rel
                p.parent.mkdir(parents=True, exist_ok=True)
                p.write_text(text)
                have.add(Path(rel).stem)
            if stubs:
                byobj: dict[str, list[str]] = {}
                for m in re.finditer(r"(?m)^[aqr] ([a-z0-9_-]+)\.([a-z0-9_]+) ", GENERATOR.read_text()):
                    byobj.setdefault(m.group(1), []).append(m.group(2))
                for obj, meths in byobj.items():
                    if obj in have:
                        continue
                    p = Path(d) / "src/data/api/stub" / f"{obj}.yaml"
                    p.parent.mkdir(parents=True, exist_ok=True)
                    p.write_text(f"object: {obj}\ncategory: stub\nsummary: Stub.\nmethods:\n" +
                                 "".join(f"  - name: {m}\n    summary: Stub.\n" for m in meths))
            return subprocess.run(["sh", str(GENERATOR), d, "-"], capture_output=True, text=True)

    def test_generator_fails_when_a_rule_matches_nothing(self):
        # a documentation without the methods the rules table names must not pass silently
        r = self.run_generator({"system/system.yaml": "object: system\ncategory: system\nsummary: S.\nmethods:\n"
                                                      "  - name: get_x\n    summary: Returns x.\n"})
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("which the documentation does not have", r.stderr)
        self.assertEqual(r.stdout, "")

    def test_generator_reproduces_the_catalog(self):
        """The committed catalog is exactly what the generator prints from the
        documentation repository (GLINET_API_DOCS, or ../glinet-api; skipped without)."""
        cands = [Path(p) for p in (os.environ.get("GLINET_API_DOCS"), ROOT.parent / "glinet-api") if p]
        src = next((c for c in cands if (c / "src/data/api").is_dir()), None)
        if src is None:
            self.skipTest("glinet-api documentation repository not found (set GLINET_API_DOCS)")
        r = subprocess.run(["sh", str(GENERATOR), str(src), "-"], capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stderr)

        def strip(s: str) -> str:
            return re.sub(r"\(commit [0-9a-z]+\)", "(commit X)", s)
        if strip(r.stdout) != strip(CATALOG.read_text()):
            self.fail("server/61-admin-glinet-catalog.sh differs from the generator's output: run "
                      "scripts/glinet-methods.sh again (or the documentation moved on)")

    def test_generator_parses_the_yaml_forms(self):
        # quoted scalars, block scalars, enums, conditions, non-ASCII, keys to skip
        text = '''object: tailscale
category: remote-access
summary: "Tailscale: mesh VPN."
description: |
  Not used.
methods:
  - name: get_auth_url
    summary: Restarts Tailscale and returns a login URL.
    description: |
      Long text
      over lines.
    notes:
      - Only useful in status `NeedsLogin`.
  - name: set_config
    summary: 'Changes the config — and restarts.'
    params:
      - name: enabled
        type: boolean
        required: true
        description: On or off.
      - name: "nodes[].ip"
        type: string/number
        required: "if enabled is true"
        description: |
          First line
          second line.
        enum: [a, "b c", 3]
    examples:
      - title: One
        params: { enabled: true }
    see_also: [tailscale.get_auth_url]
  - name: logout
    summary: Logs out.
    destructive: true
  - name: get_status
    summary: Returns the status.
  - name: remove_node
    summary: Removes a node.
  - name: do_thing
    summary: Does a thing.
'''
        r = self.run_generator({"remote-access/tailscale.yaml": text}, stubs=True)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertTrue(r.stdout.startswith("# admin module data"))
        self.assertTrue(r.stdout.endswith("GLINET_CATALOG_END\n}\n"))
        lines = [line.split("\t") for line in r.stdout.splitlines() if "\ttailscale\t" in line or line.startswith("P\t")]
        self.assertEqual(lines, [
            ["O", "tailscale", "remote-access", "Tailscale: mesh VPN."],
            ["M", "tailscale", "get_auth_url", "a", "restarts Tailscale", "Restarts Tailscale and returns a login URL."],
            ["M", "tailscale", "set_config", "r", "turns Tailscale on or off and decides what the tailnet may reach "
             "(LAN, WAN, exit node); restarts it", "Changes the config - and restarts."],
            ["P", "enabled", "boolean", "y", "", "On or off."],
            ["P", "nodes[].ip", "string/number", "if enabled is true", 'a|"b c"|3', "First line second line."],
            ["M", "tailscale", "logout", "r", "logs the router out of Tailscale: remote access through the tailnet ends",
             "Logs out."],
            ["M", "tailscale", "get_status", "q", "", "Returns the status."],
            ["M", "tailscale", "remove_node", "r", "deletes what it names", "Removes a node."],
            ["M", "tailscale", "do_thing", "a", "", "Does a thing."],
        ])
        # a destructive method without a rule is risky because the documentation says so
        r = self.run_generator({"system/system.yaml": "object: system\ncategory: system\nsummary: S.\nmethods:\n"
                                "  - name: reboot\n    summary: Reboots.\n    destructive: true\n"}, stubs=True)
        self.assertIn("M\tsystem\treboot\tr\tdocumented as destructive\tReboots.\n", r.stdout)

    def test_generator_is_deterministic_and_posix(self):
        a = self.run_generator({}, stubs=True)
        b = self.run_generator({}, stubs=True)
        self.assertEqual(a.returncode, 0, a.stderr)
        self.assertEqual(a.stdout, b.stdout)


class TestNotGlinet(OpenWrtTestCase):
    def test_not_registered_without_admin(self):
        names = [t["name"] for t in self.session().request("tools/list")["result"]["tools"]]
        self.assertNotIn("glinet_api", names)

    @needs_container
    def test_definition(self):
        tools = {t["name"]: t for t in self.session(ADMIN_ENV).request("tools/list")["result"]["tools"]}
        t = tools["glinet_api"]
        self.assertEqual(set(t["inputSchema"]["properties"]), {"object", "method", "params", "confirm", "search", "timeout"})
        self.assertIs(t["inputSchema"]["additionalProperties"], False)
        a = t["annotations"]
        self.assertEqual((a["readOnlyHint"], a["destructiveHint"], a["idempotentHint"]), (False, True, False))
        self.assertIn("confirm", t["description"])

    @needs_container
    def test_plain_openwrt_is_an_error(self):
        for args in ({}, {"object": "system"}, {"object": "system", "method": "get_info"},
                     {"object": "system", "method": "reboot", "confirm": True}):
            with self.subTest(args=args):
                text, err = self.tool("glinet_api", env=ADMIN_ENV, **args)
                self.assertTrue(err, text)
                self.assertIn("does not run GL.iNet firmware", text)
                self.assertIn("uci_change", text)


class TestListing(OpenWrtTestCase):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        if cls.container:
            gl_fixture(cls.container)

    @needs_container
    def test_overview(self):
        text = self.tool_ok("glinet_api", env=GL_ENV)
        self.assertIn("GL.iNet firmware 4.8.5 (release1)", text)
        self.assertIn("gl-session: available", text)
        self.assertIn(f"== API objects on this router ({len(OBJECTS)})", text)
        self.assertRegex(text, r"(?m)^wifi  \(\d+ query, \d+ active, \d+ confirm\)  \S")
        self.assertRegex(text, r"(?m)^wg-server  \(")          # wg-server.so
        self.assertRegex(text, r"(?m)^security-scan  \(not in the catalog: methods unknown\)$")
        absent = text.split("== In the catalog, not on this router (")[1]
        self.assertIn("modem", absent)
        self.assertNotIn("wifi", absent.split("\n")[1].split(", "))
        self.assertNotRegex(text, r"(?m)^modem  \(")
        self.assertEqual(calls(self), [], "a listing must not call the API")

    @needs_container
    def test_object_lists_methods_with_parameters(self):
        text = self.tool_ok("glinet_api", env=GL_ENV, object="wifi")
        self.assertIn("== wifi (wireless: ", text)
        self.assertIn(", on this router", text)
        self.assertRegex(text, r"(?m)^wifi\.get_config  \[query\]  Returns")
        self.assertRegex(text, r"(?m)^wifi\.set_config  \[CONFIRM\]  Sets SSID")
        self.assertRegex(text, r"(?m)^    confirm needed: changes or turns off a Wi-Fi network")
        self.assertRegex(text, r"(?m)^    iface_name \(string, required\): ")
        self.assertRegex(text, r"(?m)^    encryption \(string, optional; one of none\|psk2\|")
        self.assertRegex(text, r'(?m)^    key \(string, required if encryption is not "none"\): ')
        text = self.tool_ok("glinet_api", env=GL_ENV, object="tailscale")
        self.assertRegex(text, r"(?m)^tailscale\.get_auth_url  \[active\]  Restarts Tailscale")
        self.assertRegex(text, r"(?m)^    note: restarts Tailscale$")

    @needs_container
    def test_object_not_on_this_router_and_unknown_ones(self):
        text = self.tool_ok("glinet_api", env=GL_ENV, object="modem")
        self.assertIn(", NOT on this router", text)
        self.assertIn("modem.get_sms_list", text)
        text = self.tool_ok("glinet_api", env=GL_ENV, object="security-scan")
        self.assertIn("on this router but not in the catalog", text)
        self.assertIn("/usr/share/gl-validator.d/security-scan.lua", text)
        text, err = self.tool("glinet_api", env=GL_ENV, object="nosuch")
        self.assertTrue(err)
        self.assertIn("no API object 'nosuch'", text)

    @needs_container
    def test_search(self):
        text = self.tool_ok("glinet_api", env=GL_ENV, search="Port Forward")
        self.assertIn('== Methods matching "Port Forward"', text)
        self.assertRegex(text, r"(?m)^firewall\.add_port_forward  \[CONFIRM\]  ")
        self.assertRegex(text, r"(?m)^firewall\.get_port_forward_list  \[query\]  ")
        self.assertNotIn("\n    ", text.split("== Methods")[1], "no parameters without object")
        # a parameter name finds its method; objects the router lacks are marked
        text = self.tool_ok("glinet_api", env=GL_ENV, search="phone_numbers")
        self.assertRegex(text, r"(?m)^sms-forward\.set_phone_number  \[CONFIRM\]  .*\(not on this router\)$")
        text = self.tool_ok("glinet_api", env=GL_ENV, object="wifi", search="txpower")
        self.assertIn("wifi.set_txpower  [active]", text)
        self.assertNotIn("wifi.get_status", text)
        text = self.tool_ok("glinet_api", env=GL_ENV, search="zzz-nothing")
        self.assertIn('no method matches "zzz-nothing"', text)

    @needs_container
    def test_listing_without_gl_session_or_rpc_directory(self):
        self.sh("rm /fixture/gl/session-on")
        try:
            text = self.tool_ok("glinet_api", env=GL_ENV)
            self.assertIn("gl-session: NOT available", text)
            self.assertIn("ubus has no object gl-session", text)
            text, err = self.tool("glinet_api", env=GL_ENV, object="system", method="get_info")
            self.assertTrue(err)
            self.assertIn("system.get_info: not called", text)
            self.assertIn("web API cannot be reached", text)
            # no ubus at all
            self.sh("mv /fixture/bin/ubus /fixture/bin/ubus.off && mv /bin/ubus /bin/ubus.off")
            try:
                text, err = self.tool("glinet_api", env=GL_ENV, object="system", method="get_info")
            finally:
                self.sh("mv /fixture/bin/ubus.off /fixture/bin/ubus && mv /bin/ubus.off /bin/ubus")
            self.assertTrue(err)
            self.assertIn("ubus: not available", text)
        finally:
            self.sh("touch /fixture/gl/session-on")
        self.sh("mv /usr/lib/oui-httpd/rpc /usr/lib/oui-httpd/rpc.off")
        try:
            text = self.tool_ok("glinet_api", env=GL_ENV)
            self.assertIn("cannot list /usr/lib/oui-httpd/rpc", text)
            self.assertRegex(text, r"== API objects in the catalog \(\d+\)")
            self.assertRegex(text, r"(?m)^modem  \(")
        finally:
            self.sh("mv /usr/lib/oui-httpd/rpc.off /usr/lib/oui-httpd/rpc")

    @needs_container
    def test_bad_arguments(self):
        for args, msg in (({"object": "wi fi"}, "object must be"), ({"object": "wifi", "method": "get;x"}, "method must be"),
                          ({"method": "get_info"}, "method needs object"),
                          ({"object": "wifi", "method": "get_config", "search": "x"}, "search is for listings"),
                          ({"object": "wifi", "method": "get_config", "timeout": 0}, "between 1 and 600"),
                          ({"object": "wifi", "method": "get_config", "params": "x"}, "must be an object"),
                          ({"object": "wifi", "bogus": 1}, "unknown argument")):
            with self.subTest(args=args):
                text, err = api(self, args)
                self.assertTrue(err, text)
                self.assertIn(msg, text)
        self.assertEqual(calls(self), [])


class TestCalls(OpenWrtTestCase):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        if cls.container:
            gl_fixture(cls.container)

    def setUp(self):
        if self.container:
            self.sh(": > /fixture/gl/calls.log")

    @needs_container
    def test_query(self):
        answer(self, "system.get_info", {"result": {"model": "e5800", "firmware_version": "4.8.5", "sn": "abc123"}})
        text = self.tool_ok("glinet_api", env=GL_ENV, object="system", method="get_info")
        self.assertEqual(text.splitlines()[0], "system.get_info: ok")
        self.assertIn("== Answer", text)
        self.assertIn('"model": "e5800"', text)
        self.assertNotIn("Config changes", text, "a query has no config report")
        self.assertEqual(calls(self), [{"module": "system", "func": "get_info", "params": {}}])

    @needs_container
    def test_params_reach_the_api_unchanged(self):
        params = {"zonename": "Europe/Zurich", "timezone": "CET-1CEST,M3.5.0,M10.5.0/3", "localtime": 1752739200,
                  "auto_timezone": False, "nested": {"list": [1, "two", None, {"k": "v \"quoted\" \\ back"}]},
                  "text": "sp ace, 'single' $HOME `id` ; | & <>\tTab äö€"}
        answer(self, "system.set_timezone_config", {"result": {}})
        text = self.tool_ok("glinet_api", env=GL_ENV, object="system", method="set_timezone_config", params=params)
        self.assertEqual(text.splitlines()[0], "system.set_timezone_config: ok")
        self.assertEqual(calls(self), [{"module": "system", "func": "set_timezone_config", "params": params}])

    @needs_container
    def test_active_call_reports_config_changes(self):
        hook(self, "system.set_timezone_config", "uci set gltest.main.zonename='Europe/Zurich' && uci commit gltest")
        answer(self, "system.set_timezone_config", {"result": {}})
        try:
            text = self.tool_ok("glinet_api", env=GL_ENV, object="system", method="set_timezone_config",
                                params={"zonename": "Europe/Zurich", "timezone": "CET-1CEST"})
            self.assertEqual(text.splitlines()[0], "system.set_timezone_config: ok")
            self.assertIn("== Config changes", text)
            self.assertIn("config gltest: 1 removed, 1 added", text)
            self.assertIn("- gltest.main.zonename='UTC'", text)
            self.assertIn("+ gltest.main.zonename='Europe/Zurich'", text)
            self.assertLess(text.index("== Config changes"), text.index("== Answer"))
        finally:
            self.sh("rm /fixture/gl/hooks/system.set_timezone_config; uci set gltest.main.zonename=UTC; uci commit gltest")
        text = self.tool_ok("glinet_api", env=GL_ENV, object="system", method="set_timezone_config",
                            params={"zonename": "UTC", "timezone": "UTC"})
        self.assertIn("no change in /etc/config", text)

    @needs_container
    def test_risky_needs_confirm(self):
        answer(self, "system.reboot", {"result": {}})
        for args in ({}, {"confirm": False}, {"params": {"delay": 1}}):
            with self.subTest(args=args):
                text, err = self.tool("glinet_api", env=GL_ENV, object="system", method="reboot", **args)
                self.assertTrue(err, text)
                self.assertEqual(text.splitlines()[0], "system.reboot: NOT CALLED, it needs confirmation. Nothing was changed.")
                self.assertIn("What it does: Reboots the device", text)
                self.assertIn("Why confirmation: documented as destructive.", text)
                self.assertIn('send the same call again with "confirm": true', text)
                self.assertIn("    delay (number, optional)", text)
        self.assertEqual(calls(self), [], "nothing may reach the API without confirm")
        text = self.tool_ok("glinet_api", env=GL_ENV, object="system", method="reboot", params={"delay": 1}, confirm=True)
        self.assertEqual(text.splitlines()[0], "system.reboot: ok")
        self.assertIn("== Config changes", text)
        self.assertEqual(calls(self), [{"module": "system", "func": "reboot", "params": {"delay": 1}}])

    @needs_container
    def test_every_risky_method_of_the_fake_router_is_gated(self):
        """One listing, then the gate for a few of each kind (not all: a call takes a
        second under emulation)."""
        for name in ("system.reset_firmware", "system.set_password", "upgrade.upgrade_online", "wifi.set_config",
                     "firewall.set_wan_access", "firewall.remove_port_forward", "tailscale.logout", "lan.set_config",
                     "wg-server.remove_peer"):
            obj, meth = name.split(".")
            text, err = self.tool("glinet_api", env=GL_ENV, object=obj, method=meth, params={"x": 1})
            self.assertTrue(err, name)
            self.assertIn(f"{name}: NOT CALLED, it needs confirmation", text)
        self.assertEqual(calls(self), [])

    @needs_container
    def test_unknown_methods(self):
        answer(self, "security-scan.get_status", {"result": {"scanning": False}})
        answer(self, "security-scan.start_scan", {"result": {}})
        answer(self, "wifi.get_brand_new", {"result": {"x": 1}})
        # named like a query: runs, as an active call (config report), with a note
        for obj, meth in (("security-scan", "get_status"), ("wifi", "get_brand_new")):
            text = self.tool_ok("glinet_api", env=GL_ENV, object=obj, method=meth)
            self.assertIn(f"note: {obj}.{meth} is not in the method catalog", text)
            self.assertIn(f"{obj}.{meth}: ok", text)
            self.assertIn("== Config changes", text)
        n = len(calls(self))
        # anything else: confirm; "target" holds "get", "forget_" starts differently
        for obj, meth in (("security-scan", "start_scan"), ("wifi", "reset_target"), ("wifi", "forget_network"),
                          ("wifi", "getconfig")):
            text, err = self.tool("glinet_api", env=GL_ENV, object=obj, method=meth)
            self.assertTrue(err, meth)
            self.assertIn("NOT CALLED, it needs confirmation", text)
            self.assertIn("Why confirmation: not in the method catalog", text)
        self.assertEqual(len(calls(self)), n)
        text = self.tool_ok("glinet_api", env=GL_ENV, object="security-scan", method="start_scan", confirm=True)
        self.assertIn("security-scan.start_scan: ok", text)
        # an object the router does not have is not called at all
        text, err = self.tool("glinet_api", env=GL_ENV, object="modem", method="get_sms_list")
        self.assertTrue(err)
        self.assertIn("This router has no API object 'modem'", text)
        self.assertEqual(len(calls(self)), n + 1)

    @needs_container
    def test_changing_method_without_params_is_not_sent(self):
        text, err = self.tool("glinet_api", env=GL_ENV, object="wifi", method="set_txpower")
        self.assertTrue(err)
        self.assertIn("wifi.set_txpower: NOT CALLED, params is empty but the method has required parameters", text)
        self.assertRegex(text, r"(?m)^    \w+ \(\w+, required\)")
        text, err = self.tool("glinet_api", env=GL_ENV, object="wifi", method="set_txpower", params={})
        self.assertTrue(err)
        self.assertEqual(calls(self), [])
        # a changing method without required parameters does run with none
        answer(self, "tailscale.get_auth_url", {"result": {"auth_url": "https://login.tailscale.com/a/abc"}})
        text = self.tool_ok("glinet_api", env=GL_ENV, object="tailscale", method="get_auth_url")
        self.assertIn("https://login.tailscale.com/a/abc", text)
        self.assertIn("== Config changes", text, "get_auth_url restarts Tailscale: not a query")

    @needs_container
    def test_validator_rejection(self):
        answer(self, "system.set_timezone_config", {"error": {"code": -32602, "message": "Invalid params"}})
        text, err = self.tool("glinet_api", env=GL_ENV, object="system", method="set_timezone_config",
                              params={"zonename": 5})
        self.assertTrue(err)
        self.assertEqual(text.splitlines()[0], "system.set_timezone_config: GL API ERROR -32602: Invalid params")
        self.assertIn("Nothing was changed.", text)
        self.assertRegex(text, r"(?m)^    zonename \(string, required\): ")
        self.assertIn("no change in /etc/config", text)

    @needs_container
    def test_other_errors(self):
        # the fake answers "Method not found" for what it has no file for
        text, err = self.tool("glinet_api", env=GL_ENV, object="wifi", method="get_status")
        self.assertTrue(err)
        self.assertIn("wifi.get_status: GL API ERROR -32601: Method not found", text)
        self.assertIn("This firmware has no method wifi.get_status", text)
        answer(self, "wifi.set_txpower", {"error": {"code": -1, "message": "radio busy"}})
        text, err = self.tool("glinet_api", env=GL_ENV, object="wifi", method="set_txpower", params={"x": 1})
        self.assertTrue(err)
        self.assertIn("wifi.set_txpower: GL API ERROR -1: radio busy", text)
        self.assertIn("may have applied part of the change", text)
        self.assertIn("== Config changes", text)
        answer(self, "wifi.get_config", {"error": "broken"})
        text, err = self.tool("glinet_api", env=GL_ENV, object="wifi", method="get_config")
        self.assertTrue(err)
        self.assertIn("wifi.get_config: GL API ERROR: broken", text)
        # an error inside the result (tailscale in a non-router mode)
        answer(self, "tailscale.get_status", {"result": {"err_code": 0, "err_msg": "tailscale can only be used in router mode"}})
        text = self.tool_ok("glinet_api", env=GL_ENV, object="tailscale", method="get_status")
        self.assertIn("but the answer carries err_msg: tailscale can only be used in router mode", text)
        # ubus itself fails
        hook(self, "system.get_load", "echo 'Command failed: Connection failed' >&2; exit 10")
        try:
            text, err = self.tool("glinet_api", env=GL_ENV, object="system", method="get_load")
            self.assertTrue(err)
            self.assertIn("system.get_load: the ubus call failed (exit 10)", text)
            self.assertIn("Connection failed", text)
        finally:
            self.sh("rm /fixture/gl/hooks/system.get_load")

    @needs_container
    def test_timeout(self):
        hook(self, "diag.ping", "uci set gltest.main.hostname=slow && uci commit gltest; sleep 60")
        try:
            text, err = api(self, {"object": "diag", "method": "ping", "params": {"addr": "192.0.2.1"}, "timeout": 2})
            self.assertTrue(err)
            self.assertIn("diag.ping: NO ANSWER after 2 s (timeout)", text)
            self.assertIn("may still be working", text)
            # what it changed before the timeout is still reported
            self.assertIn("+ gltest.main.hostname='slow'", text)
            self.assertNotIn("sleep 60", self.sh("ps w"), "the call's processes are gone after the timeout")
        finally:
            self.sh("rm /fixture/gl/hooks/diag.ping; uci delete gltest.main.hostname; uci commit gltest")

    @needs_container
    def test_secrets_in_answers_are_masked(self):
        conf = f"[Interface]\nAddress = 10.0.0.2/24\nPrivateKey = {WG_PRIVATE}\n[Peer]\nPublicKey = pubpubpub=\nPresharedKey = {WG_PSK}\nEndpoint = a.example:51820\n"
        answer(self, "wifi.get_config", {"result": {"res": [{"name": "wifi2g", "ifaces": [
            {"name": "wifi2g", "ssid": "HomeNet", "key": WIFI_KEY, "encryption": "psk2", "hidden": False},
            {"name": "guest2g", "ssid": "Guest", "key": "", "wifi_password_enabled": True}]}],
            "passcode": 482913, "sid": "SESSIONID42", "mp_token": "TOKENTOKEN", "token_status": 2,
            "credentials": {"username": "bob", "password": "pw-in-object", "list": ["pw-in-array"]},
            "pins": ["keep-me"], "public_key": "PUBLICKEYISFINE=", "private_key": WG_PRIVATE,
            "presharedkey": WG_PSK, "presharedkey_enable": True, "puk_code": "12345678", "pin_counter": 3,
            "config": conf, "cert": PEM + "trailer", "open_pem": "-----BEGIN RSA PRIVATE KEY-----\nMIIabcdefSECRETBODY",
            # JSON text inside a string, as a backend may pass it through
            "raw": json.dumps({"ssid": "Inner", "password": 'in"ner-pw', "pin": 9731, "public_key": "INNERPUB=",
                               "wg": {"private_key": "INNERPRIV="}}),
            "last": "end"}})
        text = self.tool_ok("glinet_api", env=GL_ENV, object="wifi", method="get_config")
        for secret in ("ner-pw", "9731", "INNERPRIV="):
            self.assertNotIn(secret, text)
        for kept in (r'\"ssid\": \"Inner\"', r'\"public_key\": \"INNERPUB=\"', r'\"password\":\"<redacted>\"'):
            self.assertIn(kept, text)
        for secret in (WIFI_KEY, "482913", "SESSIONID42", "TOKENTOKEN", "pw-in-object", "pw-in-array", WG_PRIVATE, WG_PSK,
                       "12345678", "MIIEvQIBADANBg", "BKcwggSjAgEA", "MIIabcdefSECRETBODY", WG_PRIVATE[:12], WG_PSK[:12]):
            self.assertNotIn(secret, text)
        for kept in ('"ssid": "HomeNet"', '"wifi_password_enabled": true', '"token_status": 2',
                     '"public_key": "PUBLICKEYISFINE="', '"presharedkey_enable": true', '"pin_counter": 3', "keep-me",
                     "Address = 10.0.0.2/24", "PublicKey = pubpubpub=", "Endpoint = a.example:51820",
                     "PrivateKey = <redacted>", "PresharedKey = <redacted>", '"credentials": "<redacted>",',
                     '"cert": "<redacted private key>\\ntrailer",', '"open_pem": "<redacted private key>",',
                     '"last": "end"', '"key": "<redacted>",'):
            self.assertIn(kept, text)
        # the masked answer is still what ubus printed otherwise: valid JSON
        json.loads(text.split("== Answer\n", 1)[1])
        # and with redaction off the answer is shown as it is
        text = self.tool_ok("glinet_api", env={**GL_ENV, "MCP_REDACT": "0"}, object="wifi", method="get_config")
        self.assertIn(WIFI_KEY, text)
        self.assertIn(WG_PRIVATE, text)

    @needs_container
    def test_secrets_in_config_changes_are_masked(self):
        self.sh("printf \"config wifi-iface 'w'\\n\\toption ssid 'Old'\\n\\toption key 'oldoldold1'\\n\" > /etc/config/wireless")
        hook(self, "wifi.set_config", f"uci set wireless.w.key='{WIFI_KEY}' && uci set wireless.w.ssid=New && uci commit wireless")
        answer(self, "wifi.set_config", {"result": {}})
        try:
            text = self.tool_ok("glinet_api", env=GL_ENV, object="wifi", method="set_config", confirm=True,
                                params={"iface_name": "wifi2g", "ssid": "New", "key": WIFI_KEY})
            self.assertIn("+ wireless.w.ssid='New'", text)
            self.assertIn("+ wireless.w.key='<redacted>'", text)
            self.assertNotIn(WIFI_KEY, text)
            self.assertNotIn("oldoldold1", text)
        finally:
            self.sh("rm -f /fixture/gl/hooks/wifi.set_config /etc/config/wireless")

    @needs_container
    def test_image_ubus_is_preferred(self):
        """With a firmware image that has bin/ubus, that one is called, not PATH's."""
        self.sh("mkdir -p /fixture/rom/bin && cp /fixture/bin/ubus /fixture/rom/bin/ubus && "
                "sed -i 's#calls.log#calls-rom.log#' /fixture/rom/bin/ubus && : > /fixture/gl/calls-rom.log")
        answer(self, "system.get_load", {"result": {"load_average": [0, 0, 0]}})
        try:
            self.tool_ok("glinet_api", env={**GL_ENV, "MCP_ROM": "/fixture/rom"}, object="system", method="get_load")
            self.assertEqual(calls(self), [])
            self.assertIn('"func":"get_load"', self.sh("cat /fixture/gl/calls-rom.log").replace(" ", ""))
        finally:
            self.sh("rm -rf /fixture/rom")

    @needs_container
    def test_large_answer_keeps_status_and_changes_first(self):
        answer(self, "system.set_timezone_config", {"result": {"blob": ["x" * 100] * 900}})
        text = self.tool_ok("glinet_api", env=GL_ENV, object="system", method="set_timezone_config",
                            params={"zonename": "UTC", "timezone": "UTC"})
        self.assertEqual(text.splitlines()[0], "system.set_timezone_config: ok")
        self.assertIn("no change in /etc/config", text)
        self.assertIn("[output cut at", text)


if __name__ == "__main__":
    unittest.main()
