"""glinet: the GL.iNet firmware state, read from uci, files and /proc only.

Fixture: a stock-looking GL.iNet 4.x configuration is written into the container
(GL_STOCK), then the container's system tree is copied to the firmware image at
/fixture/rom (MAKE_ROM), so live and image agree until a test changes the live side.
/proc/gl-hw-info and the crond process come from a fixture proc root (MCP_PROC).
"""

import re
import unittest

from mcp_client import OpenWrtTestCase, needs_container
from test_forensics import MAKE_ROM, ROM_DIR

PROC_DIR = "/fixture/proc"
GL = {"MCP_ROM": ROM_DIR, "MCP_PROC": PROC_DIR}

# what a stock GL.iNet 4.x router keeps; the lines of /tmp/gl_crontabs/root are the ones
# a GL-BE14000 (firmware 4.11.0) generates at boot
GL_STOCK = r"""
set -e
mkdir -p /lib/functions /etc/nginx/conf.d
printf '#!/bin/sh\nlogger -t tz auto\n' > /usr/bin/auto_timezone && chmod 755 /usr/bin/auto_timezone
printf '#!/bin/sh\nget_arp_scan_ret() {\n\t:\n}\n' > /lib/functions/mptun.sh
printf '#!/bin/sh /etc/rc.common\nSTART=50\nstart() { mkdir -p /tmp/gl_crontabs; cat /etc/crontabs/root > /tmp/gl_crontabs/root; }\n' > /etc/init.d/gl_cron
chmod 755 /etc/init.d/gl_cron
echo 4.11.0 > /etc/glversion
echo beta5 > /etc/version.type
printf 'server {\n\tlisten 80;\n\tlisten [::]:80;\n\tlisten 443 ssl;\n}\n' > /etc/nginx/conf.d/gl.conf
cat > /etc/config/oui-httpd <<'EOF'
config oui-httpd 'main'
	option console_disabled '1'
	option inited '1'
	option session_timeout '300'

config no-auth-methods
	option object 'ui'
	list method 'get_lang'
	list method 'check_initialized'

config no-auth-methods
	option object 'system'
	list method 'get_timezone_list'
EOF
cat > /etc/config/gl-cloud <<'EOF'
config cloud
	option enable '0'
	option server 'gslb-eu.goodcloud.xyz'
	option token 'cloudtoken42'
EOF
cat > /etc/config/rtty <<'EOF'
config rtty 'general'
	option ssh_en '0'
	option web_en '0'
EOF
cat > /etc/config/glconfig <<'EOF'
config service 'general'
	option mode 'router'
EOF
cat > /etc/config/upgrade <<'EOF'
config upgrade 'general'
	option prompt '1'
	option keep_config '1'
EOF
cat > /etc/config/wireguard_server <<'EOF'
config servers 'main_server'
	option port '51820'
	option address_v4 '10.0.0.1/24'
	option private_key 'wgsecret77'

config peers 'peer_1001'
	option name 'alice'
	option public_key 'cHVibGlj'
	option private_key 'peersecret88'
EOF
cat > /etc/config/samba4 <<'EOF'
config sambashare
	option name 'usb'
	option path '/mnt/sda1'
	option guest_ok 'yes'
	option read_only 'no'
EOF
cat >> /etc/config/firewall <<'EOF'

config rule 'ssh_wan'
	option name 'ssh_wan'
	option src 'wan'
	option proto 'tcp'
	option dest_port '22'
	option target 'ACCEPT'
	option enabled '0'

config rule 'sambasharewan'
	option name 'sambasharewan'
	option src 'wan'
	option proto 'tcp'
	option dest_port '445'
	option target 'DROP'

config redirect 'dmz'
	option name 'GL-DMZ'
	option src 'wan'
	option dest_ip '192.168.8.100'
	option target 'DNAT'
	option enabled '0'
EOF
"""

# the running state: crond reading /tmp/gl_crontabs, /proc/gl-hw-info
GL_LIVE = rf"""
set -e
P={PROC_DIR}
mkdir -p $P/4000 $P/gl-hw-info /tmp/gl_crontabs/crontabs.d
echo crond > $P/4000/comm
printf '/usr/sbin/crond|-f|-c|/tmp/gl_crontabs|-l|7|' | tr '|' '\000' > $P/4000/cmdline
: > $P/4000/environ
echo GL-BE14000 > $P/gl-hw-info/model
echo US > $P/gl-hw-info/country_code
echo abc1234.glddns.com > $P/gl-hw-info/device_ddns
printf 'devicekey99\n' > $P/gl-hw-info/device_key
printf 'certificate77\n' > $P/gl-hw-info/device_cert
printf 'serial55\n' > $P/gl-hw-info/device_sn
cat > /tmp/gl_crontabs/root <<'EOF'
* * * * * /usr/bin/auto_timezone
* * * * * sleep 10; /usr/bin/auto_timezone
*/1 * * * * . /lib/functions/mptun.sh; get_arp_scan_ret
EOF
"""

GL_SETUP = GL_STOCK + MAKE_ROM + GL_LIVE

# back to stock: the GL configs of the image, no extra processes, no fake sqlite3
GL_RESET = rf"""
for f in oui-httpd gl-cloud rtty wireguard_server samba4 firewall; do cp {ROM_DIR}/etc/config/$f /etc/config/$f; done
rm -rf {PROC_DIR}/4100 /usr/bin/sqlite3 /etc/oui
"""

# a fake sqlite3: it prints the rows of table account for the query the server sends
FAKE_SQLITE = r"""
mkdir -p /etc/oui
echo 'SQLite format 3' > /etc/oui/oui.db
cat > /usr/bin/sqlite3 <<'EOF'
#!/bin/sh
for a; do last=$a; done
case $last in *'FROM account'*) printf 'root\tadmin\nbob\tadmin\n' ;; *) exit 1 ;; esac
EOF
chmod 755 /usr/bin/sqlite3
"""

# what an owner or an intruder changes: an extra unauthenticated method, the serial
# console, GoodCloud bound with rtty on and running, an extra web admin
GL_CHANGED = rf"""
set -e
uci add oui-httpd no-auth-methods >/dev/null
uci set oui-httpd.@no-auth-methods[-1].object=system
uci add_list oui-httpd.@no-auth-methods[-1].method=reboot
uci set oui-httpd.main.console_disabled=0
uci set gl-cloud.@cloud[0].enable=1
uci set gl-cloud.@cloud[0].username=owner
uci set gl-cloud.@cloud[0].email=owner@example.com
uci set gl-cloud.@cloud[0].bindtime=1700000000
uci set rtty.general.ssh_en=1
uci commit
mkdir -p {PROC_DIR}/4100
echo rtty > {PROC_DIR}/4100/comm
printf '/usr/sbin/rtty|-I|dev42|-h|relay.example|-p|5912|-a|-s|-t|rttytoken31|' | tr '|' '\000' > {PROC_DIR}/4100/cmdline
: > {PROC_DIR}/4100/environ
{FAKE_SQLITE}
"""

SECTIONS = ["Remote management", "Admin access", "VPN servers and mesh VPNs", "Sharing", "Firmware and updates"]


class GLCase(OpenWrtTestCase):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        if cls.container is None:
            raise unittest.SkipTest("needs a container")
        try:
            cls.container.sh(GL_SETUP)
        except BaseException:
            cls.tearDownClass()
            raise


class TestNotGL(OpenWrtTestCase):
    @needs_container
    def test_one_line_on_other_firmware(self):
        text = self.tool_ok("glinet")
        self.assertEqual(len(text.strip().splitlines()), 1, text)
        self.assertIn("Not GL.iNet firmware", text)
        self.assertIn("/etc/glversion", text)

    def test_takes_no_arguments(self):
        text, err = self.tool("glinet", verbose=True)
        self.assertTrue(err)
        self.assertIn("verbose", text)


class TestGlinet(GLCase):
    def test_stock_state(self):
        text = self.tool_ok("glinet", GL)
        heads = [h.split(" (")[0] for h in re.findall(r"^== (.*)$", text, flags=re.M)]
        self.assertEqual(heads, SECTIONS)
        self.assertIn("GL.iNet firmware 4.11.0 (beta5), model GL-BE14000, mode router", text)
        self.assertIn("GoodCloud (gl-cloud): off", text)
        self.assertIn("bound to a GoodCloud account: no", text)
        self.assertIn("token: present (never shown)", text)
        self.assertIn("gl-cloud process: not running", text)
        self.assertIn("Remote terminal (rtty): SSH off, web off", text)
        self.assertIn("rtty process: not running", text)
        self.assertIn("device DDNS name: abc1234.glddns.com", text)
        self.assertIn("oui-httpd.main.console_disabled='1'\n", text)
        self.assertIn("console_disabled 1: the serial console offers no login", text)
        self.assertIn("ui: get_lang [image], check_initialized [image]", text)
        self.assertIn("system: get_timezone_list [image]", text)
        self.assertNotIn("[ADDED]", text.split("[-] not compared):")[1])
        self.assertIn("  listen 443 ssl;", text)
        self.assertIn("web admin accounts: no /etc/oui/oui.db", text)
        self.assertIn("firewall.ssh_wan rule 'ssh_wan': src wan, proto tcp, dest_port 22, target ACCEPT, DISABLED", text)
        self.assertIn("firewall.dmz redirect 'GL-DMZ': src wan", text)
        self.assertIn("firewall.sambasharewan rule 'sambasharewan': src wan, proto tcp, dest_port 445, target DROP, enabled",
                      text.split("== Sharing")[1])
        self.assertNotIn("sambasharewan", text.split("== Sharing")[0])
        self.assertIn("wireguard_server.main_server.port='51820'", text)
        self.assertIn("peers: 1 (alice)", text)
        self.assertIn("interface wgserver: absent", text)
        self.assertIn("'usb': path /mnt/sda1, guest ok yes, read only no", text)
        self.assertIn("OpenVPN server (ovpnserver): not installed (no /etc/config/ovpnserver)", text)
        self.assertIn("Tor (tor): not installed", text)
        self.assertIn("model GL-BE14000, country code US", text)
        self.assertIn("upgrade.general.keep_config='1'", text)
        self.assertIn('persistence locations=["feeds"]', text)

    def test_never_prints_secrets_or_device_identity(self):
        for env in (GL, dict(GL, MCP_REDACT="0")):
            text = self.tool_ok("glinet", env)
            for secret in ("cloudtoken42", "devicekey99", "certificate77", "serial55"):
                self.assertNotIn(secret, text, env)
        text = self.tool_ok("glinet", GL)
        self.assertNotIn("wgsecret77", text)
        self.assertNotIn("peersecret88", text)

    def test_changes_against_the_image(self):
        self.sh(GL_CHANGED)
        try:
            text = self.tool_ok("glinet", GL)
            self.assertIn("system: reboot [ADDED]", text)
            self.assertIn("oui-httpd.main.console_disabled='0'  (image: '1')", text)
            self.assertIn("console_disabled 0: gl-ngx-session links /bin/login to busybox", text)
            self.assertIn("GoodCloud (gl-cloud): on", text)
            self.assertIn("gl-cloud.@cloud[0].email='owner@example.com'", text)
            self.assertIn("bound to a GoodCloud account: yes", text)
            self.assertIn("Remote terminal (rtty): SSH on, web off", text)
            self.assertIn("rtty process: running, pid 4100 (rtty): /usr/sbin/rtty -I dev42 -h relay.example", text)
            self.assertIn("-t <redacted>", text)
            self.assertNotIn("rttytoken31", text)
            self.assertIn("!! GoodCloud is on and rtty allows SSH or web access", text)
            self.assertIn("  bob (acl admin)  <- an extra admin of the web interface", text)
            self.assertIn("  root (acl admin)\n", text)
            plain = self.tool_ok("glinet", dict(GL, MCP_REDACT="0"))
            self.assertIn("rttytoken31", plain)
            self.assertNotIn("cloudtoken42", plain)
        finally:
            self.sh(GL_RESET)

    def test_without_image_nothing_is_marked(self):
        text = self.tool_ok("glinet", {"MCP_PROC": PROC_DIR})
        self.assertIn("ui: get_lang [-], check_initialized [-]", text)
        self.assertIn("the image at /rom has no /etc/config/oui-httpd: not compared", text)
        self.assertNotIn("(image:", text)

    def test_the_servers_own_processes_are_left_out(self):
        pid = self.session(GL).call_tool("exec", {"command": "echo ${MCP_CALL_TAG%%.*}"})[0].split()[0]
        self.sh(f"P={PROC_DIR}; mkdir -p $P/4200 && echo rtty > $P/4200/comm && printf 'rtty\\000' > $P/4200/cmdline && "
                f"printf 'A=1\\000MCP_CALL_TAG={pid}.3.\\000' > $P/4200/environ")
        try:
            self.assertIn("rtty process: not running", self.tool_ok("glinet", GL))
        finally:
            self.sh(f"rm -rf {PROC_DIR}/4200")

    def test_without_sqlite3(self):
        self.sh("mkdir -p /etc/oui && echo x > /etc/oui/oui.db")
        try:
            text = self.tool_ok("glinet", GL)
            self.assertIn("web admin accounts: sqlite3: not available", text)
        finally:
            self.sh("rm -rf /etc/oui")

    def test_floods_are_capped_and_cut_only_the_tail(self):
        self.sh(r"""set -e
            for i in $(seq 1 120); do uci add_list oui-httpd.@no-auth-methods[0].method=m$i; done
            for i in $(seq 1 300); do uci add firewall rule >/dev/null; uci set firewall.@rule[-1].name=GL-r$i; uci set firewall.@rule[-1].src=wan; done
            for i in $(seq 1 200); do uci add samba4 sambashare >/dev/null; uci set samba4.@sambashare[-1].name=s$i; done
            uci commit""")
        try:
            text = self.tool_ok("glinet", GL)
            self.assertLess(len(text.encode()), 60000)
            self.assertNotIn("[output cut", text)
            self.assertRegex(text, r"ui: m1 \[ADDED\], .*, \.\.\. \(120 methods\)")
            self.assertIn("(262 more; the firewall tool lists them)", text)
            self.assertIn("(171 more shares)", text)
            self.assertIn("== Firmware and updates", text)
        finally:
            self.sh(GL_RESET)
