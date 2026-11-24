"""Network inventory tools: network, connections, firewall (server/20-network.sh).

Fixtures as in test_system: a fake `ubus` answering from canned JSON, a fake firmware
root in MCP_ROM, config files written into the container, uhttpd/dropbear/nc as
listeners and clients.
"""

import re
import unittest

from mcp_client import OpenWrtTestCase, needs_container
from test_system import FAKE_PATH, WIFI_KEY, WIRELESS, fake_rom, fake_ubus, write_file

WG_PRIVATE = "WgPrivKeySecretAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
WG_PSK = "WgPskSecretBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB="
PPPOE_PASS = "PppoeSecret99"

NETWORK = f"""config interface 'loopback'
\toption device 'lo'
\toption proto 'static'
\toption ipaddr '127.0.0.1'

config interface 'wan'
\toption device 'eth0'
\toption proto 'pppoe'
\toption username 'user'
\toption password '{PPPOE_PASS}'

config interface 'wg0'
\toption proto 'wireguard'
\toption private_key '{WG_PRIVATE}'
\toption listen_port '51820'
\tlist addresses '10.0.0.1/24'

config wireguard_wg0 'peer1'
\toption public_key 'PeerPublicKey='
\toption preshared_key '{WG_PSK}'
\toption endpoint_host 'vpn.example.com'
\toption endpoint_port '51820'
\tlist allowed_ips '10.0.0.2/32'
"""

IF_DUMP = {"interface": [
    {"interface": "lan", "up": True, "proto": "static", "l3_device": "br-lan",
     "ipv4-address": [{"address": "192.168.8.1", "mask": 24}], "ipv6-address": [],
     "route": [], "dns-server": []},
    {"interface": "wan", "up": True, "proto": "dhcp", "l3_device": "eth0",
     "ipv4-address": [{"address": "203.0.113.7", "mask": 24}],
     "route": [{"target": "0.0.0.0", "mask": 0, "nexthop": "203.0.113.1"}],
     "dns-server": ["203.0.113.53", "203.0.113.54"]},
    {"interface": "wan6", "up": False, "proto": "dhcpv6"},
]}


class TestNetwork(OpenWrtTestCase):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        if cls.container:
            cls.container.sh(f"cat > /etc/config/network <<'EOF'\n{NETWORK}\nEOF\n"
                             f"cat > /etc/config/wireless <<'EOF'\n{WIRELESS}\nEOF")

    def test_overview(self):
        text = self.tool_ok("network")
        for head in ("== Interfaces (one line per device", "== netifd interfaces", "== Routes, main table",
                     "== Neighbours (entries per device", "== DNS (details: section=dns)",
                     "== DHCP (details: section=dhcp)", "== Wi-Fi (radios and SSIDs", "== VPN (details: section=vpn)"):
            self.assertIn(head, text)
        self.assertIn("section=interfaces", text)
        self.assertRegex(text, r"\nlo\s+\S+\s+.*127\.0\.0\.1/8")
        self.assertNotIn("[output cut", text)
        self.assertLess(len(text.encode()), 25000, "the overview must stay compact")

    def test_each_section(self):
        heads = {
            "interfaces": ("== Interfaces and addresses", "== Device types, bridges and VLANs", "== netifd interfaces"),
            "routes": ("== IPv4 routes, all tables", "== IPv6 routes, all tables", "== Policy routing rules"),
            "neighbors": ("== Neighbours (ip neigh)",),
            "dns": ("== Resolvers", "== dnsmasq settings", "== dnsmasq processes", "== Hosts files"),
            "dhcp": ("== DHCPv4 leases", "== DHCPv6 leases", "== DHCP servers and static leases"),
            "wifi": ("== Wi-Fi status (iwinfo)", "== Wi-Fi config", "== hostapd and wpa_supplicant processes"),
            "vpn": ("== WireGuard", "== OpenVPN", "== Tailscale", "== ZeroTier", "== Tunnel devices"),
        }
        for sec, hs in heads.items():
            text = self.tool_ok("network", section=sec)
            for h in hs:
                self.assertIn(h, text, sec)
            self.assertNotIn("[output cut", text, sec)
        text = self.tool_ok("network", section="interfaces")
        self.assertRegex(text, r"inet 127\.0\.0\.1/8")

    def test_no_unmasked_secrets(self):
        # target-safe: no secret-looking uci option may carry a value other than <redacted>
        leak = re.compile(r"\.(key[0-9]?|password|private_key|preshared_key|sae_password|psk)='(?!<redacted>')")
        for sec in ("all", "wifi", "vpn", "interfaces"):
            text = self.tool_ok("network", section=sec)
            self.assertIsNone(leak.search(text), f"{sec}: {leak.search(text)}")
            self.assertNotRegex(text, r"private key: (?!\(hidden\))")

    def test_one_section_and_bad_section(self):
        text = self.tool_ok("network", section="routes")
        self.assertIn("== IPv4 routes", text)
        self.assertNotIn("== Resolvers", text)
        text, err = self.tool("network", section="bogus")
        self.assertTrue(err)
        self.assertIn("section must be one of", text)

    @needs_container
    def test_not_available_lines(self):
        text = self.tool_ok("network")
        self.assertIn("not available (ubus or netifd not reachable); configured interfaces from uci network", text)
        self.assertRegex(text, r"interface\s+wan\s+proto=pppoe device=eth0")
        self.assertIn("iwinfo: not available", text)
        if self.sh("command -v wg || true").strip() == "":
            self.assertIn("wg: not available", text)

    @needs_container
    def test_no_secrets(self):
        for sec in ("all", "interfaces", "routes", "neighbors", "dns", "dhcp", "wifi", "vpn"):
            text = self.tool_ok("network", section=sec)
            for secret in (WIFI_KEY, WG_PRIVATE, WG_PSK, PPPOE_PASS):
                self.assertNotIn(secret, text, sec)
        text = self.tool_ok("network")
        self.assertIn('ssid  default_radio0 device=radio0 mode=ap ssid="HomeNet" encryption=psk2', text)
        self.assertIn("uci VPN interfaces: wg0(wireguard)", text)
        text = self.tool_ok("network", section="wifi")
        self.assertIn("wireless.default_radio0.key='<redacted>'", text)
        text = self.tool_ok("network", section="vpn")
        self.assertIn("uci interface wg0 (proto wireguard): listen_port=51820 addresses=10.0.0.1/24", text)
        self.assertIn("peer peer1: description= endpoint=vpn.example.com:51820 allowed_ips=10.0.0.2/32", text)

    @needs_container
    def test_netifd_and_leases(self):
        fake_ubus(self, {"network.interface dump": IF_DUMP, "dhcp ipv6leases": {"device": {"br-lan": {"leases": [
            {"duid": "000100012a", "iaid": 1, "hostname": "phone", "valid": 3600,
             "ipv6-addr": [{"address": "fd00::50", "preferred-lifetime": 1, "valid-lifetime": 2}]}]}}}})
        write_file(self, "/tmp/dhcp.leases",
                   "1795600000 aa:bb:cc:dd:ee:01 192.168.8.50 laptop 01:aa:bb:cc:dd:ee:01\n"
                   "0 aa:bb:cc:dd:ee:02 192.168.8.51 printer *")
        text = self.tool_ok("network", env={"PATH": FAKE_PATH}, section="interfaces")
        self.assertRegex(text, r"\nlan\s+static\s+yes\s+br-lan\s+192\.168\.8\.1/24\s+-\s+-")
        self.assertRegex(text, r"\nwan\s+dhcp\s+yes\s+eth0\s+203\.0\.113\.7/24\s+203\.0\.113\.1\s+203\.0\.113\.53 203\.0\.113\.54")
        self.assertRegex(text, r"\nwan6\s+dhcpv6\s+no\s+-")
        text = self.tool_ok("network", env={"PATH": FAKE_PATH}, section="dhcp")
        self.assertRegex(text, r"20\d\d-\d\d-\d\d \d\d:\d\d:\d\d aa:bb:cc:dd:ee:01 192\.168\.8\.50\s+laptop")
        self.assertRegex(text, r"never\s+aa:bb:cc:dd:ee:02 192\.168\.8\.51\s+printer")
        self.assertRegex(text, r"phone\s+000100012a\s+fd00::50 valid=3600s")
        self.assertRegex(text, r"dhcp\s+lan\s+interface=lan start=100 limit=150")

    @needs_container
    def test_dns_overrides(self):
        write_file(self, "/var/etc/dnsmasq.conf.cfg01411c",
                   "# auto-generated\nserver=/corp.example/10.1.1.1\naddress=/update.example.com/198.51.100.66\n"
                   "conf-dir=/tmp/dnsmasq.d\ndomain-needed")
        write_file(self, "/tmp/hosts/extra", "198.51.100.77 bank.example.com")
        text = self.tool_ok("network", section="dns")
        self.assertRegex(text, r"/(var|tmp)/etc/dnsmasq\.conf\.cfg01411c \(4 settings\):")
        self.assertEqual(text.count("address=/update.example.com/198.51.100.66"), 1, "each file once")
        self.assertIn("address=/update.example.com/198.51.100.66", text)
        self.assertIn("server=/corp.example/10.1.1.1", text)
        self.assertNotIn("domain-needed", text)
        self.assertIn("/tmp/hosts/extra (1 entries):", text)
        self.assertIn("198.51.100.77 bank.example.com", text)
        self.assertIn("domain=lan", text)
        text = self.tool_ok("network")
        self.assertEqual(text.count("address=/update.example.com/198.51.100.66"), 1)


class TestConnections(OpenWrtTestCase):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        if cls.container:
            ip = cls.container.sh("ip -4 addr show eth0 | awk '$1 == \"inet\" { sub(/\\/.*/, \"\", $2); print $2; exit }'").strip()
            cls.eth0 = ip
            cls.container.sh(f"uhttpd -p 0.0.0.0:8093 -h /www; uhttpd -p 127.0.0.1:8094 -h /www; "
                             f"uhttpd -p {ip}:8095 -h /www; mkdir -p /etc/dropbear; "
                             "dropbear -R -p 2222 >/dev/null 2>&1; sleep 2", check=False)

    def pid_of(self, port: int) -> str:
        """pid of the listener on port, from /proc via the container's own view"""
        hexport = f"{port:04X}"
        inode = self.sh(f"awk '$2 ~ /:{hexport}$/ && $4 == \"0A\" {{ print $10; exit }}' /proc/net/tcp /proc/net/tcp6").strip()
        if not inode:
            return ""
        return self.sh(f"ls -l /proc/[0-9]*/fd 2>/dev/null | awk '/^\\/proc\\// {{ split($0, p, \"/\"); pid = p[3] }} "
                       f"/socket:\\[{inode}\\]/ {{ print pid; exit }}'").strip()

    @needs_container
    def test_listeners_with_scope_and_pid(self):
        text = self.tool_ok("connections")
        self.assertIn("== Listening and unbound sockets", text)
        pid = self.pid_of(8093)
        self.assertRegex(text, rf"tcp\s+LISTEN\s+0\.0\.0\.0\s+8093\s+all IPv4 addresses\s+{pid}\s+uhttpd")
        self.assertRegex(text, r"tcp\s+LISTEN\s+127\.0\.0\.1\s+8094\s+loopback only\s+\d+\s+uhttpd")
        self.assertRegex(text, rf"tcp\s+LISTEN\s+{re.escape(self.eth0)}\s+8095\s+interface eth0\s+\d+\s+uhttpd")
        self.assertIn("== Connection tracking", text)
        dpid = self.pid_of(2222)
        if dpid:  # dropbear does not start on every image under emulation
            self.assertRegex(text, rf"tcp6?\s+LISTEN\s+\S+\s+2222\s+.*\s{dpid}\s+dropbear")
        text = self.tool_ok("connections", resolve_interfaces=False)
        self.assertIn("(interfaces not resolved)", text)
        self.assertRegex(text, rf"{re.escape(self.eth0)}\s+8095\s+this address")

    @needs_container
    def test_established(self):
        self.sh("(sleep 60 | nc 127.0.0.1 8093 >/dev/null 2>&1 &); sleep 2")
        text = self.tool_ok("connections", state="established")
        self.assertIn("== Connections", text)
        self.assertNotIn("== Listening", text)
        self.assertRegex(text, r"tcp\s+ESTABLISHED\s+127\.0\.0\.1:\d+\s+127\.0\.0\.1:8093\s+\d+\s+nc")
        self.assertRegex(text, r"tcp\s+ESTABLISHED\s+127\.0\.0\.1:8093\s+127\.0\.0\.1:\d+\s+\d+\s+uhttpd")
        text = self.tool_ok("connections", state="all")
        self.assertIn("== Listening", text)
        self.assertIn("== Connections", text)

    @needs_container
    def test_unix_and_conntrack(self):
        self.sh("mkdir -p /var/run/ubus; [ -S /var/run/ubus/ubus.sock ] || "
                "{ (ubusd -s /var/run/ubus/ubus.sock >/dev/null 2>&1 &); sleep 1; }")
        text = self.tool_ok("connections", include_unix=True, conntrack=True)
        self.assertIn("== Unix domain sockets", text)
        self.assertRegex(text, r"stream\s+LISTEN\s+\d+\s+ubusd\s+/var/run/ubus/ubus\.sock")
        self.assertRegex(text, r"(entries \d+ of max \d+|nf_conntrack: not available)")

    def test_bad_args(self):
        text, err = self.tool("connections", state="weird")
        self.assertTrue(err)
        text, err = self.tool("connections", max_results=0)
        self.assertTrue(err)


class TestFirewall(OpenWrtTestCase):
    def test_summary(self):
        text = self.tool_ok("firewall")
        heads = ("== Defaults", "== Zones", "== Forwardings", "== Rules accepting input from a WAN zone",
                 "== Port forwards (redirects)", "== Includes (uci)", "== All rules", "== UPnP / NAT-PMP",
                 "== Custom rule files", "== Active ruleset")
        for head in heads:
            self.assertIn(head, text)
        # what is exposed comes first, the long lists last
        self.assertEqual([text.index(h) for h in heads], sorted(text.index(h) for h in heads))
        self.assertRegex(text, r"firewall: fw[34]")

    @needs_container
    def test_container_zones(self):
        text = self.tool_ok("firewall")
        self.assertRegex(text, r"\nwan\s+REJECT\s+ACCEPT\s+(REJECT|DROP)\s+1\s+wan wan6")
        self.assertIn("lan -> wan", text)
        self.assertRegex(text, r"\nAllow-Ping\s+proto=icmp")

    @needs_container
    def test_ruleset_not_available_says_why(self):
        text = self.tool_ok("firewall")
        # the containers cannot open netlink for nft; iptables-save prints nothing
        self.assertRegex(text, r"(cannot read the ruleset \(exit \d+\)|\(empty: no rules loaded|no iptables tables loaded)")

    @needs_container
    def test_opened_ports_and_custom_files(self):
        fake_rom(self)
        self.sh("""cat >> /etc/config/firewall <<'EOF'

config redirect
	option name 'cam'
	option src 'wan'
	option src_dport '8443'
	option dest 'lan'
	option dest_ip '192.168.8.20'
	option dest_port '443'
	option proto 'tcp'

config rule
	option name 'Open-SSH-WAN'
	option src 'wan'
	option dest_port '22'
	option proto 'tcp'
	option target 'ACCEPT'

config include 'evil'
	option path '/etc/evil.fw'
	option type 'script'
EOF
mkdir -p /etc/nftables.d && echo 'chain x { tcp dport 4444 accept }' > /etc/nftables.d/99-backdoor.nft
echo 'iptables -I INPUT -p tcp --dport 4444 -j ACCEPT' > /etc/evil.fw
cat > /etc/config/upnpd <<'EOF'
config upnpd 'config'
	option enabled '1'
	option enable_natpmp '1'
	option upnp_lease_file '/var/run/miniupnpd.leases'
EOF
mkdir -p /var/run && echo 'TCP:51413:192.168.8.30:51413:1795600000:torrent' > /var/run/miniupnpd.leases""")
        text = self.tool_ok("firewall", env={"MCP_ROM": "/fixture/rom"})
        self.assertRegex(text, r"\ncam\s+wan:8443/tcp -> 192\.168\.8\.20:443 target=DNAT")
        self.assertRegex(text, r"\nOpen-SSH-WAN\s+proto=tcp dest_port=22")
        self.assertIn("evil                 path=/etc/evil.fw type=script", text)
        self.assertIn("/etc/evil.fw (uci include, 1 non-comment lines)   !! not in firmware image", text)
        self.assertIn("iptables -I INPUT -p tcp --dport 4444 -j ACCEPT", text)
        self.assertRegex(text, r"/etc/nftables\.d/99-backdoor\.nft   !! not in firmware image")
        self.assertNotRegex(text, r"/etc/nftables\.d/README.*not in firmware image")
        self.assertIn("config.enabled=1", text)
        self.assertIn("config.enable_natpmp=1", text)
        self.assertIn("TCP:51413:192.168.8.30:51413:1795600000:torrent", text)

    @needs_container
    def test_raw(self):
        text = self.tool_ok("firewall", raw=True)
        self.assertNotIn("raw=true prints all", text)



class TestReviewFixesNetwork(OpenWrtTestCase):
    @needs_container
    def test_i7_iptables_save_only_with_tables(self):
        write_file(self, "/fixture/bin/iptables-save", "#!/bin/sh\ntouch /tmp/ipt-called\necho '*filter'", mode="755")
        write_file(self, "/fixture/bin/ip6tables-save", "#!/bin/sh\ntouch /tmp/ip6t-called\necho '*filter'", mode="755")
        self.sh("rm -f /tmp/ipt-called /tmp/ip6t-called")
        v4 = self.sh("grep -c . /proc/net/ip_tables_names 2>/dev/null || true").strip() or "0"
        v6 = self.sh("grep -c . /proc/net/ip6_tables_names 2>/dev/null || true").strip() or "0"
        text = self.tool_ok("firewall", env={"PATH": FAKE_PATH})
        if v4 == "0":
            self.assertIn("iptables-save: no iptables tables loaded", text)
            self.assertEqual(self.sh("[ -e /tmp/ipt-called ] && echo yes || echo no").strip(), "no")
        if v6 == "0":
            self.assertIn("ip6tables-save: no ip6tables tables loaded", text)
            self.assertEqual(self.sh("[ -e /tmp/ip6t-called ] && echo yes || echo no").strip(), "no")
        if v4 == "0" and v6 == "0":
            return
        self.assertIn("*filter", text)


if __name__ == "__main__":
    unittest.main()
