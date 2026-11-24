# Common tasks

Left: the GL.iNet method (`glinet_api`, GL.iNet firmware 4.x). Right: the uci package and
options on plain OpenWrt (`uci_change`). `C` marks calls that need `confirm`. Method names
are from the catalog (GL-E5800, firmware 4.8.5); list the object on the router before
calling, and take parameter values from the matching `get_` answer.

## Wi-Fi

| Task | GL.iNet | Plain OpenWrt |
| --- | --- | --- |
| Show radios and networks | `wifi.get_config`, `wifi.get_status` | `uci` package `wireless`; `network` for live state |
| SSID, password, encryption, on/off, hidden | `wifi.set_config` C (`iface_name` from `get_config`) | `wireless`, section `wifi-iface`: `ssid`, `key`, `encryption`, `disabled`, `hidden` C |
| Channel, width, band mode | `wifi.set_config` C (`device`, `channel`, `htmode`, `hwmode`) | `wireless`, section `wifi-device`: `channel`, `htmode` C |
| Transmit power only | `wifi.set_txpower` | `wifi-device` option `txpower` C |
| Guest Wi-Fi | `wifi.set_config` C on the guest interface from `get_config`; its address and DHCP are `lan.set_config` with the guest interface | a second `wifi-iface` on its own network and firewall zone: several packages, plan it with the user |
| Wi-Fi 7 MLO | `wifi.get_mlo_config`, `wifi.set_mlo_config` C | not covered here |
| Wi-Fi on a schedule | object `timer` (`set_wifi` C) | cron, not covered by the write tools |

The guest network on GL.iNet is an existing interface that is switched on, not something
to build. Look for it in `wifi.get_config` before creating anything with uci.

## LAN, DHCP, DNS

| Task | GL.iNet | Plain OpenWrt |
| --- | --- | --- |
| Show LAN and DHCP | `lan.get_config_list` | `uci` packages `network`, `dhcp` |
| Router address, netmask | `lan.set_config` C (`interface`, `ip`, `netmask`) | `network.lan.ipaddr`, `netmask` C |
| DHCP on/off, range, lease time, DNS handed out | `lan.set_config` C (`enable`, `start`, `end`, `leasetime`, `dns`) | `dhcp.lan`: `ignore`, `start`, `limit`, `leasetime`, `dhcp_option` C |
| List static leases | `lan.get_static_bind_list` | `dhcp` sections `host` |
| Add or change a static lease | `lan.add_static_bind`, `lan.set_static_bind` (`name`, `mac`, `ip`) | `dhcp`: `add` type `host`, then `@host[-1].name`, `.mac`, `.ip` C |
| Remove a static lease | `lan.remove_static_bind` C | delete the `host` section C |
| Upstream DNS, DNS over TLS/HTTPS | `dns.get_config`, `dns.set_config` C | `dhcp.@dnsmasq[0]`: `server`, `noresolv` C |
| Local host names | `dns.get_host`, `dns.set_host` C | `dhcp` sections `domain` C |
| Who is connected | `clients.get_list` | `network` (neighbors, DHCP leases) |
| Name a client | `clients.set_info` | none |

GL's `start` and `end` are addresses; uci's `start` is an offset in the subnet and `limit`
a count. Do not carry values from one to the other.

## Firewall

| Task | GL.iNet | Plain OpenWrt |
| --- | --- | --- |
| Show | `firewall.get_rule_list`, `get_port_forward_list`, `get_dmz`, `get_wan_access` | read-only tool `firewall` |
| Port forward | `firewall.add_port_forward`, `set_port_forward`, `remove_port_forward` C | `firewall`: `add` type `redirect` with `name`, `src`, `src_dport`, `dest`, `dest_ip`, `dest_port`, `proto`, `target` C |
| Rule | `firewall.add_rule`, `set_rule`, `remove_rule` C | `firewall` section `rule` C |
| DMZ | `firewall.set_dmz` C | a `redirect` without ports C |
| Reach the router from the WAN (ping, HTTPS, SSH) | `firewall.set_wan_access` C | `rule` sections with `src=wan` C |

Before opening anything towards the WAN, say plainly what becomes reachable from the
internet and for whom. After the change, check with the read-only `firewall` and
`connections` tools that exactly this and nothing more is open.

## Uplink and mode

| Task | GL.iNet object |
| --- | --- |
| WAN port role and protocol, MAC clone | `cable` |
| Join an existing Wi-Fi as uplink | `repeater` (`scan`, `connect` C, `disconnect` C, `get_saved_ap_list`) |
| Cellular modem, SIM, APN, SMS | `modem`, `sms-forward` |
| Phone as uplink over USB | `tethering` |
| Several uplinks, failover | `kmwan` |
| Router / access point / repeater / WDS | `netmode` (`get_mode`, `set_mode` C) |
| IPv6 | `ipv6` |

On plain OpenWrt these are the `network` and `wireless` packages.

## VPN and remote access

| Task | GL.iNet object |
| --- | --- |
| VPN client: tunnels, which clients go through, kill switch, start and stop | `vpn-client` |
| WireGuard client configs and providers | `wg-client`, `wg_client` |
| OpenVPN client configs | `ovpn-client` |
| WireGuard server and peers | `wg-server` |
| OpenVPN server and users | `ovpn-server` |
| Tailscale, ZeroTier, Tor | `tailscale`, `zerotier`, `tor` |
| GoodCloud, remote terminal | `cloud`, `rtty` |
| GL DDNS | `ddns` |
| Web, SSH and LuCI ports, session timeout | `local-access` |

Nearly every changing method here needs `confirm`: a VPN server or GoodCloud opens a way
into the network, a VPN client with kill switch can take the internet away. Exported
client configs come back with masked keys.

## Clients

| Task | GL.iNet |
| --- | --- |
| Block or allow by MAC | `black_white_list` (`get_config`, `set_config` C, `set_single_mac` C) |
| Speed limit per client | `qos` (`set_speed_limit_rule`, `remove_speed_limit_rule`) |
| Parental control | `parental-control` |

A whitelist that does not contain the user's own device locks them out of the Wi-Fi.

## System

| Task | GL.iNet | Plain OpenWrt |
| --- | --- | --- |
| Status, load | `system.get_status`, `get_info`, `get_load` | `system_info` |
| Time zone | `system.set_timezone_config` | `system.@system[0]`: `zonename`, `timezone` |
| Host name | via uci | `system.@system[0].hostname` |
| LED | `led`; schedules in `timer` | `system` sections `led` |
| Admin password | `system.set_password` C | not covered by the write tools |
| Reboot | `system.reboot` C; schedule in `timer.set_reboot` C | not covered by the write tools |
| Factory reset | `system.reset_firmware` C | not covered |
| Firmware | `upgrade.check_firmware_online`, `upgrade_online` C, `get_online_upgrade_status` | not covered |
| Packages and plugins | `plugins` | not covered |
| AdGuard Home, DLNA, file sharing | `adguardhome`, `dlna`, `nas-web` | their own uci packages |
| Restart a service | `service_control` | `service_control` |

"Not covered by the write tools" means: tell the user how to do it themselves. Do not use
`exec` for it unless the user asks for that command.
