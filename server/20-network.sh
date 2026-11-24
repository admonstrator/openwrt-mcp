# Network inventory: network, connections, firewall. Read-only: sockets come from
# /proc (lib_sockets), never from netstat or ss.
# Handler variables are assigned by arg/arg_int (through eval):
# shellcheck disable=SC2154

# "address ifname" for every IPv4/IPv6 address, from ip addr (busybox or ip-full)
_net_addr_map() {
	ip addr show 2>/dev/null | awk '
		/^[0-9]+: / { i = $2; sub(/:$/, "", i); sub(/@.*/, "", i); next }
		$1 == "inet" || $1 == "inet6" { a = $2; sub(/\/.*/, "", a); print a, i }'
}

# processes once per call, for the sections that look for daemons
_net_procs() { [ -f procs.tsv ] || lib_procs >procs.tsv; }

# running processes whose name matches the extended regex $1: "pid name cmdline"
_net_running() {
	_net_procs
	RE=$1 awk -F '\t' '$7 == 0 && $8 ~ ENVIRON["RE"] { printf "  pid %-6s %-16s %s\n", $1, $8, substr($10, 1, 300); n++ } END { if (!n) print "  none running" }' procs.tsv | redact
}

# dnsmasq config files, each once (/var is a link to /tmp on OpenWrt)
_net_dnsmasq_files() {
	_seen=
	for _f in /var/etc/dnsmasq.conf* /tmp/etc/dnsmasq.conf* /etc/dnsmasq.conf /tmp/dnsmasq.d/* /tmp/dnsmasq.cfg*.d/* /etc/dnsmasq.d/*; do
		[ -f "$_f" ] || continue
		_r=$(readlink -f "$_f" 2>/dev/null) || _r=$_f
		case " $_seen " in *" $_r "*) continue ;; esac
		_seen="$_seen $_r"
		printf '%s\n' "$_r"
	done
}

# list files under the given paths with size, mtime and a flag when not in the image
_net_files() {
	_romok=0
	lib_rom_ok && _romok=1
	_any=0
	for _p in "$@"; do
		[ -e "$_p" ] || [ -L "$_p" ] || continue
		_any=1
		find "$_p" -xdev -maxdepth 2 \( -type f -o -type l \) 2>/dev/null | head -n 50 >files.txt
		[ -s files.txt ] || echo "  $_p: empty"
		while IFS= read -r _f; do
			_n=
			[ "$_romok" = 1 ] && ! in_rom "$_f" && _n="   !! not in firmware image"
			# shellcheck disable=SC2012
			printf '  %s%s\n' "$(ls -ln --full-time "$_f" 2>/dev/null | awk '{ printf "%8s %s %s  ", $5, $6, $7 }')$_f" "$_n"
		done <files.txt
	done
	[ "$_any" = 1 ] || echo "  none of: $*"
}

# ============================================================== network
mcp_register network <<'EOF'
{"name":"network","title":"Network configuration","description":"The router's network state: interfaces and addresses, bridges and VLANs, netifd's view of the logical interfaces (proto, device, addresses, gateway, DNS), all routing tables and policy rules for IPv4 and IPv6, neighbours, DNS resolvers and dnsmasq settings (upstream servers, address overrides, hosts files), DHCP leases, Wi-Fi status and config (keys masked), and VPNs (WireGuard, OpenVPN, Tailscale, ZeroTier). The default section=all is a compact overview (one line per interface, main routing table, condensed DNS, DHCP, Wi-Fi and VPN); request a section for the full details.","inputSchema":{"type":"object","properties":{"section":{"type":"string","enum":["all","interfaces","routes","neighbors","dns","dhcp","wifi","vpn"],"description":"all: compact overview of everything (default). interfaces: ip -d addr, device types, bridges, VLANs, netifd. routes: all tables and policy rules. neighbors, dns, dhcp, wifi (full uci wireless), vpn: the full details of that part.","default":"all"}},"additionalProperties":false},"annotations":{"readOnlyHint":true,"openWorldHint":false}}
EOF
tool_network() {
	arg _sec section all
	case $_sec in
	all | interfaces | routes | neighbors | dns | dhcp | wifi | vpn) ;;
	*) tool_error "section must be one of all, interfaces, routes, neighbors, dns, dhcp, wifi, vpn; got '$_sec'"; return 1 ;;
	esac
	if [ "$_sec" = all ]; then _net_overview; else "_net_$_sec"; fi
	return 0
}

# section=all: one compact pass over everything, each part pointing to its section
_net_overview() {
	echo "Compact overview. Full details per part: section=interfaces (ip -d addr, bridges, VLANs), routes (all tables, rules), neighbors, dns, dhcp, wifi (full uci wireless), vpn."

	section "Interfaces (one line per device; details: section=interfaces)"
	for _i in /sys/class/net/*; do
		[ -d "$_i" ] || continue
		_t=$(sed -n 's/^DEVTYPE=//p' "$_i/uevent" 2>/dev/null)
		[ -e "$_i/tun_flags" ] && _t=tun/tap
		[ -d "$_i/bridge" ] && _t=bridge
		[ -z "$_t" ] && [ -e "$_i/phy80211" ] && _t=wlan
		_m=
		[ -e "$_i/master" ] && _m=$(readlink "$_i/master" 2>/dev/null | sed 's|.*/||')
		printf 'D\t%s\t%s\t%s\n' "${_i##*/}" "${_t:--}" "${_m:--}"
	done >devs.txt
	ip addr show >ipa.txt 2>&1
	awk -F '\t' '
	FILENAME == "devs.txt" { typ[$2] = $3; mst[$2] = $4; next }
	/^[0-9]+: / {
		split($0, h, " "); nm = h[2]; sub(/:$/, "", nm); par = ""
		if (index(nm, "@")) { par = substr(nm, index(nm, "@") + 1); nm = substr(nm, 1, index(nm, "@") - 1) }
		if (par == "NONE") par = ""
		st = "?"; for (i = 1; i < length(h); i++) if (h[i] == "state") st = h[i + 1]
		if (h[3] !~ /[<,]UP[,>]/) st = "admin-down"
		o[++n] = nm; state[nm] = st; parent[nm] = par; next
	}
	{
		split($0, f, " ")
		if (f[1] == "inet" || f[1] == "inet6") {
			if (f[2] ~ /^fe80:/) ll[nm]++
			else addr[nm] = addr[nm] "" (addr[nm] == "" ? "" : " ") f[2]
		}
	}
	END {
		printf "%-16s %-14s %-16s %-10s %s\n", "DEVICE", "STATE", "TYPE", "MASTER", "ADDRESSES"
		for (i = 1; i <= n; i++) {
			d = o[i]; t = (d in typ) ? typ[d] : "-"; if (parent[d] != "") t = t "@" parent[d]
			a = addr[d]; if (ll[d]) a = a "" (a == "" ? "" : " ") "(+" ll[d] " link-local)"
			printf "%-16s %-14s %-16s %-10s %s\n", d, state[d], t, ((d in mst) ? mst[d] : "-"), (a == "" ? "-" : a)
		}
		if (!n) print "ip addr: no output"
	}' devs.txt ipa.txt

	_net_netifd

	section "Routes, main table (all tables and policy rules: section=routes)"
	echo "IPv4:"
	ip -4 route show 2>&1 | head -n 60 | sed 's/^/  /'
	echo "IPv6 (link-local fe80:: routes left out):"
	ip -6 route show 2>&1 | grep -v -E '^(unreachable )?fe80:' | head -n 60 | sed 's/^/  /'
	{ ip -4 route show table all; ip -6 route show table all; } 2>/dev/null | awk '
		{ t = "main"; for (i = 1; i < NF; i++) if ($i == "table") t = $(i + 1); if (t != "main") c[t]++ }
		END { s = ""; for (k in c) s = s " " k "=" c[k]; print "other tables (routes, IPv4+IPv6):" (s == "" ? " none" : s) }'
	_r=$(ip -4 rule show 2>/dev/null | grep -c -v -E 'lookup (local|main|default) *$')
	echo "policy rules besides local/main/default (IPv4): ${_r:-not available}"

	section "Neighbours (entries per device; list: section=neighbors)"
	ip neigh show 2>/dev/null | awk '
		{ d = "?"; for (i = 1; i < NF; i++) if ($i == "dev") d = $(i + 1); s = $NF; n[d]++; st[d, s]++; if (!(s in seen)) { seen[s] = 1; ss[++m] = s } }
		END {
			for (d in n) { l = sprintf("%-16s %4d", d, n[d]); for (j = 1; j <= m; j++) if ((d, ss[j]) in st) l = l " " ss[j] "=" st[d, ss[j]]; print l; any = 1 }
			if (!any) print "none"
		}'

	section "DNS (details: section=dns)"
	for _f in /etc/resolv.conf /tmp/resolv.conf /tmp/resolv.conf.auto /tmp/resolv.conf.d/resolv.conf.auto; do
		[ -f "$_f" ] || continue
		printf '%-40s %s\n' "$_f" "$(rd "$_f" | awk '$1 == "nameserver" || $1 == "search" { printf "%s ", $0 }')"
	done
	echo "dnsmasq processes:"
	_net_running '^dnsmasq$' | head -n 3
	echo "dnsmasq upstreams and overrides:"
	_net_dnsmasq_files | while IFS= read -r _f; do
		rd "$_f" | grep -E '^[[:space:]]*(server|address|conf-dir|conf-file|addn-hosts|resolv-file|servers-file)=' | sed "s|^|  $_f: |"
	done >dnsov.txt
	head -n 25 dnsov.txt
	_n=$(wc -l <dnsov.txt)
	[ "$_n" -gt 25 ] && echo "  ... $_n lines in total, first 25 shown; section=dns lists them per file"
	_h=$(rd /etc/hosts | grep -c -v -E '^[[:space:]]*(#|$)')
	_x=$(cat /tmp/hosts/* 2>/dev/null | grep -c -v -E '^[[:space:]]*(#|$)')
	echo "hosts entries: /etc/hosts ${_h:-0}, /tmp/hosts/* ${_x:-0}"

	section "DHCP (details: section=dhcp)"
	_lf=$(lib_uci_dump dhcp | awk -F '\t' '$1 == "O" && $3 == "leasefile" { print $4; exit }')
	_lf=${_lf:-/tmp/dhcp.leases}
	if [ -f "$_lf" ]; then
		rd "$_lf" | awk '{ n++; if (n <= 30) printf "  %-19s %-17s %-15s %s\n", ($1 == 0 ? "never" : strftime("%Y-%m-%d %H:%M:%S", $1)), $2, $3, $4 }
			END { printf "%d DHCPv4 leases in %s%s\n", n, lf, (n > 30 ? " (first 30 shown)" : "") }' lf="$_lf"
	else
		echo "no DHCPv4 lease file ($_lf)"
	fi
	lib_uci_dump dhcp | awk -F '\t' '$1 == "S" && $3 == "host" { h++ } $1 == "S" && $3 == "dhcp" { d++ } END { printf "uci dhcp: %d DHCP pools, %d static leases\n", d, h }'

	section "Wi-Fi (radios and SSIDs from uci, keys never shown; details: section=wifi)"
	lib_uci_dump wireless >wl.uci
	if [ -s wl.uci ]; then
		awk -F '\t' '
		$1 == "S" { t[$2] = $3; o[++n] = $2; next }
		$3 ~ /^(type|band|hwmode|channel|htmode|disabled|device|mode|ssid|encryption|network|hidden|isolate|ifname)$/ { if (($2, $3) in v) v[$2, $3] = v[$2, $3] "," $4; else v[$2, $3] = $4 }
		function g(s, k) { return ((s, k) in v) ? v[s, k] : "-" }
		END {
			for (i = 1; i <= n; i++) { s = o[i]; if (t[s] == "wifi-device") printf "radio %-14s type=%s band=%s channel=%s htmode=%s disabled=%s\n", s, g(s, "type"), (g(s, "band") != "-" ? g(s, "band") : g(s, "hwmode")), g(s, "channel"), g(s, "htmode"), g(s, "disabled") }
			for (i = 1; i <= n; i++) { s = o[i]; if (t[s] == "wifi-iface") printf "ssid  %-14s device=%s mode=%s ssid=\"%s\" encryption=%s network=%s disabled=%s hidden=%s\n", s, g(s, "device"), g(s, "mode"), g(s, "ssid"), g(s, "encryption"), g(s, "network"), g(s, "disabled"), g(s, "hidden") }
		}' wl.uci
	else
		echo "no /etc/config/wireless"
	fi
	if have iwinfo; then
		run_timeout 15 iwinfo >iw.txt 2>&1
		awk '/^[^ \t]/ && /ESSID/ { d = $1; o[++n] = d; e = $0; sub(/.*ESSID: /, "", e); es[d] = e }
			/Mode:/ { m = $0; sub(/^[ \t]*/, "", m); gsub(/  +/, " ", m); mode[d] = m }
			/Encryption:/ { c = $0; sub(/.*Encryption: /, "", c); enc[d] = c }
			END { for (i = 1; i <= n; i++) printf "live  %-14s %s %s enc=%s\n", o[i], es[o[i]], mode[o[i]], enc[o[i]]; if (!n) print "iwinfo: no wireless interfaces" }' iw.txt
	else
		echo "iwinfo: not available"
	fi

	section "VPN (details: section=vpn)"
	if have wg; then
		run_timeout 10 wg show interfaces >wgi.txt 2>&1
		if [ -s wgi.txt ]; then
			awk '{ for (i = 1; i <= NF; i++) print $i }' wgi.txt >wgn.txt
			while IFS= read -r _w; do
				run_timeout 10 wg show "$_w" latest-handshakes >wgh.txt 2>/dev/null
				run_timeout 10 wg show "$_w" listen-port >wgp.txt 2>/dev/null
				awk -v w="$_w" -v port="$(cat wgp.txt)" -v now="$(date +%s)" '
					{ n++; if ($2 > last) last = $2 }
					END { printf "wireguard %-12s listen_port=%s peers=%d latest_handshake=%s\n", w, (port == "" ? "-" : port), n, (last > 0 ? (now - last) " s ago" : "never") }' wgh.txt
			done <wgn.txt
		else
			echo "wireguard: no interfaces"
		fi
	else
		echo "wg: not available"
	fi
	lib_uci_dump network | awk -F '\t' '$3 == "proto" && $4 ~ /^(wireguard|wgclient|wgserver|openvpn|zerotier|tailscale)$/ { s = s " " $2 "(" $4 ")" } END { print "uci VPN interfaces:" (s == "" ? " none" : s) }'
	_net_procs
	awk -F '\t' '$7 == 0 && $8 ~ /^(openvpn|tailscaled|tailscale|zerotier-one|wireguard-go|ipsec|charon|xl2tpd)$/ { s = s " " $8 "(pid " $1 ")" } END { print "VPN processes:" (s == "" ? " none" : s) }' procs.tsv
	_c=
	for _p in /etc/openvpn /etc/config/openvpn /etc/config/ovpnclient /etc/config/ovpnserver /etc/config/tailscale /var/lib/tailscale /etc/config/zerotier /var/lib/zerotier-one /etc/config/wireguard; do
		[ -e "$_p" ] && _c="$_c $_p"
	done
	echo "VPN config present:${_c:- none}"
}

_net_interfaces() {
	section "Interfaces and addresses"
	if ip -d addr show >ipa.txt 2>/dev/null; then
		cat ipa.txt
	else
		ip addr show 2>&1
		echo "(this ip has no -d: busybox ip, link details such as VLAN ids are not shown)"
	fi

	section "Device types, bridges and VLANs"
	for _i in /sys/class/net/*; do
		[ -d "$_i" ] || continue
		_n=${_i##*/}
		_t=$(sed -n 's/^DEVTYPE=//p' "$_i/uevent" 2>/dev/null)
		[ -e "$_i/tun_flags" ] && _t="${_t:+$_t,}tun/tap"
		[ -e "$_i/phy80211" ] && _t="${_t:+$_t,}wifi"
		_x=
		if [ -d "$_i/bridge" ]; then
			_x=" members: $(cd "$_i/brif" 2>/dev/null && echo * | sed 's/^\*$//')"
			_x="$_x vlan_filtering=$(cat "$_i/bridge/vlan_filtering" 2>/dev/null)"
		fi
		[ -e "$_i/master" ] && _x="$_x master=$(readlink "$_i/master" 2>/dev/null | sed 's|.*/||')"
		printf '%-16s %-12s %s\n' "$_n" "${_t:--}" "$_x"
	done
	if [ "$(wc -l </proc/net/vlan/config 2>/dev/null || echo 0)" -gt 2 ]; then
		echo "802.1q VLAN devices (/proc/net/vlan/config):"
		sed -n '3,$p' /proc/net/vlan/config
	fi
	if have bridge; then
		echo "bridge vlan show:"
		run_timeout 10 bridge vlan show >brv.txt 2>&1
		head -n 100 brv.txt
	fi

	_net_netifd
}

# netifd's logical interfaces, or the uci network interfaces when ubus is not reachable
_net_netifd() {
	section "netifd interfaces (ubus network.interface dump)"
	if lib_ubus network.interface dump >ifdump.json && [ -s ifdump.json ]; then
		jsonfilter -i ifdump.json -e '@.interface[*]' >ifaces.txt 2>/dev/null
		printf '%-12s %-10s %-5s %-14s %-34s %-16s %s\n' INTERFACE PROTO UP DEVICE ADDRESSES GATEWAY DNS
		while IFS= read -r _j; do
			(
				I='' P='' U='' D='' A4='' M4='' A6='' M6='' G='' N=''
				eval "$(jsonfilter -s "$_j" -e 'I=@.interface' -e 'P=@.proto' -e 'U=@.up' -e 'D=@.l3_device' \
					-e 'A4=@["ipv4-address"][*].address' -e 'M4=@["ipv4-address"][*].mask' \
					-e 'A6=@["ipv6-address"][*].address' -e 'M6=@["ipv6-address"][*].mask' \
					-e 'G=@.route[@.target="0.0.0.0" && @.mask=0].nexthop' -e 'N=@["dns-server"][*]' 2>/dev/null)"
				_a=$(printf '%s\n%s\n' "$A4" "$M4" | awk 'NR == 1 { n = split($0, a, " ") } NR == 2 { split($0, m, " "); for (i = 1; i <= n; i++) printf "%s/%s ", a[i], m[i] }')
				_b=$(printf '%s\n%s\n' "$A6" "$M6" | awk 'NR == 1 { n = split($0, a, " ") } NR == 2 { split($0, m, " "); for (i = 1; i <= n; i++) printf "%s/%s ", a[i], m[i] }')
				[ "$U" = 1 ] && U=yes || U=no
				printf '%-12s %-10s %-5s %-14s %-34s %-16s %s\n' "$I" "${P:--}" "$U" "${D:--}" "$(echo "$_a $_b" | awk '{ $1 = $1; print }')" "${G:--}" "${N:--}"
			)
		done <ifaces.txt
	else
		echo "not available (ubus or netifd not reachable); configured interfaces from uci network:"
		lib_uci_dump network >net.uci
		if [ -s net.uci ]; then
			awk -F '\t' '
				$1 == "S" { t[$2] = $3; if ($3 == "interface" || $3 == "device") o[++n] = $2; next }
				$3 ~ /^(proto|device|ifname|ipaddr|netmask|ip6addr|gateway|dns|type|name|ports|vid|auto|disabled)$/ { v[$2, $3] = v[$2, $3] "" (v[$2, $3] == "" ? "" : ",") $4 }
				END {
					for (i = 1; i <= n; i++) {
						s = o[i]; line = sprintf("%-10s %-16s", t[s], s)
						split("proto device ifname type name ports vid ipaddr netmask ip6addr gateway dns auto disabled", k, " ")
						for (j = 1; j <= 14; j++) if ((s, k[j]) in v) line = line " " k[j] "=" v[s, k[j]]
						print line
					}
					if (!n) print "  no interface or device sections"
				}' net.uci
		else
			echo "  no /etc/config/network"
		fi
	fi
}

_net_routes() {
	section "IPv4 routes, all tables (ip -4 route show table all)"
	ip -4 route show table all 2>&1
	section "IPv6 routes, all tables (ip -6 route show table all)"
	ip -6 route show table all 2>&1
	section "Policy routing rules (ip rule, ip -6 rule)"
	for _f in 4 6; do
		if ip -"$_f" rule show >rules.txt 2>&1; then
			echo "IPv$_f:"
			cat rules.txt
		else
			echo "IPv$_f: not available ($(head -n 1 rules.txt))"
		fi
	done
}

_net_neighbors() {
	section "Neighbours (ip neigh)"
	ip neigh show >neigh.txt 2>&1
	if [ -s neigh.txt ]; then
		cat neigh.txt
	else
		echo "ip neigh: empty; /proc/net/arp:"
		cat /proc/net/arp 2>/dev/null
	fi
}

_net_dns() {
	section "Resolvers"
	for _f in /etc/resolv.conf /tmp/resolv.conf /tmp/resolv.conf.auto /tmp/resolv.conf.d/resolv.conf.auto /tmp/resolv.conf.ppp; do
		[ -e "$_f" ] || continue
		_l=
		[ -L "$_f" ] && _l=" -> $(readlink "$_f")"
		echo "$_f$_l:"
		rd "$_f" | grep -v -E '^[[:space:]]*(#|$)' | head -n 30 | sed 's/^/  /'
	done

	section "dnsmasq settings (uci dhcp)"
	lib_uci_dump dhcp >dhcp.uci
	if [ -s dhcp.uci ]; then
		awk -F '\t' '
			$1 == "S" { t[$2] = $3; if ($3 == "dnsmasq") o[++n] = $2; next }
			t[$2] == "dnsmasq" && $3 ~ /^(domain|local|server|noresolv|resolvfile|rebind_protection|rebind_localhost|rebind_domain|address|ipset|nftset|confdir|port|logqueries|addnhosts|serversfile|authoritative|interface|notinterface|localservice)$/ { v[$2] = v[$2] "  " $3 "=" $4 "\n" }
			END { for (i = 1; i <= n; i++) printf "%s\n%s", o[i], v[o[i]]; if (!n) print "no dnsmasq section" }' dhcp.uci
	else
		echo "no /etc/config/dhcp"
	fi

	section "dnsmasq processes"
	_net_running '^dnsmasq$'

	section "dnsmasq generated and extra config (upstreams, overrides, includes)"
	_any=0
	_net_dnsmasq_files >dnsmasq.files
	while IFS= read -r _f; do
		_any=1
		_c=$(grep -c -v -E '^[[:space:]]*(#|$)' "$_f" 2>/dev/null)
		echo "$_f ($_c settings):"
		rd "$_f" | grep -E '^[[:space:]]*(server|address|local|conf-dir|conf-file|addn-hosts|resolv-file|servers-file|port|no-resolv|ipset|nftset|dhcp-script|cname|host-record)[=[:space:]]' | head -n 60 | sed 's/^/  /'
	done <dnsmasq.files
	[ "$_any" = 1 ] || echo "none found (/var/etc/dnsmasq.conf*, /etc/dnsmasq.conf, /tmp/dnsmasq.d)"

	section "Hosts files"
	echo "/etc/hosts:"
	rd /etc/hosts | grep -v -E '^[[:space:]]*(#|$)' | head -n 50 | sed 's/^/  /'
	for _f in /tmp/hosts/*; do
		[ -f "$_f" ] || continue
		echo "$_f ($(grep -c -v -E '^[[:space:]]*(#|$)' "$_f" 2>/dev/null) entries):"
		rd "$_f" | grep -v -E '^[[:space:]]*(#|$)' | head -n 20 | sed 's/^/  /'
	done
}

_net_dhcp() {
	_lf=$(lib_uci_dump dhcp | awk -F '\t' '$1 == "O" && $3 == "leasefile" { print $4; exit }')
	_lf=${_lf:-/tmp/dhcp.leases}
	section "DHCPv4 leases ($_lf)"
	if [ -f "$_lf" ]; then
		printf '%-19s %-17s %-15s %-24s %s\n' EXPIRES MAC IP HOSTNAME CLIENT_ID
		rd "$_lf" | head -n 500 | awk '{ e = ($1 == 0) ? "never" : strftime("%Y-%m-%d %H:%M:%S", $1); printf "%-19s %-17s %-15s %-24s %s\n", e, $2, $3, $4, $5; n++ } END { if (!n) print "none" }'
	else
		echo "no lease file"
	fi

	section "DHCPv6 leases (odhcpd)"
	if lib_ubus dhcp ipv6leases >v6.json && [ -s v6.json ]; then
		jsonfilter -i v6.json -e '@.device[*].leases[*]' 2>/dev/null >v6.txt
		while IFS= read -r _j; do
			(
				H='' U='' A='' V=''
				eval "$(jsonfilter -s "$_j" -e 'H=@.hostname' -e 'U=@.duid' -e 'A=@["ipv6-addr"][*].address' -e 'V=@.valid' 2>/dev/null)"
				printf '%-24s %-40s %s valid=%ss\n' "${H:--}" "$U" "$A" "$V"
			)
		done <v6.txt
		[ -s v6.txt ] || echo "none"
	elif [ -f /tmp/hosts/odhcpd ]; then
		echo "ubus not reachable; /tmp/hosts/odhcpd:"
		rd /tmp/hosts/odhcpd | grep -v '^#' | head -n 200
	else
		echo "not available (odhcpd not reachable over ubus, no /tmp/hosts/odhcpd)"
	fi

	section "DHCP servers and static leases (uci dhcp)"
	lib_uci_dump dhcp >dhcp.uci
	if [ -s dhcp.uci ]; then
		awk -F '\t' '
			$1 == "S" { t[$2] = $3; if ($3 == "dhcp" || $3 == "host") o[++n] = $2; next }
			$3 ~ /^(interface|start|limit|leasetime|ignore|dhcpv4|dhcpv6|ra|ndp|master|name|mac|ip|hostid|dns|tag)$/ { v[$2] = v[$2] " " $3 "=" $4 }
			END { for (i = 1; i <= n; i++) printf "%-6s %-14s%s\n", t[o[i]], o[i], v[o[i]]; if (!n) print "none" }' dhcp.uci
	else
		echo "no /etc/config/dhcp"
	fi
}

_net_wifi() {
	section "Wi-Fi status (iwinfo)"
	if have iwinfo; then
		run_timeout 15 iwinfo >iw.txt 2>&1
		if [ -s iw.txt ]; then
			redact <iw.txt
			echo "associated stations:"
			awk '/^[^ \t]/ && /ESSID/ { print $1 }' iw.txt | while IFS= read -r _w; do
				run_timeout 10 iwinfo "$_w" assoclist >as.txt 2>/dev/null
				printf '  %-14s %s\n' "$_w" "$(grep -c -E '^[0-9A-Fa-f]{2}(:[0-9A-Fa-f]{2}){5}' as.txt)"
			done
		else
			echo "no wireless interfaces"
		fi
	else
		echo "iwinfo: not available"
		_w=$(cd /sys/class/net 2>/dev/null && for _i in *; do [ -e "$_i/phy80211" ] && printf '%s ' "$_i"; done)
		echo "wireless devices in /sys/class/net: ${_w:-none}"
	fi

	section "Wi-Fi config (uci show wireless, secrets masked)"
	if have uci && uci -q show wireless >wl.txt 2>/dev/null; then
		redact <wl.txt
	elif [ -f /etc/config/wireless ]; then
		rd /etc/config/wireless | redact
	else
		echo "no /etc/config/wireless"
	fi

	section "hostapd and wpa_supplicant processes"
	_net_running '^(hostapd|wpa_supplicant|wpad)$'
}

_net_vpn() {
	section "WireGuard"
	if have wg; then
		# wg show prints private and preshared keys as "(hidden)"; redact as a second guard
		run_timeout 10 wg show all >wg.txt 2>&1
		if [ -s wg.txt ]; then redact <wg.txt; else echo "wg show: no WireGuard interfaces"; fi
	else
		echo "wg: not available"
	fi
	lib_uci_dump network >net.uci
	awk -F '\t' '
		$1 == "S" { t[$2] = $3; next }
		$3 == "proto" && $4 ~ /^(wireguard|wgclient|wgserver)$/ { wi[++n] = $2; pr[$2] = $4; next }
		{ if (($2, $3) in v) v[$2, $3] = v[$2, $3] "," $4; else v[$2, $3] = $4 }
		END {
			if (!n) { print "uci: no interface with proto wireguard, wgclient or wgserver"; exit }
			for (i = 1; i <= n; i++) {
				s = wi[i]; printf "uci interface %s (proto %s): listen_port=%s addresses=%s\n", s, pr[s], ((s, "listen_port") in v) ? v[s, "listen_port"] : "-", v[s, "addresses"]
				for (k in t) if (t[k] == "wireguard_" s)
					printf "  peer %s: description=%s endpoint=%s:%s allowed_ips=%s public_key=%s\n", k, v[k, "description"], v[k, "endpoint_host"], v[k, "endpoint_port"], v[k, "allowed_ips"], v[k, "public_key"]
			}
		}' net.uci

	section "OpenVPN"
	_net_running '^openvpn$'
	echo "config files:"
	_net_files /etc/openvpn /etc/config/openvpn /etc/config/ovpnclient /etc/config/ovpnserver
	lib_uci_dump openvpn | awk -F '\t' '$1 == "S" { o[++n] = $2; next } $3 ~ /^(enabled|config|remote|dev|proto|port)$/ { v[$2] = v[$2] " " $3 "=" $4 } END { for (i = 1; i <= n; i++) printf "uci openvpn %s:%s\n", o[i], v[o[i]] }'

	section "Tailscale"
	_net_running '^tailscaled?$'
	echo "config and state:"
	_net_files /etc/config/tailscale /etc/tailscale /var/lib/tailscale

	section "ZeroTier"
	_net_running '^zerotier-one$'
	echo "config and state:"
	_net_files /etc/config/zerotier /etc/zerotier /var/lib/zerotier-one

	section "Tunnel devices"
	_any=0
	for _i in /sys/class/net/*; do
		[ -e "$_i" ] || continue
		_t=$(sed -n 's/^DEVTYPE=//p' "$_i/uevent" 2>/dev/null)
		[ -e "$_i/tun_flags" ] && _t=tun/tap
		case $_t in wireguard | tun/tap | gre | gretap | ip6gre | ip6tnl | ipip | sit | vti | vti6 | l2tp | ppp | vxlan | geneve | erspan | ip6erspan | ip6gretap) ;; *) continue ;; esac
		_any=1
		printf '%-16s %-10s operstate=%s\n' "${_i##*/}" "$_t" "$(cat "$_i/operstate" 2>/dev/null)"
	done
	[ "$_any" = 1 ] || echo "none"
	echo "(gre0, gretap0, erspan0, ip6tnl0, sit0, tunl0, ip_vti0 and similar are fallback devices the kernel creates when the tunnel module loads)"
}

# ============================================================== connections
mcp_register connections <<'EOF'
{"name":"connections","title":"Connections and listeners","description":"Sockets from /proc (never netstat or ss): listening TCP and unbound or listening UDP/raw sockets with the owning process and pid, whether each listens on all addresses, loopback only or one address and which interface carries it; or established connections with both endpoints. Optionally Unix sockets with paths and owners, and the connection tracking table size with the top remote endpoints. Use it to see what the router exposes and who it talks to.","inputSchema":{"type":"object","properties":{"state":{"type":"string","enum":["listen","established","all"],"description":"listen (listening and unbound sockets), established (connections in any other state) or all. Default listen.","default":"listen"},"include_unix":{"type":"boolean","description":"Also list Unix domain sockets with path and owning process.","default":false},"resolve_interfaces":{"type":"boolean","description":"Name the interface that carries each listening address.","default":true},"conntrack":{"type":"boolean","description":"Also summarize /proc/net/nf_conntrack: top destinations and sources (capped at 25 each).","default":false},"max_results":{"type":"integer","description":"Maximum sockets listed per table. Default 500.","default":500,"minimum":1,"maximum":5000}},"additionalProperties":false},"annotations":{"readOnlyHint":true,"openWorldHint":false}}
EOF
tool_connections() {
	arg _state state listen
	case $_state in listen | established | all) ;; *) tool_error "state must be listen, established or all; got '$_state'"; return 1 ;; esac
	arg_int _max max_results 500 1 5000 || return 1
	lib_sockets >sockets.tsv
	: >addr.txt
	_res=0
	if arg_bool resolve_interfaces true; then
		_res=1
		_net_addr_map >addr.txt
	fi
	if [ "$_state" != established ]; then
		section "Listening and unbound sockets"
		RES=$_res MAXR=$_max awk -F '\t' '
		FILENAME == "addr.txt" { split($0, a, " "); if (a[1] in ifc) ifc[a[1]] = ifc[a[1]] "," a[2]; else ifc[a[1]] = a[2]; next }
		{
			listen = ($1 ~ /^tcp/ && $2 == "LISTEN") || ($1 !~ /^tcp/ && $2 == "UNCONN")
			if (!listen) next
			la = $3
			if (la == "0.0.0.0") scope = "all IPv4 addresses"
			else if (la == "::") scope = ($1 ~ /^tcp/ || $1 ~ /^udp/) ? "all addresses (IPv6, and IPv4 unless v6only)" : "all IPv6 addresses"
			else if (la ~ /^127\./ || la == "::1" || la ~ /^::ffff:127\./) scope = "loopback only"
			else {
				b = la; sub(/^::ffff:/, "", b)
				if (ENVIRON["RES"] != 1) scope = "this address"
				else if (b in ifc) scope = "interface " ifc[b]
				else scope = "address on no interface"
			}
			n++
			if (n <= ENVIRON["MAXR"]) row[n] = sprintf("%-5s %-7s %-39s %6s  %-44s %-7s %s", $1, $2, la, $4, scope, $8, $9)
			if (scope ~ /^all/) na++
		}
		END {
			printf "%d sockets, %d bound to all addresses%s\n", n, na, (ENVIRON["RES"] == 1 ? "" : " (interfaces not resolved)")
			printf "%-5s %-7s %-39s %6s  %-44s %-7s %s\n", "PROTO", "STATE", "LOCAL_ADDRESS", "PORT", "REACHABLE_ON", "PID", "PROCESS"
			for (i = 1; i <= n && i <= ENVIRON["MAXR"]; i++) print row[i]
			if (n > ENVIRON["MAXR"]) printf "... %d more not shown (max_results)\n", n - ENVIRON["MAXR"]
			print "(raw sockets: PORT is the IP protocol number, 1 ICMP, 58 ICMPv6, 255 any. PID - means a kernel socket or one whose owner is gone. Reachability ignores the firewall: see firewall.)"
		}' addr.txt sockets.tsv
	fi
	if [ "$_state" != listen ]; then
		section "Connections"
		MAXR=$_max awk -F '\t' '
		{
			if (($1 ~ /^tcp/ && $2 == "LISTEN") || ($1 !~ /^tcp/ && $2 == "UNCONN")) next
			n++; cnt[$2]++
			if (n <= ENVIRON["MAXR"]) row[n] = sprintf("%-5s %-11s %-45s %-45s %-7s %s", $1, $2, $3 ":" $4, $5 ":" $6, $8, $9)
		}
		END {
			s = ""; for (k in cnt) s = s " " k "=" cnt[k]
			printf "%d sockets:%s\n", n, s
			printf "%-5s %-11s %-45s %-45s %-7s %s\n", "PROTO", "STATE", "LOCAL", "REMOTE", "PID", "PROCESS"
			for (i = 1; i <= n && i <= ENVIRON["MAXR"]; i++) print row[i]
			if (n > ENVIRON["MAXR"]) printf "... %d more not shown (max_results)\n", n - ENVIRON["MAXR"]
		}' sockets.tsv
	fi
	if arg_bool include_unix false; then
		section "Unix domain sockets"
		lib_fd_inodes >inodes.txt
		cat /proc/net/unix >unix.txt 2>/dev/null
		MAXR=$_max awk '
		FILENAME == "inodes.txt" { owner[$1] = $2; next }
		FNR == 1 { next }
		{
			type = ($5 == "0001") ? "stream" : ($5 == "0002") ? "dgram" : ($5 == "0005") ? "seqpacket" : $5
			lst = (substr($4, length($4) - 4, 1) == "1") ? "LISTEN" : ($6 == "03" ? "CONNECTED" : "UNCONN")
			path = $8; for (i = 9; i <= NF; i++) path = path " " $i
			if (path == "") { unnamed++; next }
			p = ($7 in owner) ? owner[$7] : "-"
			c = "-"; if (p != "-") { f = "/proc/" p "/comm"; if ((getline c < f) <= 0) c = "-"; close(f) }
			n++
			if (n <= ENVIRON["MAXR"]) row[n] = sprintf("%-9s %-9s %-7s %-16s %s", type, lst, p, c, path)
		}
		END {
			printf "%d named sockets, %d unnamed (not listed)\n", n, unnamed
			printf "%-9s %-9s %-7s %-16s %s\n", "TYPE", "STATE", "PID", "PROCESS", "PATH (@ = abstract)"
			for (i = 1; i <= n && i <= ENVIRON["MAXR"]; i++) print row[i]
			if (n > ENVIRON["MAXR"]) printf "... %d more not shown (max_results)\n", n - ENVIRON["MAXR"]
		}' inodes.txt unix.txt
	fi

	section "Connection tracking"
	_c=$(cat /proc/sys/net/netfilter/nf_conntrack_count 2>/dev/null)
	_m=$(cat /proc/sys/net/netfilter/nf_conntrack_max 2>/dev/null)
	if [ -n "$_c" ]; then echo "entries $_c of max ${_m:-?}"; else echo "nf_conntrack: not available"; fi
	if arg_bool conntrack false; then
		if [ -r /proc/net/nf_conntrack ]; then
			awk '
			{
				pr = ""; src = ""; dst = ""; dport = ""
				for (i = 1; i <= NF; i++) {
					if (pr == "" && $i ~ /^(tcp|udp|icmp|icmpv6|udplite|sctp|gre|unknown)$/) pr = $i
					if (src == "" && $i ~ /^src=/) src = substr($i, 5)
					else if (dst == "" && $i ~ /^dst=/) dst = substr($i, 5)
					else if (dport == "" && $i ~ /^dport=/) dport = substr($i, 7)
				}
				n++; d[dst "" (dport != "" ? ":" dport : "") "/" pr]++; s[src]++
			}
			function top(a, title,   k, best, bk, i) {
				print title
				for (i = 1; i <= 25; i++) {
					best = 0; bk = ""
					for (k in a) if (a[k] > best) { best = a[k]; bk = k }
					if (bk == "") break
					printf "  %6d  %s\n", best, bk; delete a[bk]
				}
			}
			END {
				printf "%d entries read from /proc/net/nf_conntrack (original direction)\n", n
				if (!n) exit
				top(d, "top destinations (address:port/protocol):")
				top(s, "top sources:")
			}' /proc/net/nf_conntrack
		else
			echo "/proc/net/nf_conntrack: not available"
		fi
	fi
	return 0
}

# ============================================================== firewall
mcp_register firewall <<'EOF'
{"name":"firewall","title":"Firewall","description":"The firewall in readable form from uci (zones with input/output/forward policy and their networks, forwardings, rules that accept input from the WAN zone, port forwards, includes and custom rule files such as /etc/firewall.user and /etc/nftables.d), UPnP/NAT-PMP state and leases, and the active kernel ruleset (nft list ruleset on fw4, iptables-save on fw3), capped unless raw=true. Use it to see what is reachable from outside and what was opened.","inputSchema":{"type":"object","properties":{"raw":{"type":"boolean","description":"Print the complete active ruleset instead of the first 300 lines.","default":false}},"additionalProperties":false},"annotations":{"readOnlyHint":true,"openWorldHint":false}}
EOF
tool_firewall() {
	_cap=300
	arg_bool raw false && _cap=0
	_fw=none
	[ -x /sbin/fw3 ] && _fw="fw3 (iptables)"
	[ -x /sbin/fw4 ] && _fw="fw4 (nftables)"
	_romok=0
	lib_rom_ok && _romok=1
	echo "firewall: $_fw"

	lib_uci_dump firewall >fw.uci
	if [ -s fw.uci ]; then
		awk -F '\t' '
		$1 == "S" { t[$2] = $3; o[++n] = $2; next }
		{ k = $2 SUBSEP $3; if (k in v) v[k] = v[k] " " $4; else v[k] = $4 }
		function g(s, opt, d) { return ((s, opt) in v) ? v[s, opt] : d }
		END {
			print "\n== Defaults"
			for (i = 1; i <= n; i++) if (t[o[i]] == "defaults") printf "input=%s output=%s forward=%s syn_flood=%s drop_invalid=%s flow_offloading=%s\n", g(o[i], "input", "-"), g(o[i], "output", "-"), g(o[i], "forward", "-"), g(o[i], "syn_flood", "-"), g(o[i], "drop_invalid", "-"), g(o[i], "flow_offloading", "-")
			print "\n== Zones"
			printf "%-12s %-8s %-8s %-8s %-5s %s\n", "ZONE", "INPUT", "OUTPUT", "FORWARD", "MASQ", "NETWORKS / DEVICES / SUBNETS"
			for (i = 1; i <= n; i++) {
				s = o[i]; if (t[s] != "zone") continue
				nm = g(s, "name", s)
				if (nm ~ /wan/ || g(s, "masq", "0") == "1" || g(s, "network", "") ~ /(^| )wan/) wan[nm] = 1
				printf "%-12s %-8s %-8s %-8s %-5s %s%s%s\n", nm, g(s, "input", "-"), g(s, "output", "-"), g(s, "forward", "-"), g(s, "masq", "0"), g(s, "network", "-"), (((s, "device") in v) ? " dev:" v[s, "device"] : ""), (((s, "subnet") in v) ? " subnet:" v[s, "subnet"] : "")
			}
			w = ""; for (k in wan) w = w " " k
			printf "WAN zones (named wan, masquerading, or holding network wan):%s\n", (w == "" ? " none" : w)
			print "\n== Forwardings"
			c = 0
			for (i = 1; i <= n; i++) { s = o[i]; if (t[s] != "forwarding") continue; c++; printf "%s -> %s%s\n", g(s, "src", "?"), g(s, "dest", "?"), (g(s, "enabled", "1") == "0" ? " (disabled)" : "") }
			if (!c) print "none"
			print "\n== Rules accepting input from a WAN zone"
			c = 0
			for (i = 1; i <= n; i++) {
				s = o[i]; if (t[s] != "rule") continue
				if (!(g(s, "src", "") in wan) || g(s, "dest", "") != "" || g(s, "target", "") != "ACCEPT") continue
				c++
				printf "%-28s proto=%s dest_port=%s src_ip=%s family=%s icmp_type=%s%s\n", g(s, "name", s), g(s, "proto", "any"), g(s, "dest_port", "any"), g(s, "src_ip", "any"), g(s, "family", "any"), g(s, "icmp_type", "-"), (g(s, "enabled", "1") == "0" ? " (disabled)" : "")
			}
			if (!c) print "none"
			print "\n== Port forwards (redirects)"
			c = 0
			for (i = 1; i <= n; i++) {
				s = o[i]; if (t[s] != "redirect") continue
				c++
				printf "%-28s %s:%s/%s -> %s:%s target=%s%s\n", g(s, "name", s), g(s, "src", "?"), g(s, "src_dport", "any"), g(s, "proto", "tcp udp"), g(s, "dest_ip", "?"), g(s, "dest_port", g(s, "src_dport", "same")), g(s, "target", "DNAT"), (g(s, "enabled", "1") == "0" ? " (disabled)" : "")
			}
			if (!c) print "none"
			print "\n== Includes (uci)"
			c = 0
			for (i = 1; i <= n; i++) {
				s = o[i]; if (t[s] != "include") continue
				c++
				printf "%-20s path=%s type=%s position=%s reload=%s%s\n", s, g(s, "path", "-"), g(s, "type", "script"), g(s, "position", "-"), g(s, "reload", "-"), (g(s, "enabled", "1") == "0" ? " (disabled)" : "")
			}
			if (!c) print "none"
			print "\n== All rules"
			c = 0
			for (i = 1; i <= n; i++) {
				s = o[i]; if (t[s] != "rule") continue
				c++
				printf "%-28s %s -> %s proto=%s dest_port=%s target=%s%s\n", g(s, "name", s), g(s, "src", "(router)"), g(s, "dest", "(router)"), g(s, "proto", "any"), g(s, "dest_port", "any"), g(s, "target", "-"), (g(s, "enabled", "1") == "0" ? " (disabled)" : "")
			}
			if (!c) print "none"
		}' fw.uci
	else
		echo "no /etc/config/firewall"
	fi

	section "UPnP / NAT-PMP"
	if [ -f /etc/config/upnpd ]; then
		lib_uci_dump upnpd | awk -F '\t' '$3 ~ /^(enabled|enable_upnp|enable_natpmp|secure_mode|external_iface|internal_iface|upnp_lease_file|log_output)$/ { printf "%s.%s=%s\n", $2, $3, $4 }'
	else
		echo "no /etc/config/upnpd (miniupnpd not installed)"
	fi
	_net_running '^miniupnpd$'
	_lf=$(lib_uci_dump upnpd | awk -F '\t' '$3 == "upnp_lease_file" { print $4; exit }')
	for _f in ${_lf:-/var/run/miniupnpd.leases} /var/upnp.leases; do
		[ -f "$_f" ] || continue
		echo "leases ($_f, PROTO:EXT_PORT:INT_IP:INT_PORT:EXPIRY:DESCRIPTION):"
		rd "$_f" | head -n 100 | sed 's/^/  /'
		break
	done

	section "Custom rule files"
	for _f in /etc/firewall.user /etc/firewall.d; do
		[ -e "$_f" ] || continue
		_n=
		[ "$_romok" = 1 ] && ! in_rom "$_f" && _n="   !! not in firmware image"
		if [ -f "$_f" ]; then
			echo "$_f ($(grep -c -v -E '^[[:space:]]*(#|$)' "$_f" 2>/dev/null) non-comment lines)$_n"
			rd "$_f" | grep -v -E '^[[:space:]]*(#|$)' | head -n 50 | sed 's/^/  /'
		fi
	done
	lib_uci_dump firewall | awk -F '\t' '$3 == "path" { print $4 }' | while IFS= read -r _f; do
		if [ -f "$_f" ]; then
			_n=
			[ "$_romok" = 1 ] && ! in_rom "$_f" && _n="   !! not in firmware image"
			echo "$_f (uci include, $(grep -c -v -E '^[[:space:]]*(#|$)' "$_f" 2>/dev/null) non-comment lines)$_n"
			rd "$_f" | grep -v -E '^[[:space:]]*(#|$)' | head -n 30 | sed 's/^/  /'
		else
			echo "$_f (uci include): missing"
		fi
	done
	echo "/etc/nftables.d and /usr/share/nftables.d (fw4 includes these automatically):"
	_net_files /etc/nftables.d /usr/share/nftables.d

	section "Active ruleset"
	_any=0
	if have nft; then
		_any=1
		echo "nft list ruleset:"
		run_timeout 20 nft list ruleset >rs.txt 2>&1
		_rc=$?
		_net_ruleset "$_rc" "$_cap"
	fi
	for _c in iptables-save ip6tables-save; do
		have "$_c" || continue
		_any=1
		# with legacy iptables, *-save loads the table modules it asks for: only call it
		# when the kernel already has tables
		case $_c in iptables-save) _tn=/proc/net/ip_tables_names _tf=iptables ;; *) _tn=/proc/net/ip6_tables_names _tf=ip6tables ;; esac
		if ! grep -q . "$_tn" 2>/dev/null; then
			echo "$_c: no $_tf tables loaded ($_tn is empty or missing)"
			continue
		fi
		echo "$_c:"
		run_timeout 20 "$_c" >rs.txt 2>&1
		_rc=$?
		_net_ruleset "$_rc" "$_cap"
	done
	[ "$_any" = 1 ] || echo "nft, iptables-save: not available"
	return 0
}

_net_ruleset() { # RC CAP; reads rs.txt
	if [ "$1" != 0 ]; then
		echo "  cannot read the ruleset (exit $1): $(head -n 1 rs.txt)"
		return
	fi
	_t=$(wc -l <rs.txt)
	if [ "$_t" = 0 ]; then
		echo "  (empty: no rules loaded, or no permission to read them)"
	elif [ "$2" = 0 ] || [ "$_t" -le "$2" ]; then
		cat rs.txt
	else
		head -n "$2" rs.txt
		echo "... $_t lines in total, first $2 shown; raw=true prints all"
	fi
}
