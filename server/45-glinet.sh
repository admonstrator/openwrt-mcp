# GL.iNet firmware: the read-only tool glinet, and the gl_* readers that the audit's
# GL.iNet checks (50-audit.sh) share.
#
# Everything comes from uci, files and /proc. The GL web API is never called, not even
# its get methods: some of them have side effects (tailscale.get_auth_url restarts
# Tailscale, ddns.get_status goes to the network; decision 2.5). /proc/gl-hw-info is
# read below MCP_PROC (default /proc), so the tests can use a fixture; its device_key,
# device_cert and device_sn are never read.

# shellcheck disable=SC2016  # awk programs are single-quoted on purpose

# awk program: an OpenWrt config file to the lib_uci_dump format (S section type / O
# section option value). The same parser as lib_uci_dump's fallback, for files that are
# not in /etc/config (the firmware image's copy).
GL_AWK_CFG='
function vals(s,   i, c, q, cur, st) {
	nv = 0; cur = ""; q = ""; st = 0
	for (i = 1; i <= length(s); i++) {
		c = substr(s, i, 1)
		if (q != "") { if (c == q) q = ""; else cur = cur c; continue }
		if (c == "\047" || c == "\"") { q = c; st = 1; continue }
		if (c == "\\" && i < length(s)) { cur = cur substr(s, i + 1, 1); i++; st = 1; continue }
		if (c == " " || c == "\t") { if (st) { v[++nv] = cur; cur = ""; st = 0 } continue }
		if (c == "#" && !st) break
		cur = cur c; st = 1
	}
	if (st) v[++nv] = cur
}
{
	vals($0)
	if (nv < 2) next
	if (v[1] == "config") {
		t = v[2]
		if (nv >= 3) sec = v[3]; else sec = "@" t "[" (0 + cnt[t]) "]"
		cnt[t]++
		printf "S\t%s\t%s\n", sec, t
	} else if ((v[1] == "option" || v[1] == "list") && sec != "" && nv >= 3) {
		printf "O\t%s\t%s\t%s\n", sec, v[2], v[3]
	}
}'

# gl_init: a fresh scratch directory for the uci dumps of one call.
gl_init() {
	GLD=$MCP_TMP/gl
	rm -rf "$GLD"
	mkdir -p "$GLD"
	GL_HW=${MCP_PROC:-/proc}/gl-hw-info
}

# gl_is: exit status 0 on GL.iNet firmware (4.x keeps its version in /etc/glversion).
gl_is() { [ -f /etc/glversion ]; }

# gl_load PKG: the uci package as lib_uci_dump prints it, in $GLD/PKG.u; status 1 when
# the package is not installed (no /etc/config/PKG).
gl_load() {
	[ -f "/etc/config/$1" ] || return 1
	[ -f "$GLD/$1.u" ] || lib_uci_dump "$1" >"$GLD/$1.u" 2>/dev/null
	return 0
}

# gl_rom PKG: the firmware image's /etc/config/PKG in the same form, in $GLD/PKG.rom;
# status 1 when there is no usable image or the image has no such file.
gl_rom() {
	lib_rom_ok || return 1
	_glr=$(rom_path "/etc/config/$1")
	[ -f "$_glr" ] || return 1
	[ -f "$GLD/$1.rom" ] || rd "$_glr" | awk "$GL_AWK_CFG" >"$GLD/$1.rom"
	return 0
}

# gl_get PKG SECTION OPTION [rom]: the option's value (list elements joined by spaces);
# status 1 when it is unset or empty, or the package is missing. With "rom", from the
# image.
gl_get() {
	if [ "${4-}" = rom ]; then gl_rom "$1" || return 1; _glf=$GLD/$1.rom; else gl_load "$1" || return 1; _glf=$GLD/$1.u; fi
	awk -F'\t' -v s="$2" -v o="$3" '$1 == "O" && $2 == s && $3 == o { if (n++) v = v " "; v = v $4 } END { if (v == "") exit 1; print v }' "$_glf"
}

# gl_sec PKG TYPE: the name of the first section of TYPE (@type[0] when anonymous).
gl_sec() {
	gl_load "$1" || return 1
	awk -F'\t' -v t="$2" '$1 == "S" && $3 == t { print $2; f = 1; exit } END { exit !f }' "$GLD/$1.u"
}

# gl_show PKG SECTION_ERE OPTION_ERE [MAX]: the matching options as "uci show" prints
# them (PKG.section.option='value'), redacted and indented. A section matches by name
# or by type; both EREs are anchored. Prints nothing when nothing matches.
gl_show() {
	gl_load "$1" || return 1
	awk -F'\t' -v p="$1" -v sre="^($2)\$" -v ore="^($3)\$" -v max="${4:-40}" '
	$1 == "S" { ty[$2] = $3; next }
	$1 == "O" && ($2 ~ sre || ty[$2] ~ sre) && $3 ~ ore {
		k = p "." $2 "." $3
		if (!(k in v)) { ord[++n] = k; v[k] = "\047" $4 "\047" } else v[k] = v[k] " \047" $4 "\047"
	}
	END {
		for (i = 1; i <= n && i <= max; i++) print ord[i] "=" v[ord[i]]
		if (n > max) print "(" (n - max) " more options; the uci tool shows the package)"
	}' "$GLD/$1.u" | redact | sed 's/^/  /'
}

# gl_onoff VALUE: a uci boolean in words.
gl_onoff() {
	case $1 in
	1 | on | yes | true | enabled) echo on ;;
	0 | off | no | false | disabled) echo off ;;
	'') echo "not set" ;;
	*) printf "'%s'\n" "$1" ;;
	esac
}

# gl_hw NAME: the first line of /proc/gl-hw-info/NAME (model, country_code, device_ddns,
# ...); status 1 when it is missing. Never the key, the certificate or the serial.
gl_hw() {
	case $1 in device_key | device_cert | device_sn | */*) return 1 ;; esac
	_glh=$(rd "$GL_HW/$1" 2>/dev/null | tr -d '\000\r' | head -n 1)
	[ -n "$_glh" ] || return 1
	printf '%s\n' "$_glh"
}

# gl_mask_t: filter for command lines. rtty takes its authorization token as "-t TOKEN",
# a single-letter option that redact leaves alone (-p 22 is a port elsewhere).
gl_mask_t() {
	if [ "$MCP_REDACT" != 1 ]; then cat; return; fi
	awk '{
		n = split($0, a, " "); out = ""
		for (i = 1; i <= n; i++) {
			if (m) { a[i] = "<redacted>"; m = 0 }
			else if (a[i] == "-t") m = 1
			else if (a[i] ~ /^-t./) a[i] = "-t<redacted>"
			if (i > 1) out = out " "
			out = out a[i]
		}
		print out
	}'
}

# gl_procs ERE: "pid<TAB>comm<TAB>cmdline" of the matching processes, the command line
# masked (gl_mask_t) and redacted.
gl_procs() {
	fo_procs_by_comm "$1" | while IFS="$FX_TAB" read -r _glp _glc _gll; do
		printf '%s\t%s\t%s\n' "$_glp" "$_glc" "$(printf '%s\n' "$_gll" | gl_mask_t | redact | cut -c1-300)"
	done
}

# gl_proc_line LABEL ERE: "  LABEL process: running, pid N (comm): cmdline" or "not running".
gl_proc_line() {
	gl_procs "$2" >"$GLD/procs"
	if [ -s "$GLD/procs" ]; then
		while IFS="$FX_TAB" read -r _glp _glc _gll; do
			printf '  %s process: running, pid %s (%s): %s\n' "$1" "$_glp" "$_glc" "${_gll:-(no command line)}"
		done <"$GLD/procs"
	else
		printf '  %s process: not running\n' "$1"
	fi
}

# gl_noauth: the web API methods that oui-httpd runs without a session, one line each:
#   object  method  mark
# mark: image (the image's /etc/config/oui-httpd lists it too), ADDED (it does not), -
# (no image to compare with). Sections of type no-auth-methods, object from their
# "object" option (else the section name), methods from the list "method".
gl_noauth() {
	gl_load oui-httpd || return 1
	_glcmp=0
	gl_rom oui-httpd && _glcmp=1
	if [ "$_glcmp" = 1 ]; then set -- "$GLD/oui-httpd.rom" "$GLD/oui-httpd.u"; else set -- "$GLD/oui-httpd.u"; fi
	awk -F'\t' -v cmp="$_glcmp" -v live="$GLD/oui-httpd.u" '
	{ f = (FILENAME == live) ? "L" : "R" }
	$1 == "S" { if ($3 ~ /^no[-_]auth/ || $2 ~ /^no[-_]auth/) na[f, $2] = 1; if (f == "L") ord[++n] = $2; next }
	$1 == "O" && $3 == "object" { ob[f, $2] = $4; next }
	$1 == "O" && $3 == "method" { k = ++nm[f, $2]; m[f, $2, k] = $4; next }
	END {
		for (key in na) {
			split(key, kk, SUBSEP); if (kk[1] != "R") continue
			s = kk[2]; o = ((("R", s) in ob) ? ob["R", s] : s)
			for (i = 1; i <= nm["R", s]; i++) img[o, m["R", s, i]] = 1
		}
		for (j = 1; j <= n; j++) {
			s = ord[j]; if (!(("L", s) in na)) continue
			o = ((("L", s) in ob) ? ob["L", s] : s)
			for (i = 1; i <= nm["L", s]; i++) {
				x = m["L", s, i]
				print o "\t" x "\t" ((cmp != 1) ? "-" : (((o, x) in img) ? "image" : "ADDED"))
			}
		}
	}' "$@"
}

# gl_accounts: "username<TAB>acl" for every row of table account in /etc/oui/oui.db, the
# web interface's extra admin accounts (root logs in with the system password). The
# database is copied below MCP_TMP first and only the copy is opened, read-only.
# Status 2: sqlite3 not available; 3: no /etc/oui/oui.db; 4: the query failed (its
# message in $GLD/acct.err).
gl_accounts() {
	[ -f /etc/oui/oui.db ] || return 3
	have sqlite3 || return 2
	rd /etc/oui/oui.db >"$GLD/oui.db" || return 3
	[ -f /etc/oui/oui.db-wal ] && rd /etc/oui/oui.db-wal >"$GLD/oui.db-wal"
	run_timeout 10 sqlite3 -readonly -batch -noheader -separator "$FX_TAB" "$GLD/oui.db" \
		'SELECT username, acl FROM account;' >"$GLD/acct" 2>"$GLD/acct.err" || return 4
	tr -d '\r' <"$GLD/acct"
}

# gl_fw admin|share: the firewall rules and redirects GL.iNet writes for WAN access to
# the router itself and DMZ (admin), or for the WAN side of file sharing (share), one
# line each, redacted. Matched by section name or the "name" option.
gl_fw() {
	gl_load firewall || return 1
	awk -F'\t' -v mode="$1" '
	$1 == "S" && ($3 == "rule" || $3 == "redirect") { ty[$2] = $3; ord[++n] = $2; next }
	# busybox awk creates v[k] before it tests "k in v" on the right side: test first
	$1 == "O" && ($2 in ty) { k = $2 SUBSEP $3; y = (k in v) ? v[k] " " $4 : $4; v[k] = y }
	function g(s, o) { return ((s, o) in v) ? v[s, o] : "-" }
	END {
		share = "^(sambasharewan|glnas_ser|webdav_wan)"
		admin = "^((ping|http|https|ssh)_wan6?$|GL[-_]|wan[-_]access)|DMZ"
		for (i = 1; i <= n; i++) {
			s = ord[i]; nm = g(s, "name")
			sh = (s ~ share || nm ~ share); ad = !sh && (s ~ admin || nm ~ admin)
			if (!((mode == "share" && sh) || (mode == "admin" && ad))) continue
			x = "firewall." s " " ty[s] " \047" nm "\047: src " g(s, "src")
			if (ty[s] == "rule") x = x ", proto " g(s, "proto") ", dest_port " g(s, "dest_port") ", target " g(s, "target")
			else x = x ", src_dport " g(s, "src_dport") " -> " g(s, "dest_ip") ":" g(s, "dest_port")
			if (g(s, "src_ip") != "-") x = x ", src_ip " g(s, "src_ip")
			if (g(s, "ipset") != "-") x = x ", ipset " g(s, "ipset")
			x = x ", " ((g(s, "enabled") == "0") ? "DISABLED" : "enabled")
			if (++c <= 40) print x
		}
		if (!c) print "none"
		if (c > 40) print "(" (c - 40) " more; the firewall tool lists them)"
	}' "$GLD/firewall.u" | redact | sed 's/^/  /'
}

# gl_missing THING PKG: the one line for a package that is not installed.
gl_missing() { printf '%s (%s): not installed (no /etc/config/%s)\n' "$1" "$2" "$2"; }

mcp_register glinet <<'EOF'
{"name":"glinet","title":"GL.iNet firmware state","description":"On GL.iNet firmware (4.x), shows what the vendor firmware has switched on that reaches the router from outside, reports to outside or controls access to it, most important first: remote management (GoodCloud binding, the rtty remote terminal, AstroWarp, GL DDNS), admin access (oui-httpd options compared with the firmware image, web API methods callable without login, nginx ports, extra web admin accounts, WAN access whitelist, GL firewall rules for WAN access and DMZ), VPN servers and mesh VPNs (WireGuard and OpenVPN servers, Tailscale, ZeroTier, Tor, site-to-site), sharing (NAS, Samba, WebDAV, DLNA) and firmware and update settings. Read from uci, files and /proc only; the GL web API is never called. Secrets are masked, tokens are only reported as present. On other firmware it says so in one line. Use it on a GL.iNet router before the generic uci and firewall tools; the audit reports the risky parts as findings.","inputSchema":{"type":"object","properties":{},"additionalProperties":false},"annotations":{"readOnlyHint":true,"openWorldHint":false}}
EOF
tool_glinet() {
	gl_init
	if ! gl_is; then
		echo "Not GL.iNet firmware: /etc/glversion (the version file of GL.iNet firmware 4.x) does not exist. The uci, persistence, users_auth and audit tools cover stock OpenWrt."
		return 0
	fi
	_glv=$(rd /etc/glversion | head -n 1)
	_glt=$(rd /etc/version.type 2>/dev/null | head -n 1)
	printf 'GL.iNet firmware %s%s, model %s, mode %s\n' "$_glv" "${_glt:+ ($_glt)}" "$(gl_hw model || echo unknown)" \
		"$(gl_get glconfig general mode || echo unknown)" | redact
	echo "Read from uci, files and /proc only; the GL web API is never called (some of its get methods have side effects). Values are redacted as everywhere; device_key, device_cert and device_sn are never read."

	section "Remote management (reaches the router from outside, past the firewall)"
	_glce=
	if _glcs=$(gl_sec gl-cloud cloud); then
		_glce=$(gl_get gl-cloud "$_glcs" enable)
		printf 'GoodCloud (gl-cloud): %s\n' "$(gl_onoff "$_glce")"
		gl_show gl-cloud cloud 'enable|server|reset_uuid|username|email|bindtime|bindtype'
		if gl_get gl-cloud "$_glcs" username >/dev/null || gl_get gl-cloud "$_glcs" email >/dev/null ||
			gl_get gl-cloud "$_glcs" bindtime >/dev/null; then
			echo "  bound to a GoodCloud account: yes (account shown above); the account can manage this router from the cloud"
		else
			echo "  bound to a GoodCloud account: no (no username, email or bindtime)"
		fi
		if gl_get gl-cloud "$_glcs" token >/dev/null; then echo "  token: present (never shown)"; else echo "  token: none"; fi
	elif gl_load gl-cloud; then
		echo "GoodCloud (gl-cloud): installed, no section of type cloud"
	else
		gl_missing GoodCloud gl-cloud
	fi
	gl_proc_line gl-cloud 'gl[-_]?cloud.*'
	_glrs=0
	_glrw=0
	if gl_load rtty; then
		_glrs=$(gl_get rtty general ssh_en)
		_glrw=$(gl_get rtty general web_en)
		printf 'Remote terminal (rtty): SSH %s, web %s\n' "$(gl_onoff "$_glrs")" "$(gl_onoff "$_glrw")"
		gl_show rtty '.*' '.*' 15
	else
		gl_missing "Remote terminal" rtty
	fi
	gl_proc_line rtty rtty
	if [ "$_glce" = 1 ] && { [ "$_glrs" = 1 ] || [ "$_glrw" = 1 ]; }; then
		echo "  !! GoodCloud is on and rtty allows SSH or web access: the cloud account can open a root shell or the web interface through GL's relay, past the firewall"
	fi
	if gl_load mptun; then
		printf 'AstroWarp / SD-WAN (mptun): %s\n' "$(gl_onoff "$(gl_get mptun global enable)")"
		gl_show mptun global '.*' 10
	else
		gl_missing "AstroWarp / SD-WAN" mptun
	fi
	if gl_load gl_ddns; then
		echo "GL DDNS (gl_ddns):"
		gl_show gl_ddns '.*' 'enable|enabled|enabled_ssh|http_port|https_port|domain|interface|service_name' 20
	else
		gl_missing "GL DDNS" gl_ddns
	fi
	if _gld=$(gl_hw device_ddns); then
		printf '  device DDNS name: %s (%s/device_ddns)\n' "$_gld" "$GL_HW"
	else
		printf '  device DDNS name: none (%s/device_ddns not readable)\n' "$GL_HW"
	fi

	section "Admin access (web interface and API, console, WAN access to the router)"
	if gl_load oui-httpd; then
		if gl_rom oui-httpd; then
			echo "oui-httpd main options (GL's web server), with the image's value where it differs:"
			_glrf=$GLD/oui-httpd.rom
		else
			echo "oui-httpd main options (the image at $MCP_ROM has no /etc/config/oui-httpd: not compared):"
			_glrf=/dev/null
		fi
		FX_R="$_glrf" awk -F'\t' '
			FILENAME == ENVIRON["FX_R"] { if ($1 == "O" && $2 == "main") { y = ($3 in r) ? r[$3] " " $4 : $4; r[$3] = y } next }
			$1 == "O" && $2 == "main" { if (!($3 in l)) ord[++n] = $3; y = ($3 in l) ? l[$3] " " $4 : $4; l[$3] = y }
			END {
				img = (ENVIRON["FX_R"] != "/dev/null")
				for (i = 1; i <= n; i++) {
					o = ord[i]; x = "oui-httpd.main." o "=\047" l[o] "\047"
					if (img && !(o in r)) x = x "  (image: unset)"
					else if (img && r[o] != l[o]) x = x "  (image: \047" r[o] "\047)"
					print x
				}
				if (img) for (o in r) if (!(o in l)) print "oui-httpd.main." o "=\047\047  (unset here; image: \047" r[o] "\047)"
			}' "$_glrf" "$GLD/oui-httpd.u" | redact | sed 's/^/  /'
		_glcd=$(gl_get oui-httpd main console_disabled)
		if [ "$_glcd" = 1 ]; then
			echo "  console_disabled 1: the serial console offers no login"
		else
			printf '  console_disabled %s: gl-ngx-session links /bin/login to busybox, so the serial console asks for a login (root and its password)\n' "${_glcd:-unset}"
		fi
		echo "web API methods callable without login (no-auth-methods; [image] as shipped, [ADDED] not in the image's oui-httpd, [-] not compared):"
		gl_noauth >"$GLD/noauth"
		if [ -s "$GLD/noauth" ]; then
			awk -F'\t' '
				# ADDED first, so that a cap never hides one; at most 60 methods per
				# object and 40 objects
				{
					k = ($3 == "ADDED") ? 0 : 1
					if (!(($1, k) in c)) { ord[++n] = $1 SUBSEP k; m[$1, k] = "" }
					cc = ++c[$1, k]; sep = (cc > 1) ? ", " : ""
					if (cc <= 60) m[$1, k] = m[$1, k] sep $2 " [" $3 "]"
					else if (cc == 61) m[$1, k] = m[$1, k] ", ..."
				}
				END {
					for (k = 0; k <= 1; k++) for (i = 1; i <= n; i++) {
						split(ord[i], o, SUBSEP); if (o[2] != k) continue
						if (++shown > 40) break
						x = (c[o[1], k] > 60) ? " (" c[o[1], k] " methods)" : ""
						print "  " o[1] ": " m[o[1], k] x
					}
					if (shown > 40) print "  (more objects; read_file /etc/config/oui-httpd)"
				}' "$GLD/noauth"
		else
			echo "  none"
		fi
	else
		gl_missing "GL web server" oui-httpd
	fi
	if [ -f /etc/nginx/conf.d/gl.conf ]; then
		echo "nginx listen lines (/etc/nginx/conf.d/gl.conf):"
		rd /etc/nginx/conf.d/gl.conf | grep -E '^[[:space:]]*listen[[:space:]]' | sed 's/^[[:space:]]*//' | head -n 20 | redact | sed 's/^/  /'
	else
		echo "nginx: no /etc/nginx/conf.d/gl.conf"
	fi
	gl_accounts >"$GLD/acct.l"
	case $? in
	0)
		echo "web admin accounts (/etc/oui/oui.db, table account; root logs in with the system password):"
		if [ -s "$GLD/acct.l" ]; then
			awk -F'\t' '{ printf "  %s (acl %s)%s\n", $1, ($2 == "") ? "-" : $2, ($1 == "root") ? "" : "  <- an extra admin of the web interface" }' "$GLD/acct.l" | head -n 30
		else
			echo "  none"
		fi
		;;
	2) echo "web admin accounts: sqlite3: not available, /etc/oui/oui.db cannot be read" ;;
	3) echo "web admin accounts: no /etc/oui/oui.db" ;;
	*) printf 'web admin accounts: table account of /etc/oui/oui.db could not be read (%s)\n' "$(head -n 1 "$GLD/acct.err" 2>/dev/null)" ;;
	esac
	if gl_load wan-access; then
		echo "WAN access whitelist (wan-access):"
		gl_show wan-access '.*' '.*' 20
	else
		gl_missing "WAN access whitelist" wan-access
	fi
	echo "GL firewall sections for WAN access to the router and DMZ (the firewall tool shows the loaded rules):"
	gl_fw admin || echo "  no /etc/config/firewall"

	section "VPN servers and mesh VPNs (accept connections into the network)"
	if gl_load wireguard_server; then
		echo "WireGuard server (wireguard_server):"
		gl_show wireguard_server main_server 'enable|enabled|address_v4|address_v6|port|access|client_to_client|masq|local_access'
		awk -F'\t' '
			$1 == "S" { ty[$2] = $3; next }
			$1 == "O" && $2 != "main_server" && ($3 == "public_key" || ty[$2] ~ /peer/) { if (!($2 in p)) { p[$2] = 1; ord[++n] = $2 } }
			$1 == "O" && $3 == "name" { nm[$2] = $4 }
			END {
				x = ""
				for (i = 1; i <= n; i++) { if (i > 1) x = x ", "; y = (ord[i] in nm) ? nm[ord[i]] : ord[i]; x = x y }
				printf "  peers: %d%s\n", n, (n ? " (" x ")" : "")
			}' "$GLD/wireguard_server.u" | redact
	else
		gl_missing "WireGuard server" wireguard_server
	fi
	if [ -e /sys/class/net/wgserver ]; then echo "  interface wgserver: present"; else echo "  interface wgserver: absent"; fi
	if gl_load ovpnserver; then
		echo "OpenVPN server (ovpnserver):"
		gl_show ovpnserver 'global|vpn' 'enable|enabled|port|proto|client_auth|client_to_client|dev|server|subnet'
		if [ -f /etc/openvpn/cert/user_passwd.txt ]; then
			printf '  /etc/openvpn/cert/user_passwd.txt: %s lines (user names and passwords for client_auth; never shown)\n' \
				"$(rd /etc/openvpn/cert/user_passwd.txt | grep -c .)"
		else
			echo "  /etc/openvpn/cert/user_passwd.txt: not present"
		fi
	else
		gl_missing "OpenVPN server" ovpnserver
	fi
	if gl_load tailscale; then
		echo "Tailscale (tailscale):"
		gl_show tailscale settings 'enabled|lan_enabled|wan_enabled|run_exit_node|exit_node_ip|exit_node|ssh_enabled|advertise_routes|port'
	else
		gl_missing Tailscale tailscale
	fi
	if gl_load zerotier; then
		echo "ZeroTier (zerotier):"
		gl_show zerotier '.*' 'enabled|enable|nat|wan_nat|lan_enabled|wan_enabled|id|join'
	else
		gl_missing ZeroTier zerotier
	fi
	if gl_load tor; then
		printf 'Tor (tor): %s\n' "$(gl_onoff "$(gl_get tor global enable)")"
	else
		gl_missing Tor tor
	fi
	if gl_load gl_s2s; then
		printf 'Site-to-site WireGuard (gl_s2s): %s\n' "$(gl_onoff "$(gl_get gl_s2s global enable)")"
		gl_show gl_s2s '.*' '.*' 15
	else
		gl_missing "Site-to-site WireGuard" gl_s2s
	fi

	section "Sharing (files and media on the network, maybe on the WAN side)"
	if gl_load nas; then
		echo "NAS (nas):"
		gl_show nas '.*' '.*enable.*|webdav_port|nas_ser_.*|.*_port|.*wan.*' 20
	else
		gl_missing NAS nas
	fi
	if gl_load samba4; then
		echo "Samba shares (samba4):"
		awk -F'\t' '
			$1 == "S" { ty[$2] = $3; if ($3 == "sambashare") ord[++n] = $2; next }
			$1 == "O" && ty[$2] == "sambashare" { v[$2, $3] = $4 }
			function g(s, o) { return ((s, o) in v) ? v[s, o] : "-" }
			END {
				for (i = 1; i <= n && i <= 30; i++) { s = ord[i]; printf "  \047%s\047: path %s, guest ok %s, read only %s\n", g(s, "name"), g(s, "path"), g(s, "guest_ok"), g(s, "read_only") }
				if (n > 30) printf "  (%d more shares)\n", n - 30
				if (!n) print "  none"
			}' "$GLD/samba4.u" | redact
	else
		gl_missing "Samba shares" samba4
	fi
	echo "GL firewall rules for sharing on the WAN side (DROP keeps it closed):"
	gl_fw share || echo "  no /etc/config/firewall"
	if gl_load minidlna; then
		printf 'DLNA (minidlna): %s\n' "$(gl_onoff "$(gl_get minidlna config enabled)")"
		gl_show minidlna '.*' 'enabled|enable|media_dir|port|interface|friendly_name'
	else
		gl_missing DLNA minidlna
	fi

	section "Firmware and updates"
	printf 'GL.iNet firmware %s, type %s (/etc/glversion, /etc/version.type)\n' "$_glv" "${_glt:-unknown}" | redact
	printf 'model %s, country code %s, flash size %s (%s)\n' "$(gl_hw model || echo unknown)" \
		"$(gl_hw country_code || echo unknown)" "$(gl_hw flash_size || echo unknown)" "$GL_HW" | redact
	if gl_load upgrade; then
		echo "upgrade settings (upgrade; gray_url set means the beta channel):"
		gl_show upgrade '.*' '.*' 20
	else
		gl_missing "Upgrade settings" upgrade
	fi
	echo "plugin feeds: persistence locations=[\"feeds\"] shows the package feeds and their signing keys"
	return 0
}
