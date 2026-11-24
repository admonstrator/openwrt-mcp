# Audit: one call that runs the checks and returns findings with evidence.
#
# Rules the checks follow:
#   - a finding names the file, line, process or socket it rests on, and how sure it is
#   - severities stay conservative: what a normal router does (changed /etc/config,
#     packages installed by the owner) is never more than "info"
#   - a check that cannot run on this device says so at the end instead of passing
#
# MCP_PROC (default /proc) is where the process checks read exe links, environments and
# the module list. It exists for the tests: in an emulated container every exe link
# points at the emulator. Sockets always come from the real /proc (lib_sockets).
# shellcheck disable=SC2154,SC2016  # arg/arg_int/fx_path assign through eval; awk programs are single-quoted on purpose
: "${MCP_PROC:=/proc}"

# Release branches without security support. Checked against openwrt.org in 2026-11;
# extend it when a branch reaches its end of life.
AU_EOL_BRANCHES="17.01 18.06 19.07 21.02 22.03 23.05"

# au_add SEVERITY ID CONFIDENCE TITLE WHY DO   (stdin: evidence, one item per line)
# No evidence means the check found nothing; it is then listed as clean.
au_add() {
	cat >"$AU/ev"
	if [ ! -s "$AU/ev" ]; then
		echo "$2" >>"$AU/clean"
		return 0
	fi
	# busybox tr has no character classes, hence the labels spelled out
	case $1 in high) _ar=1 _al=HIGH ;; medium) _ar=2 _al=MEDIUM ;; low) _ar=3 _al=LOW ;; *) _ar=4 _al=INFO ;; esac
	{
		printf '[%s] %s: %s\n' "$_al" "$2" "$4"
		printf '  confidence: %s\n' "$3"
		echo '  evidence:'
		awk 'NR <= 25 { print "    - " $0 } END { if (NR > 25) print "    - ... and " (NR - 25) " more of the same kind" }' "$AU/ev"
		printf '  why: %s\n' "$5"
		printf '  do: %s\n\n' "$6"
	} >"$AU/f.$_ar.$2"
}

au_skip() { printf '%s: %s\n' "$1" "$2" >>"$AU/skipped"; }

# What a file is, from its first bytes (for evidence lines).
au_kind() {
	_ak=$(rd "$1" 2>/dev/null | head -c 64 | tr -d '\000' | head -n 1 | cut -c1-40)
	case $_ak in
	?ELF*) echo "ELF program" ;;
	'#!'*) echo "script ($_ak)" ;;
	*) echo "data" ;;
	esac
}

au_cmdline() { tr '\000' ' ' <"$MCP_PROC/$1/cmdline" 2>/dev/null | cut -c1-160; }

# ---------------------------------------------------------------- exposure
# Writes $AU/fw (zones, allow rules, redirects from uci), $AU/reach (listeners the WAN
# side may connect to) and the exposure findings. The auth checks read $AU/reach.
au_exposure_data() {
	: >"$AU/fw"
	: >"$AU/reach"
	: >"$AU/wanaddr"
	lib_sockets >"$AU/socks" 2>/dev/null
	if ! fo_uci firewall >"$AU/fw.uci" || [ ! -s "$AU/fw.uci" ]; then
		AU_FW=none
		return 0
	fi
	AU_FW=ok
	awk '
	function val(s) { sub(/^[^=]*=/, "", s); gsub(/\047/, "", s); return s }
	function wanlike(s,   n, w, i) {
		if (v[s, "name"] ~ /wan/ || v[s, "masq"] == "1") return 1
		n = split(v[s, "network"], w, " ")
		for (i = 1; i <= n; i++) if (w[i] ~ /wan|modem|tether/) return 1
		return 0
	}
	/^firewall\.[^.=]+=/ { s = $0; sub(/=.*/, "", s); type[s] = val($0); order[++n] = s; next }
	{ k = $0; sub(/=.*/, "", k); o = k; sub(/.*\./, "", o); sub(/\.[^.]*$/, "", k); v[k, o] = val($0) }
	END {
		OFS = "\t"; dflt = "REJECT"
		for (i = 1; i <= n; i++) if (type[order[i]] == "defaults" && v[order[i], "input"] != "") dflt = toupper(v[order[i], "input"])
		for (i = 1; i <= n; i++) {
			s = order[i]
			if (type[s] != "zone" || !wanlike(s)) continue
			inp = (v[s, "input"] == "") ? dflt : toupper(v[s, "input"])
			wz[v[s, "name"]] = 1
			print "Z", v[s, "name"], inp, (v[s, "network"] == "") ? "-" : v[s, "network"], s
			if (inp == "ACCEPT") print "A", "zone", "tcp udp", "all", "zone \047" v[s, "name"] "\047 input=ACCEPT (" s ".input in /etc/config/firewall)"
		}
		for (i = 1; i <= n; i++) {
			s = order[i]
			if (v[s, "enabled"] == "0") continue
			src = v[s, "src"]
			if (!(src in wz) && src != "*") continue
			if (type[s] == "rule") {
				if (v[s, "dest"] != "" || toupper(v[s, "target"]) != "ACCEPT") continue
				pr = tolower(v[s, "proto"]); if (pr == "") pr = "tcp udp"
				if (pr == "all" || pr == "any" || pr == "tcpudp") pr = "tcp udp"
				if (pr !~ /tcp|udp/) continue
				pt = v[s, "dest_port"]; if (pt == "") pt = "all"
				t = "rule \047" v[s, "name"] "\047 (" s "): src=" src " proto=" pr " dest_port=" pt " target=ACCEPT"
				if (v[s, "src_ip"] != "") t = t " src_ip=" v[s, "src_ip"]
				if (v[s, "src_mac"] != "") t = t " src_mac=" v[s, "src_mac"]
				print "A", "rule", pr, pt, t
			} else if (type[s] == "redirect") {
				tg = toupper(v[s, "target"]); if (tg != "" && tg != "DNAT") continue
				print "R", "redirect \047" v[s, "name"] "\047 (" s "): " src " " ((v[s, "proto"] == "") ? "tcp udp" : v[s, "proto"]) " port " v[s, "src_dport"] " -> " v[s, "dest_ip"] ":" ((v[s, "dest_port"] == "") ? v[s, "src_dport"] : v[s, "dest_port"])
			}
		}
	}' "$AU/fw.uci" >"$AU/fw"

	# addresses on the devices of the WAN zones; AU_WANDEV: yes | no | unknown
	AU_WANDEV=unknown
	if have ip && have uci; then
		# shellcheck disable=SC2013  # network names are words
		for _n in $(awk -F'\t' '$1 == "Z" && $4 != "-" { print $4 }' "$AU/fw"); do
			_d=
			if have ubus; then _d=$(ubus call "network.interface.$_n" status 2>/dev/null | jsonfilter -e '@.l3_device' 2>/dev/null); fi
			[ -n "$_d" ] || _d=$(uci -q get "network.$_n.device" 2>/dev/null) || _d=$(uci -q get "network.$_n.ifname" 2>/dev/null)
			[ -n "$_d" ] || continue
			[ "$AU_WANDEV" = unknown ] && AU_WANDEV=no
			for _dd in $_d; do
				ip -o addr show dev "$_dd" 2>/dev/null | awk '{ a = $4; sub(/\/.*/, "", a); if (a !~ /^fe80:/) print a }' >>"$AU/wanaddr"
			done
		done
		[ -s "$AU/wanaddr" ] && AU_WANDEV=yes
	fi

	FX_W="$AU/wanaddr" FX_F="$AU/fw" awk -F'\t' '
	function portmatch(list, port,   n, a, i, r) {
		if (list == "all") return 1
		n = split(list, a, " ")
		for (i = 1; i <= n; i++) {
			if (a[i] ~ /^!/) continue
			if (split(a[i], r, /[-:]/) == 2) { if (port + 0 >= r[1] + 0 && port + 0 <= r[2] + 0) return 1 }
			else if (a[i] == port) return 1
		}
		return 0
	}
	BEGIN { OFS = "\t" }
	FILENAME == ENVIRON["FX_W"] { wan[$1] = 1; next }
	FILENAME == ENVIRON["FX_F"] { if ($1 == "A") { n++; kind[n] = $2; pr[n] = $3; pt[n] = $4; txt[n] = $5 } next }
	{
		p = $1; sub(/6$/, "", p)
		if (p == "tcp" && $2 != "LISTEN") next
		if (p == "udp" && ($2 != "UNCONN" || $4 == 0)) next
		if (p != "tcp" && p != "udp") next
		if ($3 != "0.0.0.0" && $3 != "::" && !($3 in wan)) next
		# zone entries come first: a socket the zone policy already opens is reported
		# once, not again for every rule that also matches
		for (i = 1; i <= n; i++) {
			if (index(pr[i], p) == 0 || !portmatch(pt[i], $4)) continue
			# the DHCP clients answer on these ports; the stock rules open them
			if (kind[i] == "rule" && p == "udp" && ($4 == 68 || $4 == 546)) continue
			print kind[i], p, $4, sprintf("%s %s:%s pid %s (%s)", $1, $3, $4, $8, $9), txt[i]
			break
		}
	}' "$AU/wanaddr" "$AU/fw" "$AU/socks" >"$AU/reach"
}

au_exposure() {
	if [ "$AU_FW" != ok ]; then
		au_skip "exposure.wan_input_accept, exposure.wan_open_port, exposure.port_forward" "no firewall configuration readable (uci or /etc/config/firewall missing)"
		return 0
	fi
	case $AU_WANDEV in
	yes) _conf="medium: read from /etc/config/firewall and the socket table; the loaded ruleset was not evaluated rule by rule, a custom nft or iptables include can open or close more" ;;
	no) _conf="low: no interface of the WAN zone has an address right now, so nothing is attached to it at the moment; the configuration still allows it" ;;
	*) _conf="medium: read from /etc/config/firewall and the socket table; which interface is the WAN side could not be determined, and the loaded ruleset was not evaluated rule by rule" ;;
	esac
	_sev=high
	[ "$AU_WANDEV" = no ] && _sev=medium
	{
		awk -F'\t' '$1 == "Z" && $3 == "ACCEPT" { print "zone \047" $2 "\047 (" $5 " in /etc/config/firewall): input=ACCEPT, networks: " $4 }' "$AU/fw"
		awk -F'\t' '$1 == "zone" { print "reachable: " $4 }' "$AU/reach"
	} | au_add "$_sev" exposure.wan_input_accept "$_conf" \
		"The WAN zone accepts every incoming connection" \
		"With input=ACCEPT on the WAN zone, every service that listens on all addresses (SSH, the web interface, DNS) can be reached from the internet side." \
		"Set the zone's input to REJECT (uci set firewall.<zone>.input='REJECT'; uci commit firewall; service firewall reload) unless this device is a pure access point behind another router. The firewall tool shows the loaded rules."
	awk -F'\t' '$1 == "rule" { print $4 "  <- " $5 }' "$AU/reach" |
		au_add medium exposure.wan_open_port "$_conf" \
			"Services reachable from the WAN side through a firewall rule" \
			"Each listed socket listens on all addresses (or a WAN address) and a rule accepts its port from the WAN zone, so it is exposed to the internet side." \
			"Confirm that each rule is intended. Remove rules nobody remembers adding, or restrict them with src_ip."
	awk -F'\t' '$1 == "R" { print $2 }' "$AU/fw" |
		au_add low exposure.port_forward "high: read from /etc/config/firewall" \
			"Port forwards from the WAN side" \
			"A port forward exposes a device inside the network to the internet. Malware also adds forwards to keep access." \
			"Confirm each forward is yours; delete the others in the firewall configuration."

	# is a firewall loaded at all?
	if have nft && [ -x /sbin/fw4 ]; then
		if _t=$(nft list tables 2>/dev/null); then
			case $_t in
			*fw4*) echo exposure.firewall_not_loaded >>"$AU/clean" ;;
			*)
				echo "nft list tables: no table 'inet fw4' (loaded tables: $(echo "$_t" | tr '\n' ' '))" |
					au_add low exposure.firewall_not_loaded "high: the kernel has no fw4 table" \
						"The firewall ruleset is not loaded" \
						"Without the fw4 table nothing filters incoming connections. That is intended on a pure access point with the firewall service disabled, and a problem on a router." \
						"If this device routes to the internet: service firewall enable; service firewall start, then check the firewall tool."
				;;
			esac
		else
			au_skip exposure.firewall_not_loaded "nft cannot list tables here (no permission or no nftables in this kernel)"
		fi
	elif have iptables-save; then
		if _t=$(iptables-save 2>/dev/null) && [ -n "$_t" ]; then
			case $_t in
			*zone_*) echo exposure.firewall_not_loaded >>"$AU/clean" ;;
			*)
				echo "iptables-save: no zone_* chains" |
					au_add low exposure.firewall_not_loaded "high: the kernel has no fw3 chains" \
						"The firewall ruleset is not loaded" \
						"Without the zone chains nothing filters incoming connections. That is intended on a pure access point with the firewall service disabled, and a problem on a router." \
						"If this device routes to the internet: /etc/init.d/firewall enable; /etc/init.d/firewall start, then check the firewall tool."
				;;
			esac
		else
			au_skip exposure.firewall_not_loaded "iptables-save returns nothing here (no permission or no iptables in this kernel)"
		fi
	else
		au_skip exposure.firewall_not_loaded "nft: not available, iptables-save: not available"
	fi
}

# ---------------------------------------------------------------- authentication
au_auth() {
	fo_accounts >"$AU/acct"
	awk -F'\t' '$1 == "root" && $6 == "EMPTY" { print "/etc/shadow: root has an empty password field (shell " $5 ")" }' "$AU/acct" |
		au_add high auth.root_no_password "high: read from /etc/shadow" \
			"root has no password" \
			"Anyone who reaches SSH or the web interface logs in as root without a password. That is the state of a freshly flashed OpenWrt, and it must not stay." \
			"Set a password: passwd on the router, or System > Administration in LuCI."
	awk -F'\t' '$8 ~ /UID0/ {
		pw = $6; sub(/^set:/, "set, ", pw)
		x = "/etc/passwd: account \047" $1 "\047 has uid 0, shell " $5 ", password " pw
		if ($8 ~ /not-in-image/) x = x ", not in the firmware image"
		print x
	}' "$AU/acct" |
		au_add high auth.extra_uid0 "high: read from /etc/passwd" \
			"Accounts with uid 0 besides root" \
			"An account with uid 0 is root under another name. OpenWrt and GL.iNet firmware ship none; a second one is a classic backdoor." \
			"Unless you created it: remove the line from /etc/passwd and /etc/shadow, then treat the router as compromised (check persistence and overlay_diff, reflash if in doubt)."
	awk -F'\t' '$1 != "root" && $6 == "EMPTY" && $8 ~ /login-shell/ && $8 !~ /UID0/ { print "/etc/shadow: account \047" $1 "\047 (uid " $2 ", shell " $5 ") has an empty password" }' "$AU/acct" |
		au_add medium auth.empty_password "high: read from /etc/shadow" \
			"Accounts with a login shell and an empty password" \
			"Such an account can log in without a password wherever password logins are allowed." \
			"Set a password or change the shell to /bin/false."
	awk -F'\t' '$8 ~ /not-in-image/ && $8 ~ /login-shell/ && $8 !~ /UID0/ && $6 != "EMPTY" { pw = $6; sub(/^set:/, "set, ", pw); print "/etc/passwd: account \047" $1 "\047 (uid " $2 ", shell " $5 ", password " pw ") is not in the firmware image" }' "$AU/acct" |
		au_add low auth.account_added "high: /etc/passwd compared with the image" \
			"Login accounts added after flashing" \
			"Packages add service accounts without a login shell; an added account that can log in was created by someone." \
			"Confirm you created it."
	fo_keys_table |
		au_add low auth.authorized_keys "high: read from the authorized_keys files" \
			"SSH keys that can log in without a password" \
			"Every listed key opens a root shell (or the account's shell). Keys are the usual way to keep access after a break-in; a key you put there is fine." \
			"Compare each fingerprint with your own keys (ssh-keygen -lf ~/.ssh/id_ed25519.pub) and delete lines you do not recognise."
	if fo_uci uhttpd >"$AU/tmp.uci"; then
		grep "no_ubusauth='1'" "$AU/tmp.uci" | sed 's|$| (/etc/config/uhttpd)|' |
			au_add high auth.ubus_without_login "high: read from /etc/config/uhttpd" \
				"ubus over HTTP needs no login" \
				"With no_ubusauth=1 anyone who reaches the web server can call every ubus method as root." \
				"uci delete uhttpd.main.no_ubusauth; uci commit uhttpd; service uhttpd restart"
	else
		au_skip auth.ubus_without_login "no uhttpd configuration or uci not available"
	fi
	# password logins on SSH ports that the WAN side reaches
	if [ "$AU_FW" = ok ]; then
		fo_dropbear | awk -F'\t' '$2 == "on" && $5 == "on" { print $1 "\t" $3 }' >"$AU/db"
		if [ -f /etc/ssh/sshd_config ] && ! grep -Eiq '^[[:space:]]*PasswordAuthentication[[:space:]]+no' /etc/ssh/sshd_config; then
			_sp=$(awk 'tolower($1) == "port" { print $2; exit }' /etc/ssh/sshd_config)
			printf 'sshd_config\t%s\n' "${_sp:-22}" >>"$AU/db"
		fi
		FX_D="$AU/db" awk -F'\t' '
			FILENAME == ENVIRON["FX_D"] { who[$2] = $1; next }
			$2 == "tcp" && ($3 in who) { print who[$3] ": password login on, port " $3 "; " $4 "  <- " $5 }' "$AU/db" "$AU/reach" |
			au_add high auth.ssh_password_from_wan "medium: SSH configuration, socket table and /etc/config/firewall agree; the loaded ruleset was not evaluated rule by rule" \
				"SSH with password login is reachable from the WAN side" \
				"Password logins on an internet-facing SSH port are brute-forced around the clock, and root has no lockout." \
				"Close the port on the WAN side, or bind SSH to the LAN (uci set dropbear.main.Interface='lan'), or allow keys only (PasswordAuth 'off', RootPasswordAuth 'off')."
	else
		au_skip auth.ssh_password_from_wan "no firewall configuration readable, WAN reachability unknown"
	fi
}

# ---------------------------------------------------------------- integrity
au_integrity() {
	_up=
	if _up=$(fx_upper) && fx_rom_ok; then
		fo_overlay "$_up" / >"$AU/ov"
		_ev='{ x = $12 ": " (($6 == "l") ? "symlink -> " $13 : $10 " bytes, mode " $7) ", mtime " $11; if ($5 != "-") x = x "; " $5; if ($14 != "-") x = x "; package " $14 " (" $15 ")"; print x }'
		awk -F'\t' "$FO_AWK_LOC"'$1 == 1 && $2 == "changed" && fo_loc($12) == "" '"$_ev" "$AU/ov" |
			au_add high integrity.image_file_replaced "high: content compared with the firmware image (size, then SHA-256)" \
				"Programs of the firmware image were replaced" \
				"These files exist in the image, but the overlay holds a different version, and no package upgrade accounts for it. Replacing a system program is how implants hide (a fake netstat) or survive." \
				"Compare with file_hash and read_file view=strings. If you did not replace them yourself, treat the router as compromised: save the evidence, reflash the firmware without keeping settings, set new passwords."
		awk -F'\t' '$1 == 1 && $2 == "mode" '"$_ev" "$AU/ov" |
			au_add high integrity.setuid_added "high: mode compared with the firmware image" \
				"Setuid or setgid bit added to an image program" \
				"A setuid-root program lets any local user run it as root. The image ships these programs without the bit." \
				"Remove the bit (chmod u-s,g-s) and find out who set it."
		awk -F'\t' "$FO_AWK_LOC"'$1 == 2 && $2 == "added" && fo_loc($12) == "" '"$_ev" "$AU/ov" |
			au_add medium integrity.unowned_program "medium: not in the image and in no package file list; a program copied by hand looks the same" \
				"Programs in system directories that neither the image nor a package provides" \
				"Software normally arrives with the image or as a package. A program dropped into /usr/bin or /lib by hand may be yours, or an implant." \
				"Check each with file_hash (look the hash up) and read_file view=strings; delete what you cannot account for."
		awk -F'\t' '$1 == 2 && $2 == "deleted" { print $12 ": deleted in the overlay; " $5 (($14 != "-") ? "; package " $14 " (" $15 ")" : "") }' "$AU/ov" |
			au_add low integrity.image_file_deleted "high: whiteout entry in the overlay" \
				"Files of the firmware image were deleted" \
				"A deleted system file is unusual unless its package was removed (those are not listed here). Malware removes tools that could expose it." \
				"Check whether you removed them; a firmware reflash restores them."
		awk -F'\t' '$1 == 3 && $3 ~ /^replaced by an upgrade/ { n[$14]++ } END { for (p in n) print "package " p ": " n[p] " image files replaced, explained by a newer installed version" }' "$AU/ov" |
			au_add info integrity.package_upgrades "medium: the package database is writable, so this explanation can be forged" \
				"Image files replaced by package upgrades" \
				"Upgrading a preinstalled package replaces its files in the overlay. Normal, listed so that nothing replaced stays unmentioned." \
				"Nothing, if you upgraded these packages. overlay_diff max_priority=3 lists the files."
		_n=$(awk -F'\t' '$4 == "uncmp"' "$AU/ov" | wc -l)
		[ "$_n" -gt 0 ] && au_skip integrity.image_file_replaced "$_n overlay files could not be hashed (unusual file names); overlay_diff lists them"
	else
		# shellcheck disable=SC2153
		if [ -z "$_up" ]; then _r="no overlay upper directory found ($MCP_UPPER)"; else _r="no usable firmware image at $MCP_ROM"; fi
		au_skip "integrity.image_file_replaced, integrity.setuid_added, integrity.unowned_program, integrity.image_file_deleted" "$_r; nothing to compare the system files with"
		_up=
	fi

	# executables on the RAM disk
	set -- /tmp
	[ -d /dev/shm ] && set -- "$@" /dev/shm
	find "$@" -xdev -type f -perm /0111 ! -path '/tmp/openwrt-mcp.*' ! -path "${_up:-/nonexistent}/*" ! -path "${MCP_ROM%/}/*" -print0 2>/dev/null |
		fx_ls | head -n 60 | awk "$FX_AWK_LS"'{ if (fx_ls($0)) print F_path "\t" F_size "\t" F_mode "\t" F_mtime }' >"$AU/tmpx"
	while IFS="$FX_TAB" read -r _p _s _m _t; do
		printf '%s: %s, %s bytes, mode %s, mtime %s\n' "$_p" "$(au_kind "$_p")" "$_s" "$_m" "$_t"
	done <"$AU/tmpx" |
		au_add medium integrity.tmp_executable "medium: an executable file on the RAM disk; whether it is malicious needs a look inside" \
			"Executable files in /tmp or /dev/shm" \
			"OpenWrt keeps no programs on the RAM disk. Downloaders drop their payload there because it is writable and leaves no trace after a reboot." \
			"Inspect each with file_hash and read_file; note which process uses it (processes tool) before deleting it."

	# processes: deleted binaries, binaries on the RAM disk, binaries the image lacks
	# shellcheck disable=SC2012
	ls -l "$MCP_PROC"/[0-9]*/exe 2>/dev/null | awk '
		{
			i = index($0, " -> "); if (!i) next
			t = substr($0, i + 4); h = substr($0, 1, i - 1); sub(/\/exe$/, "", h); sub(/.*\//, "", h)
			del = 0; if (t ~ / \(deleted\)$/) { del = 1; sub(/ \(deleted\)$/, "", t) }
			print h "\t" del "\t" t
		}' >"$AU/exe"
	: >"$AU/p.del.tmp"; : >"$AU/p.del"; : >"$AU/p.tmp"; : >"$AU/p.cand"
	_gone=0
	while IFS="$FX_TAB" read -r _pid _del _exe; do
		_c=$(cat "$MCP_PROC/$_pid/comm" 2>/dev/null)
		case $_del$_exe in
		1/tmp/* | 1/dev/shm/* | 1/var/* | 1/run/*) printf 'pid %s (%s): %s (deleted); command line: %s\n' "$_pid" "$_c" "$_exe" "$(au_cmdline "$_pid")" >>"$AU/p.del.tmp" ;;
		1*) printf 'pid %s (%s): %s (deleted); command line: %s\n' "$_pid" "$_c" "$_exe" "$(au_cmdline "$_pid")" >>"$AU/p.del" ;;
		0/tmp/* | 0/dev/shm/* | 0/var/* | 0/run/*) printf 'pid %s (%s): %s; command line: %s\n' "$_pid" "$_c" "$_exe" "$(au_cmdline "$_pid")" >>"$AU/p.tmp" ;;
		*)
			if [ ! -e "$_exe" ]; then
				_gone=$((_gone + 1))
			elif fx_rom_ok && ! in_rom "$_exe"; then
				printf '%s\t%s\t%s\n' "$_exe" "$_pid" "$_c" >>"$AU/p.cand"
			fi
			;;
		esac
	done <"$AU/exe"
	au_add high integrity.process_deleted_tmp_binary "high: /proc/PID/exe names a deleted file on the RAM disk" \
		"Processes running a program that was deleted from /tmp" \
		"Start from the RAM disk, then delete the file: the program keeps running and nothing is left on disk. Legitimate software on OpenWrt does not do this." \
		"Do not reboot yet (the evidence is only in memory). read_file /proc/PID/exe view=strings and file_hash /proc/PID/exe still read the deleted program; the processes and connections tools show what it does." <"$AU/p.del.tmp"
	au_add medium integrity.process_deleted_binary "medium: also happens when a package is upgraded while its service keeps running" \
		"Processes running a program file that no longer exists" \
		"The file was replaced or removed after the process started: a package upgrade without a restart, or a program hiding its file." \
		"Restart the service if you upgraded it. Otherwise read the program through /proc/PID/exe (read_file, file_hash)." <"$AU/p.del"
	au_add medium integrity.process_tmp_binary "medium: a program running from the RAM disk; whether it is malicious needs a look inside" \
		"Processes running from /tmp, /var or /dev/shm" \
		"Programs belong to the firmware or to packages. One that runs from the RAM disk was put there after boot." \
		"Inspect the file with file_hash and read_file view=strings, and the process with the processes and connections tools." <"$AU/p.tmp"
	if fx_rom_ok; then
		if [ -s "$AU/p.cand" ]; then
			cut -f1 "$AU/p.cand" | sort -u | tr '\n' '\0' | fx_ls | fx_cmp "" 1 | fx_pkg >"$AU/p.rec"
		else
			: >"$AU/p.rec"
		fi
		FX_R="$AU/p.rec" awk -F'\t' '
			FILENAME == ENVIRON["FX_R"] { if ($12 != "added") own[$9] = ($11 == "-") ? "no package owns it" : "package " $11 " (" $12 ")"; next }
			($1 in own) { print "pid " $2 " (" $3 "): " $1 " is not in the firmware image; " own[$1] }' "$AU/p.rec" "$AU/p.cand" |
			au_add medium integrity.process_not_from_image "medium: the program is neither in the image nor in an added package; software installed by hand looks the same" \
				"Processes running programs that neither the image nor a package provides" \
				"A running program that was not shipped and not installed as a package was put there by hand, by you or by someone else." \
				"Check the file with file_hash and read_file view=strings; the processes tool shows its parent and start time."
	else
		au_skip integrity.process_not_from_image "no usable firmware image at $MCP_ROM"
	fi
	[ "$_gone" -gt 0 ] && au_skip integrity.process_not_from_image "$_gone processes point at a program path that does not exist in this filesystem view (another mount namespace, or an emulator)"

	# kernel modules
	_rel=$(uname -r 2>/dev/null)
	if [ -d "$MCP_ROM/lib/modules/$_rel" ] && [ -r "$MCP_PROC/modules" ]; then
		{
			find "$MCP_ROM/lib/modules/$_rel" -name '*.ko*' 2>/dev/null | sed 's|.*/||; s|^|I\t|'
			find "/lib/modules/$_rel" -name '*.ko*' 2>/dev/null | sed 's|^|L\t|'
			sed 's|^|M\t|' "$MCP_PROC/modules"
		} | awk -F'\t' '
			function norm(f) { sub(/.*\//, "", f); sub(/\.ko.*$/, "", f); gsub(/-/, "_", f); return f }
			$1 == "I" { img[norm($2)] = 1; next }
			$1 == "L" { live[norm($2)] = $2; next }
			{ split($2, m, " "); if (!(m[1] in img)) print m[1] "\t" m[2] "\t" ((m[1] in live) ? live[m[1]] : "-") }' >"$AU/mod"
		: >"$AU/mod.rec"
		if [ -s "$AU/mod" ]; then
			awk -F'\t' '$3 != "-" { print $3 }' "$AU/mod" | tr '\n' '\0' | fx_ls | fx_cmp "" 0 | fx_pkg >"$AU/mod.rec"
		fi
		FX_R="$AU/mod.rec" awk -F'\t' '
			FILENAME == ENVIRON["FX_R"] { if ($12 == "added") ok[$9] = 1; else own[$9] = ($11 == "-") ? "no package owns it" : "package " $11 " (" $12 ")"; next }
			($3 in ok) { next }
			{ print "module " $1 " (" $2 " bytes, /proc/modules): no " $1 ".ko in the image; " (($3 == "-") ? "no module file of that name on disk either" : "loaded from " $3 ", " own[$3]) }' "$AU/mod.rec" "$AU/mod" |
			au_add medium integrity.kernel_module_not_in_image "medium: module name compared with the .ko files of the image; a module from a kmod package installed after flashing is not listed" \
				"Loaded kernel modules that the firmware image does not contain" \
				"A kernel module runs with full control over the system and can hide files, processes and connections. Modules normally come with the image or a kmod package." \
				"Find the file (find_files name='<module>.ko*'), hash it with file_hash, and check who installed it."
	else
		au_skip integrity.kernel_module_not_in_image "the image has no /lib/modules/$_rel (no image, or its kernel is not the running one)"
	fi

	# preloaded libraries
	_sev=medium
	ls /lib/ld-musl-* >/dev/null 2>&1 || _sev=high
	{
		if [ -e /etc/ld.so.preload ] || [ -L /etc/ld.so.preload ]; then
			if _w=$(fx_refuse /etc/ld.so.preload); then
				echo "/etc/ld.so.preload exists: $_w"
			else
				rd /etc/ld.so.preload | awk '!/^[ \t]*(#|$)/ { print "/etc/ld.so.preload line " NR ": " $0; n++ } END { if (!n) print "/etc/ld.so.preload exists (no active lines)" }'
			fi
		fi
		for _f in $(grep -l -a 'LD_PRELOAD=' "$MCP_PROC"/[0-9]*/environ 2>/dev/null | head -n 20); do
			_v=$(tr '\000' '\n' <"$_f" 2>/dev/null | grep '^LD_PRELOAD=' | head -n 1)
			[ -n "$_v" ] || continue
			_pid=${_f%/environ}
			_pid=${_pid##*/}
			echo "pid $_pid ($(cat "$MCP_PROC/$_pid/comm" 2>/dev/null)): environment has $_v"
		done
	} >"$AU/pre"
	grep -q 'environment has' "$AU/pre" && _sev=high
	au_add "$_sev" integrity.ld_preload "high: the file or variable is there; musl (the C library of OpenWrt) ignores /etc/ld.so.preload but honours LD_PRELOAD" \
		"A library is preloaded into programs" \
		"Preloading injects code into every program that starts: the standard userland rootkit technique. Nothing in OpenWrt or GL.iNet firmware uses it." \
		"Inspect the named library with file_hash and read_file view=strings, find what sets it (persistence tool), then remove it." <"$AU/pre"

	# something mounted over a system directory
	awk '$2 ~ /^\/(bin|sbin|lib|lib64|usr|www)(\/|$)/ { print "/proc/mounts: " $1 " mounted on " $2 " (" $3 ")" }' /proc/mounts 2>/dev/null |
		au_add medium integrity.mount_over_system_path "medium: a mount hides what the image and the overlay hold at that path; extroot and custom setups do this on purpose" \
			"A filesystem is mounted over a system directory or program" \
			"A bind mount over /usr/bin/x replaces the program without touching the overlay, so overlay_diff would not show it." \
			"Check what is mounted there (list_dir, file_hash compare with the image)."
}

# ---------------------------------------------------------------- persistence
au_persistence() {
	fo_persist >"$AU/ps"
	_ev='{ x = $10 (($11 != "-") ? " -> " $11 : "") ": " $8 " bytes, mode " $5 ", mtime " $9; if ($3 != "-") x = x "; " $3; x = x "; " (($12 == "-") ? "no package owns it" : "package " $12 " (" $13 ")"); print x }'
	if fx_rom_ok; then
		awk -F'\t' '$2 == "changed" && ($1 == "init" || $1 == "hotplug" || $1 == "inittab" || $1 == "rpcd" || $1 == "luci") && $13 !~ /^upgraded/ '"$_ev" "$AU/ps" |
			au_add high persistence.image_script_changed "high: content compared with the firmware image" \
				"Startup scripts of the firmware image were modified" \
				"These scripts run as root at boot or on events, and they differ from the image although no package upgrade accounts for it. Appending a line to an existing init script is a well-known way to hide a backdoor." \
				"Read each one (persistence shows the active lines, read_file the whole file) and compare with the image copy under $MCP_ROM. If you did not edit it, treat the router as compromised."
		awk -F'\t' '$2 == "new" && $13 != "added" && $1 != "cron" && $1 != "rc_local" && $1 != "preload" && $1 != "ssh_keys" && $1 != "hosts" && $1 != "sysupgrade" && $1 != "feeds" && $1 != "modules" && !($10 ~ /^\/etc\/rc\.d\// && $11 ~ /^\.\.\/init\.d\/[^\/]+$/) '"$_ev" "$AU/ps" |
			au_add medium persistence.autostart_added "medium: not in the image and in no package file list; a script you added yourself looks the same" \
				"Autostart entries that neither the image nor a package provides" \
				"Each listed file runs by itself: at boot, on a network or button event, at login or at a firewall reload. That is how something survives a reboot." \
				"Read each one (the persistence tool shows the content). Delete what you did not put there and look for what it starts."
		awk -F'\t' '$2 == "new" && $13 == "added" && $1 != "ssh_keys" { n[$12]++ } END { for (p in n) print "package " p ": " n[p] " autostart files" }' "$AU/ps" |
			au_add info persistence.package_autostart "medium: the package database is writable, so ownership can be forged" \
				"Autostart entries of packages installed after flashing" \
				"Installed packages bring their own init scripts and hooks. Normal, listed so that every autostart entry outside the image is accounted for." \
				"Nothing, if you installed these packages (the packages tool lists them)."
		awk -F'\t' '($2 == "changed" || $2 == "new") && $1 == "feeds" '"$_ev" "$AU/ps" |
			au_add low persistence.feeds_changed "high: content compared with the firmware image" \
				"Package feeds or signing keys differ from the image" \
				"Feeds and keys decide where software comes from and whom the router trusts. Mirrors are a common, harmless change; an unknown feed or key is a supply-chain path." \
				"Check the URLs and keys (persistence locations=[\"feeds\"])."
	else
		au_skip "persistence.image_script_changed, persistence.autostart_added, persistence.package_autostart, persistence.feeds_changed" "no usable firmware image at $MCP_ROM, new and changed entries cannot be told from shipped ones (the persistence tool lists them all)"
	fi
	# entries the owner may have written: cron, rc.local, changed profile and hooks
	awk -F'\t' '$4 == "f" && ($1 == "cron" || ($1 == "rc_local" && $2 != "same") || (($1 == "profile" || $1 == "firewall" || $1 == "dnsmasq") && $2 == "changed")) { print $10 }' "$AU/ps" |
		while IFS= read -r _p; do
			fx_refuse "$_p" >/dev/null && continue
			rd "$_p" | tr -d '\000\r' | redact | fx_redact_kv "$_p" | FX_P="$_p" awk '
				/^[ \t]*(#|$)/ { next }
				/^[ \t]*exit 0[ \t]*$/ { next }
				{
					n++; if (n > 10) next
					s = (length($0) > 300) ? substr($0, 1, 300) "..." : $0
					h = ""
					if ($0 ~ /(wget|curl|uclient-fetch|tftp|base64)/ || $0 ~ /\|[ \t]*(sh|ash|bash)([ \t;&]|$)/ || $0 ~ /\/(tmp|dev\/shm)\//) h = "  <- downloads, pipes into a shell or uses the RAM disk"
					print ENVIRON["FX_P"] " line " NR ": " s h
				}
				END { if (n > 10) print ENVIRON["FX_P"] ": " (n - 10) " more active lines" }'
		done >"$AU/hooks"
	_sev=low
	grep -q '<- downloads' "$AU/hooks" && _sev=medium
	au_add "$_sev" persistence.user_autostart "medium: these are the places owners use for their own jobs; the content decides" \
		"Commands that run by themselves from cron, rc.local or changed startup files" \
		"Scheduled reboots and DDNS updates live here, and so do the download-and-run lines of malware. Lines marked with an arrow fetch something, pipe into a shell or use the RAM disk." \
		"Confirm each line is yours. Remove the others, then look at what they started (processes) and fetched (find_files in /tmp)." <"$AU/hooks"
}

# ---------------------------------------------------------------- update state
au_updates() {
	_rel=$(sed -n "s/^DISTRIB_RELEASE=['\"]\{0,1\}\([^'\"]*\).*/\1/p" /etc/openwrt_release 2>/dev/null | head -n 1)
	_gl=
	[ -f /etc/glversion ] && _gl=$(rd /etc/glversion | head -n 1)
	if [ -z "$_rel" ]; then
		au_skip "updates.branch_eol, updates.firmware_age" "no DISTRIB_RELEASE in /etc/openwrt_release"
		return 0
	fi
	_br=$(echo "$_rel" | awk -F. '{ print $1 "." $2 }')
	_eol=0
	case " $AU_EOL_BRANCHES " in *" $_br "*) _eol=1 ;; esac
	case $_rel in
	*SNAPSHOT* | *snapshot*) au_skip updates.branch_eol "snapshot build ($_rel), no release branch to judge" ;;
	*)
		if [ -n "$_gl" ]; then
			[ "$_eol" = 1 ] && echo "/etc/openwrt_release: DISTRIB_RELEASE=$_rel (OpenWrt branch $_br is end of life); /etc/glversion: GL.iNet firmware $_gl"
		else
			[ "$_eol" = 1 ] && echo "/etc/openwrt_release: DISTRIB_RELEASE=$_rel; the OpenWrt $_br branch is end of life and gets no security fixes"
		fi | if [ -n "$_gl" ]; then
			au_add low updates.branch_eol "medium: GL.iNet builds on older OpenWrt branches and backports fixes itself; the OpenWrt branch alone does not say whether this firmware is current" \
				"The firmware is based on an OpenWrt branch that is end of life" \
				"Upstream OpenWrt no longer fixes this branch. On vendor firmware what counts is whether the vendor's own firmware version is the latest." \
				"Compare the GL.iNet firmware version with the newest one for this model (dl.gl-inet.com) and install it if newer."
		else
			au_add medium updates.branch_eol "high for the release read from /etc/openwrt_release; the list of end-of-life branches is built into this server (as of 2026-11)" \
				"The OpenWrt release branch is end of life" \
				"Known vulnerabilities in the kernel, dnsmasq, dropbear and the web interface stay unpatched on a branch without security support." \
				"Upgrade to a supported release (firmware-selector.openwrt.org) with sysupgrade."
		fi
		;;
	esac
	_f=$(rom_path /etc/openwrt_release)
	[ -f "$_f" ] || _f=/etc/openwrt_release
	_b=$(date -r "$_f" +%s 2>/dev/null)
	_now=$(date +%s)
	if [ -z "$_b" ] || [ "$_now" -lt 1700000000 ] || [ "$_now" -lt "$_b" ]; then
		au_skip updates.firmware_age "the clock is not set or the build date is unreadable (now: $(date '+%Y-%m-%d'))"
		return 0
	fi
	_days=$(((_now - _b) / 86400))
	if [ "$_days" -gt 365 ]; then
		echo "$_f is dated $(date -r "$_f" '+%Y-%m-%d'), $_days days ago; release $_rel${_gl:+, GL.iNet firmware $_gl}"
	fi | au_add low updates.firmware_age "medium: the date of the firmware's release file stands in for the build date; whether a newer firmware exists was not checked (no network access)" \
		"The firmware build is more than a year old" \
		"A year without a firmware update usually means published security fixes are missing." \
		"Check for a newer firmware for this model and install it."
}

# ---------------------------------------------------------------- Wi-Fi
au_wifi() {
	if ! fo_uci wireless >"$AU/wl" || [ ! -s "$AU/wl" ]; then
		au_skip "wifi.open_network, wifi.wep, wifi.wpa1, wifi.wps" "no wireless configuration (no Wi-Fi hardware or driver, or uci not available)"
		return 0
	fi
	awk '
	function val(s) { sub(/^[^=]*=/, "", s); gsub(/\047/, "", s); return s }
	/^wireless\.[^.=]+=/ { s = $0; sub(/=.*/, "", s); type[s] = val($0); order[++n] = s; next }
	{ k = $0; sub(/=.*/, "", k); o = k; sub(/.*\./, "", o); sub(/\.[^.]*$/, "", k); v[k, o] = val($0) }
	END {
		OFS = "\t"
		for (i = 1; i <= n; i++) {
			s = order[i]
			if (type[s] != "wifi-iface" || v[s, "disabled"] == "1") continue
			if (v["wireless." v[s, "device"], "disabled"] == "1") continue
			e = tolower(v[s, "encryption"]); if (e == "") e = "none"
			m = (v[s, "mode"] == "") ? "ap" : v[s, "mode"]
			d = s " (/etc/config/wireless): ssid \047" v[s, "ssid"] "\047, mode " m ", encryption " e
			if (e == "none") print (m == "ap") ? "open_ap" : "open_sta", d
			else if (e ~ /^wep/) print "wep", d
			else if (e ~ /^(psk|wpa)($|\+)/) print "wpa1", d " (WPA1 only)"
			# psk-mixed and wpa-mixed are WPA1+WPA2; sae-mixed and wpa3-mixed are WPA2+WPA3
			else if (e ~ /^(psk|wpa)-mixed/) print "mixed", d " (WPA1 still accepted)"
			else if (e ~ /tkip/ && e !~ /ccmp|aes/) print "mixed", d " (TKIP only)"
			if (v[s, "wps_label"] == "1" || v[s, "wps_pin"] != "") print "wps_pin", d ", WPS PIN enabled"
			else if (v[s, "wps_pushbutton"] == "1") print "wps_pbc", d ", WPS push button enabled"
		}
	}' "$AU/wl" >"$AU/wf"
	awk -F'\t' '$1 == "open_ap" { print $2 }' "$AU/wf" |
		au_add medium wifi.open_network "high: read from /etc/config/wireless; a captive portal or guest isolation behind it was not evaluated" \
			"Wi-Fi networks without encryption" \
			"Anyone in range can join and read the traffic of everyone on that network. Intended for some guest networks, a mistake everywhere else." \
			"Set encryption to sae-mixed or psk2 with a strong key, or use owe for an open guest network."
	awk -F'\t' '$1 == "open_sta" { print $2 }' "$AU/wf" |
		au_add low wifi.open_uplink "high: read from /etc/config/wireless" \
			"The router connects to an unencrypted Wi-Fi network" \
			"Traffic to that network (a hotel or hotspot uplink) can be read by anyone nearby; only a VPN or TLS protects it." \
			"Use a VPN on this uplink."
	awk -F'\t' '$1 == "wep" { print $2 }' "$AU/wf" |
		au_add high wifi.wep "high: read from /etc/config/wireless" \
			"Wi-Fi networks with WEP" \
			"WEP is broken: the key can be recovered within minutes with freely available tools." \
			"Switch to psk2 or sae-mixed."
	awk -F'\t' '$1 == "wpa1" || $1 == "mixed" { print $2 }' "$AU/wf" >"$AU/ev2"
	_sev=low
	grep -q 'WPA1 only' "$AU/ev2" && _sev=medium
	au_add "$_sev" wifi.wpa1 "high: read from /etc/config/wireless" \
		"Wi-Fi networks that allow WPA1 or TKIP" \
		"WPA1 and TKIP have known weaknesses and are deprecated; a mixed mode lets a client be pushed down to them." \
		"Use psk2 (CCMP) or sae-mixed unless a very old client needs WPA1." <"$AU/ev2"
	awk -F'\t' '$1 == "wps_pin" || $1 == "wps_pbc" { print $2 }' "$AU/wf" >"$AU/ev2"
	_sev=low
	grep -q 'WPS PIN' "$AU/ev2" && _sev=medium
	au_add "$_sev" wifi.wps "high: read from /etc/config/wireless" \
		"Wi-Fi networks with WPS" \
		"The WPS PIN method can be brute-forced and then reveals the Wi-Fi key; the push button method is only open for a short time after someone presses the button." \
		"Turn WPS off (wps_pushbutton '0', remove wps_label and wps_pin)." <"$AU/ev2"
}

# ---------------------------------------------------------------- audit
mcp_register audit <<'EOF'
{"name":"audit","title":"Security audit","description":"Runs all security checks in one call and returns findings ordered by severity (high, medium, low, info), each with a stable check id, a confidence statement, the evidence it rests on (file, line, pid or socket), why it matters and what to do. It covers exposure to the WAN side, authentication (root password, uid 0 accounts, SSH keys and password logins), integrity against the firmware image (replaced programs, executables in /tmp, processes running deleted or foreign binaries, kernel modules, ld.so.preload), autostart entries the image does not have, update state and Wi-Fi encryption. The output ends with the checks that found nothing and the checks that could not run on this device and why. Start here, then follow up a finding with the specific tools.","inputSchema":{"type":"object","properties":{"categories":{"type":"array","items":{"type":"string","enum":["exposure","auth","integrity","persistence","updates","wifi"]},"description":"Only these categories. Default: all six."},"min_severity":{"type":"string","enum":["info","low","medium","high"],"description":"Leave out findings below this severity. Default info (everything).","default":"info"}},"additionalProperties":false},"annotations":{"readOnlyHint":true,"openWorldHint":false}}
EOF
tool_audit() {
	arg minsev min_severity info
	case $minsev in info) _max=4 ;; low) _max=3 ;; medium) _max=2 ;; high) _max=1 ;; *) tool_error "min_severity must be info, low, medium or high, got '$minsev'"; return 1 ;; esac
	all="exposure auth integrity persistence updates wifi"
	cats=$(arg_list categories | tr '\n' ' ')
	for c in $cats; do
		case " $all " in *" $c "*) ;; *) tool_error "unknown category '$c'; known: $all"; return 1 ;; esac
	done
	[ -n "$cats" ] || cats=$all
	AU=$MCP_TMP/audit
	rm -rf "$AU"
	mkdir -p "$AU"
	: >"$AU/clean"
	: >"$AU/skipped"
	AU_FW=none
	AU_WANDEV=unknown
	case " $cats " in *" exposure "* | *" auth "*) au_exposure_data ;; esac
	for c in $cats; do "au_$c"; done

	_host=$(cat /proc/sys/kernel/hostname 2>/dev/null)
	_desc=$(sed -n "s/^DISTRIB_DESCRIPTION=['\"]\{0,1\}\([^'\"]*\).*/\1/p" /etc/openwrt_release 2>/dev/null | head -n 1)
	printf 'Audit of %s (%s%s), %s\n' "${_host:-?}" "${_desc:-unknown release}" "$([ -f /etc/glversion ] && printf ', GL.iNet firmware %s' "$(rd /etc/glversion | head -n 1)")" "$(date '+%Y-%m-%d %H:%M:%S')"
	if fx_rom_ok; then _i="$MCP_ROM (usable)"; else _i="$MCP_ROM (not usable)"; fi
	if _u=$(fx_upper); then :; else _u="none found"; fi
	printf 'firmware image: %s | overlay: %s | trusted tools: %s\n' "$_i" "$_u" "$MCP_TRUSTED"
	printf 'categories: %s\n' "$cats"
	_n1=$(find "$AU" -name 'f.1.*' | wc -l)
	_n2=$(find "$AU" -name 'f.2.*' | wc -l)
	_n3=$(find "$AU" -name 'f.3.*' | wc -l)
	_n4=$(find "$AU" -name 'f.4.*' | wc -l)
	printf 'findings: %s high, %s medium, %s low, %s info' "$_n1" "$_n2" "$_n3" "$_n4"
	[ "$_max" -lt 4 ] && printf ' (shown: %s and above)' "$minsev"
	printf '\n\n'
	_shown=0
	for _r in 1 2 3 4; do
		[ "$_r" -le "$_max" ] || break
		for _f in "$AU"/f."$_r".*; do
			[ -f "$_f" ] || continue
			cat "$_f"
			_shown=$((_shown + 1))
		done
	done
	[ "$_shown" = 0 ] && printf 'No findings.\n\n'
	echo "== Checked, nothing found"
	if [ -s "$AU/clean" ]; then tr '\n' ' ' <"$AU/clean"; echo; else echo "(none)"; fi
	echo
	echo "== Could not check"
	if [ -s "$AU/skipped" ]; then sed 's/^/- /' "$AU/skipped"; fi
	case $MCP_TRUSTED in
	no*) echo "- trusted tools: the image at $MCP_ROM has no busybox, so every check ran with the programs of the live system; replaced applets could hide things" ;;
	esac
	echo "- a kernel rootkit can hide processes, sockets and files from everything read here; only an offline look at the flash rules that out"
	rm -rf "$AU"
	return 0
}
