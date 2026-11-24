# Forensics: overlay_diff, persistence, users_auth, and the two scanners the audit
# (50-audit.sh) builds on: fo_overlay (what the overlay changes against the image) and
# fo_persist (every place code starts from by itself).

# shellcheck disable=SC2154,SC2016  # arg/arg_int/fx_path assign through eval; awk programs are single-quoted on purpose

# awk library: fo_loc(path) names the persistence location a path belongs to ("" when
# none), fo_code(path) says whether a path holds programs, fo_expected(path) whether
# every router writes it during normal use.
FO_AWK_LOC='
function fo_loc(p) {
	if (p ~ /^\/etc\/crontabs\// || p ~ /^\/etc\/cron\.d\//) return "cron"
	if (p == "/etc/rc.local") return "rc_local"
	if (p ~ /^\/etc\/init\.d\// || p ~ /^\/etc\/rc\.d\// || p == "/etc/rc.common" || p ~ /^\/etc\/rc\.button\// || p == "/etc/preinit") return "init"
	if (p == "/etc/inittab") return "inittab"
	if (p ~ /^\/etc\/hotplug\.d\// || p ~ /^\/etc\/hotplug(-preinit)?\.json$/) return "hotplug"
	if (p ~ /^\/etc\/(udhcpc|odhcp6c)\.user$/ || p ~ /^\/etc\/(udhcpc|odhcp6c)\.user\.d\// || p ~ /^\/etc\/ppp\/ip(v6)?-(up|down)$/ || p ~ /^\/etc\/ppp\/ip(v6)?-(up|down)\.d\//) return "hotplug"
	if (p ~ /^\/etc\/uci-defaults\//) return "uci_defaults"
	if (p == "/etc/firewall.user" || p ~ /^\/etc\/nftables\.d\// || p ~ /^\/usr\/share\/nftables\.d\// || p ~ /^\/etc\/firewall\.d\//) return "firewall"
	if (p == "/etc/dnsmasq.conf" || p ~ /^\/etc\/dnsmasq\.d\// || p ~ /^\/tmp\/dnsmasq\.d\//) return "dnsmasq"
	if (p == "/etc/profile" || p ~ /^\/etc\/profile\.d\// || p == "/etc/shinit" || p ~ /^\/root\/\.(profile|shinit|ashrc|bashrc)$/) return "profile"
	if (p == "/etc/ld.so.preload") return "preload"
	if (p ~ /^\/etc\/modules(-boot)?\.d\//) return "modules"
	if (p == "/etc/sysupgrade.conf" || p ~ /^\/lib\/upgrade\/keep\.d\//) return "sysupgrade"
	if (p ~ /^\/usr\/libexec\/rpcd\// || p ~ /^\/usr\/share\/rpcd\//) return "rpcd"
	if (p ~ /^\/usr\/lib\/lua\/luci\/controller\// || p ~ /^\/usr\/share\/luci\/menu\.d\// || p ~ /^\/usr\/share\/ucode\/luci\/controller\// || p ~ /^\/www\/cgi-bin\//) return "luci"
	if (p == "/etc/opkg.conf" || p ~ /^\/etc\/opkg\// || p ~ /^\/etc\/apk\/repositories/ || p ~ /^\/etc\/apk\/keys\//) return "feeds"
	if (p == "/etc/hosts") return "hosts"
	if (p ~ /\/authorized_keys$/) return "ssh_keys"
	return ""
}
function fo_code(p) {
	return (p ~ /^\/(bin|sbin|lib|lib64|www|opt)\// || p ~ /^\/usr\/(bin|sbin|lib|libexec|share|local)\//)
}
function fo_expected(p) {
	return (p ~ /^\/etc\/config\// || p ~ /^\/usr\/lib\/opkg\// || p ~ /^\/lib\/apk\// || p ~ /^\/etc\/apk\/world$/ || \
		p ~ /^\/etc\/dropbear\/dropbear_[a-z0-9]+_host_key$/ || p ~ /^\/etc\/uhttpd\.(key|crt)$/ || \
		p == "/etc/urandom.seed" || p == "/etc/board.json" || p ~ /^\/etc\/\.uci/ || p ~ /^\/etc\/luci-uploads\// || \
		p ~ /^\/\.extroot/ || p ~ /^\/root\/\.ash_history$/ || p ~ /^\/etc\/ssl\/certs\//)
}
'
FO_LOCS="cron rc_local init inittab hotplug uci_defaults firewall dnsmasq profile preload modules sysupgrade rpcd luci feeds hosts ssh_keys"

# uci show PKG, or failure when uci is missing or the package does not exist.
fo_uci() {
	have uci || return 1
	uci -q show "$1" 2>/dev/null
}

# fo_overlay UPPER PREFIX: every entry of the overlay's upper directory below PREFIX,
# classified and sorted by priority, then path. Tab separated:
#   prio status why state detail type mode uid gid size mtime path target pkg qual fb
# status: added changed mode deleted same. prio 1 (look first) to 5 (expected). fb is
# "firstboot" for entries written in the first-boot window (see fx_firstboot).
# Directories that also exist in the image are left out.
fo_overlay() {
	_ou=${1%/}
	_os=$_ou$2/
	[ "$2" = / ] && _os=$_ou/
	[ -d "$_os" ] || return 0
	find "$_os" -xdev -mindepth 1 -print0 2>/dev/null | fx_ls | head -n 20001 | fx_cmp "$_ou" 1 | fx_pkg | fx_firstboot "$_ou" |
		FX_UP="$_ou" FX_ROM="${MCP_ROM%/}" awk -F'\t' "$FX_AWK_LS$FO_AWK_LOC"'
		# a regular file that exists below ROOT (no process needed: getline fails on a missing file)
		function isfile(root, p,   l, r) { r = (getline l < (root p)); close(root p); return (r >= 0) }
		BEGIN { OFS = "\t" }
		{
			st = $1; type = $3; mode = $4; size = $7; p = $9; pkg = $11; q = $12; fb = ($13 == "firstboot")
			loc = fo_loc(p); code = fo_code(p); exec = (type == "f" && mode ~ /[1357]/ && substr(mode, 2) ~ /[1357]/)
			# a program, as opposed to a data or configuration file that lives next to programs
			prog = (type == "l" || exec || loc != "" || p ~ /\.(so|ko|lua|uc|sh|js|ut|htm|py|pl)(\.[0-9.]+)?$/ || \
				p ~ /^\/(lib\/(functions|netifd|preinit|upgrade)|usr\/libexec|www\/cgi-bin)\//)
			prio = 4; status = "added"; why = ""
			if (type == "c" && size == "0,0") {
				status = "deleted"
				if (st == "new") { prio = 4; why = "whiteout for a path the image does not have" }
				else if (loc == "uci_defaults") { prio = 5; why = "first-boot script ran and removed itself (expected)" }
				else if (q == "removed") { prio = 4; why = "removed with package " pkg }
				else if (p ~ /^\/etc\/rc\.d\//) { prio = 4; why = "service disabled" }
				else if (code || loc != "") { prio = 2; why = "image file deleted" }
				else { prio = 4; why = "image file deleted (configuration)" }
			} else if (type == "d") {
				if (st == "same") next
				if (st == "new") { prio = 5; why = "directory added" }
				else { status = "mode"; prio = 3; why = "directory mode, owner or type changed" }
			} else if (st == "same") {
				status = "same"; prio = 5; why = "copied up, identical to the image"
			} else if (st == "uncmp") {
				status = "changed"; prio = 3; why = "could not be compared with the image"
			} else if (st == "meta") {
				status = "mode"
				if (type == "f" && substr(mode, 1, 1) ~ /[2-7]/) { prio = 1; why = "setuid or setgid bit set on an image file" }
				else { prio = 3; why = "mode or owner changed, content as in the image" }
			} else if (p == "/etc/ld.so.preload") {
				status = (st == "new") ? "added" : "changed"; prio = 1; why = "preloads a library into every program"
			} else if (st == "changed") {
				status = "changed"
				if (fo_expected(p)) { prio = 5; why = "configuration or device state (expected)" }
				else if (code || loc == "init" || loc == "hotplug" || loc == "inittab") {
					if (q ~ /^upgraded/) { prio = 3; why = "replaced by an upgrade of package " pkg " (the package database is writable: a hint, not proof)" }
					else if (fb) { prio = 4; why = "changed by the firmware at first boot" }
					else if (!prog) { prio = 3; why = "data or configuration file of the image changed" }
					else { prio = 1; why = "image program replaced after first boot" }
				}
				else if (loc == "sysupgrade" || loc == "hosts" || loc == "feeds" || loc == "modules") { prio = 3; why = "changed: " loc }
				else if (loc != "") { prio = 2; why = "autostart location changed (" loc ")" }
				else if (p ~ /^\/etc\/(passwd|shadow|group)$/) { prio = 3; why = "accounts changed (normal after setting a password; see users_auth)" }
				else { prio = 4; why = "configuration changed" }
			} else {
				status = "added"
				t = (type == "l") ? fx_resolve(p, $10) : ""
				if (fo_expected(p)) { prio = 5; why = "configuration or device state (expected)" }
				else if (q == "added") { prio = 4; why = "from package " pkg ", installed after flashing" }
				else if (loc == "ssh_keys") { prio = 2; why = "authorized SSH keys added (see users_auth)" }
				else if (p ~ /^\/etc\/rc\.d\// && $10 ~ /^\.\.\/init\.d\/[^\/]+$/) { prio = 4; why = "service enabled or disabled" }
				else if (type == "l" && fo_code(t) && isfile(ENVIRON["FX_ROM"], t) && !isfile(ENVIRON["FX_UP"], t)) { prio = 4; why = "link to a program of the image (" t ")" }
				else if (fb && (code || loc != "")) { prio = 4; why = "created by the firmware at first boot" }
				else if (loc == "sysupgrade" || loc == "hosts" || loc == "feeds" || loc == "modules") { prio = 3; why = "added: " loc }
				else if (loc != "") { prio = 2; why = "autostart entry not in the image (" loc "), no package owns it" }
				else if (code && (exec || type == "l" || p ~ /\.(so|ko)(\.[0-9.]+)?$/)) { prio = 2; why = "program not in the image, no package owns it" }
				else if (code) { prio = 3; why = "file not in the image, no package owns it" }
				else if (exec) { prio = 3; why = "executable outside the system directories" }
				else { prio = 4; why = "added" }
			}
			print prio "\t" p, prio, status, why, $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13
		}' | sort | cut -f3-
}

# ---------------------------------------------------------------- overlay_diff
mcp_register overlay_diff <<'EOF'
{"name":"overlay_diff","title":"Overlay against firmware image","description":"Lists everything the writable overlay adds, changes or deletes compared with the firmware image: per entry status, type, mode, owner, size, mtime, what the image has instead and which package owns the path. Entries are ordered by priority: 1 image programs replaced after first boot, setuid added, ld.so.preload; 2 new programs or autostart entries no package owns, deleted image files; 3 package upgrades, account files, mode changes, changed data files; 4 package installs, what the firmware wrote at first boot, other configuration; 5 expected state (/etc/config, host keys, package database). Use it to answer what differs from the shipped firmware; without an overlay (x86 ext4, initramfs) it says so.","inputSchema":{"type":"object","properties":{"path":{"type":"string","description":"Only entries below this absolute path, e.g. /usr/bin. Default /.","default":"/"},"status":{"type":"string","enum":["all","added","changed","deleted","unchanged"],"description":"Only entries with this status; changed includes mode and owner changes, unchanged are files copied up with identical content. Default all.","default":"all"},"max_priority":{"type":"integer","description":"Only entries of this priority or more urgent (1 = most urgent). Default 5 (everything).","default":5,"minimum":1,"maximum":5},"offset":{"type":"integer","description":"Entries to skip, for paging. Default 0.","default":0,"minimum":0},"max_results":{"type":"integer","description":"Entries to return. Default 200.","default":200,"minimum":1,"maximum":1000}},"additionalProperties":false},"annotations":{"readOnlyHint":true,"openWorldHint":false}}
EOF
tool_overlay_diff() {
	fx_path p path / || return 1
	arg status status all
	case $status in all | added | changed | deleted | unchanged) ;; *) tool_error "status must be all, added, changed, deleted or unchanged, got '$status'"; return 1 ;; esac
	arg_int maxp max_priority 5 1 5 || return 1
	arg_int off offset 0 0 1000000 || return 1
	arg_int max max_results 200 1 1000 || return 1
	if ! up=$(fx_upper); then
		echo "No overlay found: $MCP_UPPER does not exist and the root filesystem is not an overlay mount with a visible upper directory."
		echo "That is normal on x86 images with an ext4 root, on initramfs images and in containers; then there is no separate layer to diff."
		if fx_rom_ok; then
			echo "The firmware image at $MCP_ROM is usable: list_dir, find_files and file_hash still compare single paths with it."
		else
			echo "There is no usable firmware image at $MCP_ROM either, so nothing can be compared with the shipped firmware."
		fi
		return 0
	fi
	if ! fx_rom_ok; then
		echo "Overlay found at $up, but there is no usable firmware image at $MCP_ROM: entries are listed without comparison."
	fi
	rec=$MCP_TMP/overlay.rec
	fo_overlay "$up" "$p" >"$rec"
	printf 'overlay %s against image %s, below %s\n' "$up" "$MCP_ROM" "$p"
	if [ ! -s "$rec" ]; then
		echo "no entries: the overlay changes nothing below $p"
		rm -f "$rec"
		return 0
	fi
	awk -F'\t' '
		{ n[$1]++; s[$2]++; t++ }
		END {
			printf "entries: %d  (added %d, changed %d, mode/owner %d, deleted %d, identical copies %d)\n", t, s["added"], s["changed"], s["mode"], s["deleted"], s["same"]
			printf "by priority: 1 replaced image programs: %d | 2 unowned programs, autostart, deletions: %d | 3 upgrades, accounts, modes: %d | 4 packages, configuration: %d | 5 expected: %d\n", n[1], n[2], n[3], n[4], n[5]
		}' "$rec"
	echo "columns: priority status type mode owner:group bytes mtime path [reason; what the image has; package]"
	echo "notes: package ownership comes from the writable package database (a hint, not proof). Opaque directories (trusted.overlay.opaque) cannot be detected: busybox cannot read xattrs."
	if fbw=$(fx_fbwindow); then
		echo "first boot: entries with mtime and ctime between ${fbw%%"$FX_TAB"*} and ${fbw#*"$FX_TAB"} (the hour after the newest file of the image's /etc, where the clock starts before NTP) count as written by the firmware itself; a forged system clock could place a file there."
	fi
	[ "$(wc -l <"$rec")" -gt 20000 ] && echo "note: more than 20000 overlay entries, the scan stopped there; pass path to scan a subtree"
	echo
	awk -F'\t' -v want="$status" -v maxp="$maxp" -v off="$off" -v max="$max" '
		function names(   l, f) {
			while ((getline l < "/etc/passwd") > 0) { split(l, f, ":"); if (!(f[3] in UN)) UN[f[3]] = f[1] }
			while ((getline l < "/etc/group") > 0) { split(l, f, ":"); if (!(f[3] in GN)) GN[f[3]] = f[1] }
		}
		BEGIN { names() }
		{
			if ($1 > maxp) next
			if (want == "added" && $2 != "added") next
			if (want == "changed" && $2 != "changed" && $2 != "mode") next
			if (want == "deleted" && $2 != "deleted") next
			if (want == "unchanged" && $2 != "same") next
			m++
			if (m <= off || m > off + max) next
			own = (($8 in UN) ? UN[$8] : $8) ":" (($9 in GN) ? GN[$9] : $9)
			x = $3
			if ($5 != "-") x = x "; " $5
			if ($14 != "-") x = x "; package " $14 " (" $15 ")"
			if ($16 == "firstboot" && $2 != "same" && $2 != "deleted") x = x "; written at first boot"
			if ($2 == "deleted") printf "P%s %-7s %s  [%s]\n", $1, $2, $12, x
			else printf "P%s %-7s %s %s %-11s %9s %s %s%s  [%s]\n", $1, $2, $6, $7, own, $10, $11, $12, ($13 != "-") ? " -> " $13 : "", x
		}
		END {
			print ""
			if (m == 0) print "[no entries match the filter]"
			else if (m > off + max) printf "[entries %d-%d of %d matching; continue with offset=%d]\n", off + 1, off + max, m, off + max
			else printf "[entries %d-%d of %d matching, end of list]\n", (m > off) ? off + 1 : m, m, m
		}' "$rec"
	rm -f "$rec"
	return 0
}

# ---------------------------------------------------------------- persistence
# fo_persist: one record per file or link in a persistence location, compared with the
# image. Tab separated:
#   loc state detail type mode uid gid size mtime path target pkg qual fb
# fb is "firstboot" for entries written in the first-boot window (see fx_firstboot).
fo_persist() {
	set -- /etc/crontabs /etc/cron.d /etc/rc.local /etc/init.d /etc/rc.d /etc/rc.common /etc/rc.button \
		/etc/preinit /etc/inittab /etc/hotplug.d /etc/hotplug.json /etc/hotplug-preinit.json \
		/etc/udhcpc.user /etc/udhcpc.user.d /etc/odhcp6c.user /etc/odhcp6c.user.d /etc/ppp \
		/etc/uci-defaults /etc/firewall.user /etc/nftables.d /usr/share/nftables.d /etc/firewall.d \
		/etc/dnsmasq.conf /etc/dnsmasq.d /tmp/dnsmasq.d /etc/profile /etc/profile.d /etc/shinit \
		/root/.profile /root/.shinit /root/.ashrc /root/.bashrc /etc/ld.so.preload /etc/modules.d \
		/etc/modules-boot.d /etc/sysupgrade.conf /lib/upgrade/keep.d /usr/libexec/rpcd /usr/share/rpcd \
		/usr/lib/lua/luci/controller /usr/share/luci/menu.d /usr/share/ucode/luci/controller /www/cgi-bin \
		/etc/opkg.conf /etc/opkg /etc/apk/repositories /etc/apk/repositories.d /etc/apk/keys /etc/hosts
	# hook files that only uci names: firewall includes and the dnsmasq dhcp-script
	{
		fo_uci firewall | sed -n "s/^firewall\.[^.]*\.path='\(\/.*\)'\$/firewall\t\1/p"
		fo_uci dhcp | sed -n "s/^dhcp\.[^.]*\.dhcpscript='\(\/.*\)'\$/dnsmasq\t\1/p"
	} >"$MCP_TMP/persist.extra" 2>/dev/null
	{
		find "$@" -maxdepth 4 ! -type d -print0 2>/dev/null
		fo_keyfiles | tr '\n' '\0'
		cut -f2 "$MCP_TMP/persist.extra" | tr '\n' '\0'
	} | fx_ls | head -n 5000 | fx_cmp "" 1 | fx_pkg | fx_firstboot "" | FX_X="$MCP_TMP/persist.extra" awk -F'\t' "$FO_AWK_LOC"'
		BEGIN {
			OFS = "\t"; split("'"$FO_LOCS"'", o, " "); for (i in o) ord[o[i]] = sprintf("%02d", i)
			while ((getline x < ENVIRON["FX_X"]) > 0) { split(x, f, "\t"); extra[f[2]] = f[1] }
		}
		{
			l = fo_loc($9); if (l == "" && ($9 in extra)) l = extra[$9]
			if (l != "" && !(($9) in seen)) { seen[$9] = 1; print ord[l] "\t" $9, l, $0 }
		}' | sort | cut -f3-
	rm -f "$MCP_TMP/persist.extra"
}

# The authorized_keys files that exist: dropbear's for root, and ~/.ssh of every account.
fo_keyfiles() {
	{
		echo /etc/dropbear/authorized_keys
		awk -F: '$6 != "" && $6 != "/" { print $6 "/.ssh/authorized_keys" }' /etc/passwd 2>/dev/null
		echo /root/.ssh/authorized_keys
	} | awk '!seen[$0]++' | while IFS= read -r _kf; do
		[ -f "$_kf" ] && printf '%s\n' "$_kf"
	done
	return 0
}

fo_loc_title() {
	case $1 in
	cron) echo "scheduled jobs (/etc/crontabs)" ;;
	rc_local) echo "/etc/rc.local, run at the end of every boot" ;;
	init) echo "init scripts (/etc/init.d), the links that enable them (/etc/rc.d), button handlers" ;;
	inittab) echo "/etc/inittab, what procd starts first" ;;
	hotplug) echo "event hooks (hotplug.d, udhcpc/odhcp6c user scripts, ppp ip-up/ip-down)" ;;
	uci_defaults) echo "first-boot scripts (/etc/uci-defaults); they delete themselves after running, a file here runs at the next boot" ;;
	firewall) echo "firewall includes (firewall.user, nftables.d, uci includes): shell or nft code run at every firewall reload" ;;
	dnsmasq) echo "dnsmasq configuration and hooks (dhcp-script runs a program on every lease)" ;;
	profile) echo "shell startup files, run at every login" ;;
	preload) echo "/etc/ld.so.preload, a library loaded into every program (glibc only; musl ignores it)" ;;
	modules) echo "kernel modules loaded at boot (/etc/modules.d, /etc/modules-boot.d)" ;;
	sysupgrade) echo "what survives a firmware upgrade (besides /etc/config and changed package conffiles)" ;;
	rpcd) echo "rpcd plugins and ACLs: code reachable as root through ubus and the web interface" ;;
	luci) echo "LuCI controllers, menu entries and CGI programs" ;;
	feeds) echo "package feeds and signing keys (supply chain)" ;;
	hosts) echo "/etc/hosts, static name resolution" ;;
	ssh_keys) echo "authorized SSH keys (users_auth lists them with fingerprints)" ;;
	esac
}

# Facts about a location that are not files: uci options, whether the service runs.
fo_loc_extra() {
	case $1 in
	cron)
		_ce=$(find /etc/rc.d -maxdepth 1 -name 'S*cron' 2>/dev/null | head -n 1)
		if [ -n "$_ce" ]; then echo "  cron service: enabled ($_ce)"; else echo "  cron service: not enabled (no /etc/rc.d/S*cron), entries would not run"; fi
		;;
	firewall)
		if fo_uci firewall >"$MCP_TMP/persist.uci"; then
			if grep -q '=include$' "$MCP_TMP/persist.uci"; then
				echo "  uci firewall includes:"
				awk -F= '/=include$/ { s[$1] = 1 } { k = $1; sub(/\.[^.]*$/, "", k); if (k in s) print "    " $0 }' "$MCP_TMP/persist.uci"
			else
				echo "  uci firewall includes: none"
			fi
		else
			echo "  uci: not available or no firewall config, includes not read"
		fi
		;;
	dnsmasq)
		if fo_uci dhcp >"$MCP_TMP/persist.uci"; then
			if grep -Eq '\.(dhcpscript|confdir|addnhosts|serversfile|resolvfile|server|address|rebind_domain)=' "$MCP_TMP/persist.uci"; then
				echo "  uci dhcp options that hook or redirect:"
				grep -E '\.(dhcpscript|confdir|addnhosts|serversfile|resolvfile|server|address|rebind_domain)=' "$MCP_TMP/persist.uci" | sed 's/^/    /'
			else
				echo "  uci dhcp: no dhcpscript, confdir, addnhosts, serversfile, server or address options"
			fi
		else
			echo "  uci: not available or no dhcp config, hooks not read"
		fi
		;;
	esac
	rm -f "$MCP_TMP/persist.uci"
}

mcp_register persistence <<'EOF'
{"name":"persistence","title":"Autostart and persistence","description":"Shows every place on the router from which code starts by itself or survives a firmware upgrade: cron, rc.local, init scripts and rc.d links, inittab, hotplug and DHCP/PPP hooks, uci-defaults, firewall includes, dnsmasq hooks, shell profiles, ld.so.preload, kernel module lists, sysupgrade keep lists, rpcd plugins, LuCI additions, package feeds, /etc/hosts and authorized keys. Each entry is marked against the firmware image (same, CHANGED, new); entries that differ are shown with their active lines, identical ones are only named. Use it to answer what starts on its own and from where.","inputSchema":{"type":"object","properties":{"locations":{"type":"array","items":{"type":"string","enum":["cron","rc_local","init","inittab","hotplug","uci_defaults","firewall","dnsmasq","profile","preload","modules","sysupgrade","rpcd","luci","feeds","hosts","ssh_keys"]},"description":"Only these locations. Default: all."},"only_changed":{"type":"boolean","description":"Leave out entries that are identical to the firmware image. Default false.","default":false},"max_lines":{"type":"integer","description":"Active lines shown per file (comments and blank lines are skipped). Default 40.","default":40,"minimum":0,"maximum":400}},"additionalProperties":false},"annotations":{"readOnlyHint":true,"openWorldHint":false}}
EOF
tool_persistence() {
	arg_int maxl max_lines 40 0 400 || return 1
	only=0
	arg_bool only_changed false && only=1
	want=$(arg_list locations | tr '\n' ' ')
	for l in $want; do
		case " $FO_LOCS " in *" $l "*) ;; *) tool_error "unknown location '$l'; known: $FO_LOCS"; return 1 ;; esac
	done
	rec=$MCP_TMP/persist.rec
	fo_persist >"$rec"
	if fx_rom_ok; then
		echo "Entries are compared with the firmware image at $MCP_ROM: [same] identical, [CHANGED] differs, [new] not in the image, [meta] same content, other mode or owner."
	else
		echo "No usable firmware image at $MCP_ROM: entries cannot be marked as changed or new ([-]); judge them by content and mtime."
	fi
	for loc in $FO_LOCS; do
		if [ -n "$want" ]; then
			case " $want " in *" $loc "*) ;; *) continue ;; esac
		fi
		section "$loc: $(fo_loc_title "$loc")"
		fo_loc_extra "$loc"
		awk -F'\t' -v l="$loc" '$1 == l' "$rec" >"$rec.l"
		if [ ! -s "$rec.l" ]; then
			echo "  (no files)"
			continue
		fi
		if [ "$only" = 1 ] && ! grep -qv "^$loc$FX_TAB""same$FX_TAB" "$rec.l"; then
			echo "  ($(wc -l <"$rec.l") entries, none differs from the image)"
			continue
		fi
		case $loc in
		cron | rc_local | preload) class=always ;;
		init | hotplug | uci_defaults | rpcd | luci | modules) class=scripts ;;
		ssh_keys) class=keys ;;
		*) class=lines ;;
		esac
		nquiet=0
		while IFS="$FX_TAB" read -r _ st det ty mo ui gi sz mt path tg pkg qual fb; do
			case $st in same) mark="[same]" ;; changed) mark="[CHANGED]" ;; new) mark="[new]" ;; meta) mark="[meta]" ;; noimage) mark="[-]" ;; *) mark="[?]" ;; esac
			if [ "$st" = same ] && [ "$only" = 1 ]; then continue; fi
			if [ "$class" = scripts ] || [ "$class" = lines ]; then
				if [ "$st" = same ] || { [ "$st" = noimage ] && [ "$class" = scripts ]; }; then
					nquiet=$((nquiet + 1))
					continue
				fi
			fi
			printf '  %s %s' "$mark" "$path"
			[ "$tg" != - ] && printf ' -> %s' "$tg"
			printf '  (%s %s %s:%s, %s bytes, %s' "$ty" "$mo" "$ui" "$gi" "$sz" "$mt"
			[ "$det" != - ] && printf '; %s' "$det"
			if [ "$pkg" != - ]; then printf '; package %s, %s' "$pkg" "$qual"; else printf '; no package'; fi
			[ "$fb" = firstboot ] && [ "$st" != same ] && printf '; written at first boot'
			printf ')\n'
			[ "$ty" = f ] || continue
			if [ "$class" = keys ]; then
				printf '      %s key lines\n' "$(rd "$path" | grep -c '^[^#]')"
			elif [ "$class" = scripts ] && [ "$qual" = added ]; then
				echo "      (installed by package $pkg after flashing; read_file shows it)"
			elif [ "$maxl" -gt 0 ]; then
				fx_show "$path" "$maxl"
			fi
		done <"$rec.l"
		if [ "$nquiet" -gt 0 ]; then
			# named per directory, so that two files of the same name stay apart
			awk -F'\t' -v cls="$class" '
				$2 == "same" || ($2 == "noimage" && cls == "scripts") {
					d = $10; sub(/\/[^\/]*$/, "", d); b = $10; sub(/.*\//, "", b)
					if (!(d in n)) order[++k] = d
					n[d]++; names[d] = names[d] " " b; lab[d] = ($2 == "same") ? "[same] as in the image" : "[-] present, not compared"
				}
				END { for (i = 1; i <= k; i++) printf "  %s, %s (%d):%s\n", lab[order[i]], order[i], n[order[i]], names[order[i]] }' "$rec.l"
		fi
	done
	rm -f "$rec" "$rec.l"
	return 0
}

# ---------------------------------------------------------------- users_auth
# fo_accounts: one line per account, tab separated:
#   name uid gid home shell pwstate changed flags
# pwstate: EMPTY | none | locked | set:<algorithm>   flags: comma list or "-"
fo_accounts() {
	_ap=$(rom_path /etc/passwd)
	[ -f "$_ap" ] || _ap=/dev/null
	_as=/etc/shadow
	[ -r "$_as" ] || _as=/dev/null
	FX_S="$_as" FX_RP="$_ap" awk -F: '
	function day2date(d,   z, era, doe, yoe, y, doy, mp, m, dd) {
		z = d + 719468; era = int(z / 146097); doe = z - era * 146097
		yoe = int((doe - int(doe / 1460) + int(doe / 36524) - int(doe / 146096)) / 365)
		y = yoe + era * 400; doy = doe - (365 * yoe + int(yoe / 4) - int(yoe / 100))
		mp = int((5 * doy + 2) / 153); dd = doy - int((153 * mp + 2) / 5) + 1
		m = (mp < 10) ? mp + 3 : mp - 9; if (m <= 2) y++
		return sprintf("%04d-%02d-%02d", y, m, dd)
	}
	function pwstate(h) {
		if (h == "") return "EMPTY"
		if (h == "*" || h == "x" || h == "!" || h == "!!" || h == "*LK*") return "none"
		if (substr(h, 1, 1) == "!") return "locked"
		if (h ~ /^\$1\$/) return "set:md5crypt"
		if (h ~ /^\$5\$/) return "set:sha256crypt"
		if (h ~ /^\$6\$/) return "set:sha512crypt"
		if (h ~ /^\$2[abxy]?\$/) return "set:bcrypt"
		if (h ~ /^\$y\$/) return "set:yescrypt"
		if (h ~ /^\$/) return "set:unknown-scheme"
		return "set:des-crypt"
	}
	BEGIN { OFS = "\t" }
	FILENAME == ENVIRON["FX_S"] { sh[$1] = $2; hs[$1] = 1; ch[$1] = $3; next }
	FILENAME == ENVIRON["FX_RP"] { rom[$1] = $0; hasrom = 1; next }
	/^[ \t]*(#|$)/ { next }
	{
		h = $2; src = "passwd"
		if (h == "x" && ($1 in hs)) { h = sh[$1]; src = "shadow" }
		else if (h == "x") src = "noshadow"
		st = pwstate(h)
		if (src == "noshadow") st = "none"
		c = "-"
		if (src == "shadow" && ch[$1] ~ /^[0-9]+$/ && ch[$1] > 0) c = day2date(ch[$1])
		f = ""
		if ($3 == 0 && $1 != "root") f = f ",UID0"
		if ($7 != "" && $7 !~ /(false|nologin)$/) f = f ",login-shell"
		if (src == "passwd" && st ~ /^set/) f = f ",hash-in-passwd"
		if (hasrom && !($1 in rom)) f = f ",not-in-image"
		print $1, $3, $4, ($6 == "") ? "-" : $6, ($7 == "") ? "-" : $7, st, c, (f == "") ? "-" : substr(f, 2)
	}' "$_as" "$_ap" /etc/passwd 2>/dev/null
}

# fo_keys: one line per authorized key, tab separated:
#   file line type bits comment options inimage octal-blob
# inimage: yes | no | - (no image). The blob is the decoded key as printf octal escapes,
# for fingerprinting.
fo_keys() {
	fo_keyfiles >"$MCP_TMP/keys.files"
	: >"$MCP_TMP/keys.rom"
	if fx_rom_ok; then
		while IFS= read -r _kf; do
			rd "$(rom_path "$_kf")"
		done <"$MCP_TMP/keys.files" >"$MCP_TMP/keys.rom" 2>/dev/null
	fi
	while IFS= read -r _kf; do
		rd "$_kf" | FX_KF="$_kf" FX_KR="$MCP_TMP/keys.rom" FX_HASROM="$(fx_rom_ok && echo 1 || echo 0)" awk '
		function b64dec(s,   i, v, bits, c) {
			BN = 0; v = 0; bits = 0
			for (i = 1; i <= length(s); i++) {
				c = index("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/", substr(s, i, 1)) - 1
				if (c < 0) continue
				v = v * 64 + c; bits += 6
				if (bits >= 8) { bits -= 8; B[++BN] = int(v / pw[bits]); v = v % pw[bits] }
			}
		}
		function u32(o) { return ((B[o] * 256 + B[o + 1]) * 256 + B[o + 2]) * 256 + B[o + 3] }
		function keyfield(   i) {
			for (i = 1; i < NF; i++) if ($i ~ /^(ssh-(rsa|dss|ed25519)|ecdsa-sha2-[a-z0-9]+|sk-[a-z0-9@.-]+)$/ && $(i + 1) ~ /^AAAA[A-Za-z0-9+\/=]+$/) return i
			return 0
		}
		BEGIN {
			OFS = "\t"; pw[0] = 1; pw[2] = 4; pw[4] = 16; pw[6] = 64
			while ((getline l < ENVIRON["FX_KR"]) > 0) { n = split(l, f, /[ \t]+/); for (i = 1; i <= n; i++) if (f[i] ~ /^AAAA/) rom[f[i]] = 1 }
		}
		/^[ \t]*(#|$)/ { next }
		{
			k = keyfield()
			if (!k) { print ENVIRON["FX_KF"], NR, "unparsed", "-", "-", "-", "-", "-"; next }
			type = $k; blob = $(k + 1)
			# no "var (expr)": busybox 1.33 awk would read that as a function call
			com = ""; for (i = k + 2; i <= NF; i++) { if (com != "") com = com " "; com = com $i }
			opt = ""; for (i = 1; i < k; i++) { if (opt != "") opt = opt " "; opt = opt $i }
			b64dec(blob)
			bits = "-"
			if (type == "ssh-ed25519") bits = 256
			else if (type ~ /nistp256/) bits = 256
			else if (type ~ /nistp384/) bits = 384
			else if (type ~ /nistp521/) bits = 521
			else if (type == "ssh-rsa" || type == "ssh-dss") {
				o = 1; o += 4 + u32(o)          # key type string
				o += 4 + u32(o)                 # rsa: e, dss: p follows directly
				if (type == "ssh-dss") o = 1 + 4 + u32(1)
				n = u32(o); if (B[o + 4] == 0) n--
				bits = n * 8
			}
			oct = ""; for (i = 1; i <= BN; i++) oct = oct sprintf("\\%03o", B[i])
			print ENVIRON["FX_KF"], NR, type, bits, (com == "") ? "-" : com, (opt == "") ? "-" : opt, \
				(ENVIRON["FX_HASROM"] == 1) ? ((blob in rom) ? "yes" : "no") : "-", oct
		}'
	done <"$MCP_TMP/keys.files"
	rm -f "$MCP_TMP/keys.files" "$MCP_TMP/keys.rom"
}

# stdin: printf octal escapes of a key blob. stdout: its OpenSSH fingerprint.
fo_fingerprint() {
	IFS= read -r _fo
	# shellcheck disable=SC2059
	printf "$_fo" | sha256sum | awk '
		function hex(h,   i, n) { n = 0; for (i = 1; i <= length(h); i++) n = n * 16 + index("0123456789abcdef", substr(h, i, 1)) - 1; return n }
		{
			a = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"; out = ""; v = 0; bits = 0
			pw[0] = 1; pw[2] = 4; pw[4] = 16; pw[6] = 64; pw[1] = 2; pw[3] = 8; pw[5] = 32; pw[7] = 128
			for (i = 1; i <= 64; i += 2) {
				v = v * 256 + hex(substr($1, i, 2)); bits += 8
				while (bits >= 6) { bits -= 6; out = out substr(a, int(v / pw[bits]) + 1, 1); v = v % pw[bits] }
			}
			if (bits > 0) out = out substr(a, v * pw[6 - bits] + 1, 1)
			print "SHA256:" out
		}'
}

# fo_keys_table: the keys as readable lines (used by users_auth and the audit).
fo_keys_table() {
	fo_keys | while IFS="$FX_TAB" read -r kf ln type bits com opt inimg oct; do
		if [ "$type" = unparsed ]; then
			printf '%s line %s: not a key line this tool understands (read_file shows it)\n' "$kf" "$ln"
			continue
		fi
		fp=$(printf '%s\n' "$oct" | fo_fingerprint)
		printf '%s line %s: %s %s bits  %s  comment "%s"' "$kf" "$ln" "$type" "$bits" "$fp" "$com"
		[ "$opt" != - ] && printf '  options: %s' "$opt"
		case $inimg in yes) printf '  [in the image]' ;; no) printf '  [not in the image]' ;; esac
		printf '\n'
	done
}

# fo_dropbear: one line per dropbear instance, tab separated:
#   section enabled port interface password_auth root_password_auth root_login
fo_dropbear() {
	fo_uci dropbear | awk '
		function val(s) { sub(/^[^=]*=/, "", s); gsub(/\047/, "", s); return s }
		function on(v, d) { if (v == "") return d; return (v == "on" || v == "1" || v == "yes" || v == "true") ? "on" : "off" }
		/=dropbear$/ { s = $0; sub(/=dropbear$/, "", s); order[++n] = s; next }
		{
			k = $0; sub(/=.*/, "", k); o = k; sub(/.*\./, "", o); sub(/\.[^.]*$/, "", k)
			v[k, o] = val($0)
		}
		END {
			OFS = "\t"
			for (i = 1; i <= n; i++) {
				s = order[i]
				print s, on(v[s, "enable"], "on"), (v[s, "Port"] == "") ? "22" : v[s, "Port"], (v[s, "Interface"] == "") ? "all" : v[s, "Interface"], \
					on(v[s, "PasswordAuth"], "on"), on(v[s, "RootPasswordAuth"], "on"), on(v[s, "RootLogin"], "on")
			}
		}'
}

mcp_register users_auth <<'EOF'
{"name":"users_auth","title":"Accounts and logins","description":"Shows who can log in and how: accounts with uid, shell and password state (empty, none, locked, or the hash algorithm, never the hash), accounts with uid 0 besides root, authorized SSH keys with type, size, comment and SHA256 fingerprint, the dropbear and OpenSSH settings (password login, root login, ports, interfaces) with the sockets they listen on, and the web login configuration of uhttpd, rpcd and LuCI (plus GL.iNet's web interface when present). Use it to check authentication; it never prints a secret, with or without redaction.","inputSchema":{"type":"object","properties":{},"additionalProperties":false},"annotations":{"readOnlyHint":true,"openWorldHint":false}}
EOF
tool_users_auth() {
	section "Accounts (/etc/passwd, /etc/shadow)"
	[ -r /etc/shadow ] || echo "note: /etc/shadow is not readable, password states come from /etc/passwd only"
	fo_accounts | awk -F'\t' '
		BEGIN { printf "%-12s %-11s %-22s %-14s %-32s %-11s %s\n", "name", "uid:gid", "home", "shell", "password", "changed", "flags" }
		{
			pw = $6
			if (pw == "EMPTY") pw = "EMPTY (login without one)"
			else if (pw == "none") pw = "none (no password login)"
			else if (pw == "locked") pw = "locked"
			else { sub(/^set:/, "", pw); pw = "set, " pw }
			printf "%-12s %-11s %-22s %-14s %-32s %-11s %s\n", $1, $2 ":" $3, $4, $5, pw, $7, $8
			if ($8 ~ /UID0/) u0 = u0 " " $1
			if ($6 == "EMPTY") em = em " " $1
		}
		END {
			print ""
			print "uid 0 besides root:" ((u0 == "") ? " none" : u0 "  <- full root rights under another name")
			print "empty passwords:" ((em == "") ? " none" : em)
		}'
	fx_rom_ok || echo "(no usable firmware image: accounts cannot be compared with the shipped /etc/passwd)"

	section "Authorized SSH keys"
	keys=$(fo_keys_table)
	if [ -n "$keys" ]; then
		printf '%s\n' "$keys"
	else
		echo "none (checked /etc/dropbear/authorized_keys and ~/.ssh/authorized_keys of every account)"
	fi

	section "SSH server"
	if [ -f /etc/config/dropbear ] || have dropbear; then
		if fo_dropbear >"$MCP_TMP/ua.db" && [ -s "$MCP_TMP/ua.db" ]; then
			awk -F'\t' '{ printf "dropbear %s: %s, port %s, interface %s, password login %s, root password login %s, root login %s\n", $1, ($2 == "on") ? "enabled" : "DISABLED", $3, $4, $5, $6, $7 }' "$MCP_TMP/ua.db"
		elif have uci; then
			echo "dropbear: no instance in /etc/config/dropbear"
		else
			echo "uci: not available; /etc/config/dropbear as text:"
			fx_show /etc/config/dropbear 40
		fi
	else
		echo "dropbear: not installed"
	fi
	rm -f "$MCP_TMP/ua.db"
	if [ -f /etc/ssh/sshd_config ]; then
		echo "OpenSSH /etc/ssh/sshd_config, active lines:"
		fx_show /etc/ssh/sshd_config 60
		echo "    (defaults when unset: PermitRootLogin prohibit-password, PasswordAuthentication yes, Port 22)"
	else
		echo "OpenSSH: no /etc/ssh/sshd_config"
	fi
	echo "listening SSH sockets:"
	lib_sockets | awk -F'\t' '$2 == "LISTEN" && ($9 ~ /dropbear|sshd/ || $4 == 22) { printf "  %s %s:%s pid %s (%s)\n", $1, $3, $4, $8, $9; n++ } END { if (!n) print "  none" }'

	section "Web interface and ubus logins"
	if fo_uci uhttpd >"$MCP_TMP/ua.uci"; then
		echo "uhttpd:"
		grep -E '\.(listen_https?|no_ubusauth|rfc1918_filter|redirect_https|ubus_prefix|home|httpauth|realm|config)=|=httpauth$|\.(prefix|username)=' "$MCP_TMP/ua.uci" | redact | sed 's/^/  /'
		if grep -q "no_ubusauth='1'" "$MCP_TMP/ua.uci"; then echo "  WARNING: no_ubusauth=1, ubus over HTTP needs no login"; fi
	elif [ -f /etc/config/uhttpd ]; then
		echo "uhttpd: uci: not available, /etc/config/uhttpd not parsed"
	else
		echo "uhttpd: no /etc/config/uhttpd"
	fi
	if fo_uci rpcd >"$MCP_TMP/ua.uci"; then
		echo "rpcd logins (who may open a ubus session over HTTP):"
		awk '
			function val(s) { sub(/^[^=]*=/, "", s); gsub(/\047/, "", s); return s }
			/=login$/ { s = $0; sub(/=login$/, "", s); order[++n] = s; next }
			{ k = $0; sub(/=.*/, "", k); o = k; sub(/.*\./, "", o); sub(/\.[^.]*$/, "", k); v[k, o] = val($0) }
			END {
				for (i = 1; i <= n; i++) {
					s = order[i]; p = v[s, "password"]
					if (p == "") t = "no password option"
					else if (p ~ /^\$p\$/) t = "the system password of user " substr(p, 4)
					else if (p ~ /^\$[0-9a-z]+\$/) t = "its own crypt hash (not shown)"
					else t = "another form, possibly plain text (not shown)"
					printf "  %s: username %s, password: %s, read %s, write %s\n", s, v[s, "username"], t, (v[s, "read"] == "") ? "-" : v[s, "read"], (v[s, "write"] == "") ? "-" : v[s, "write"]
				}
				if (!n) print "  none configured"
			}' "$MCP_TMP/ua.uci"
	else
		echo "rpcd: no /etc/config/rpcd or uci not available"
	fi
	if fo_uci luci >"$MCP_TMP/ua.uci"; then
		grep -E '\.sessiontime=' "$MCP_TMP/ua.uci" | sed 's/^/LuCI session: /'
	fi
	rm -f "$MCP_TMP/ua.uci"
	echo "listening web sockets:"
	lib_sockets | awk -F'\t' '$2 == "LISTEN" && $9 ~ /uhttpd|nginx|lighttpd|httpd/ { printf "  %s %s:%s pid %s (%s)\n", $1, $3, $4, $8, $9; n++ } END { if (!n) print "  none" }'

	if [ -f /etc/glversion ] || [ -f /etc/config/glconfig ]; then
		section "GL.iNet web interface"
		[ -f /etc/glversion ] && printf 'firmware %s\n' "$(rd /etc/glversion | head -n 1)"
		echo "GL.iNet firmware 4.x checks the web login against root's entry in /etc/shadow (see the accounts table);"
		echo "an EMPTY or unset root password there means the web interface was never set up or was reset."
		for g in oui-httpd glconfig; do
			if fo_uci "$g" >"$MCP_TMP/ua.uci"; then
				echo "uci $g (login related options):"
				grep -Ei 'passw|login|inited|init_status|lang|session|token' "$MCP_TMP/ua.uci" | redact | head -n 20 | sed 's/^/  /'
			fi
		done
		rm -f "$MCP_TMP/ua.uci"
	fi
	return 0
}
