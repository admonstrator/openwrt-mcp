# Shared readers that more than one tool module needs. Contract file: tool modules call
# these, only the owner of 20-network.sh changes them, and only without changing the
# output format.

# lib_sockets: one line per IPv4/IPv6 socket from /proc/net, tab separated:
#   proto  state  local_addr  local_port  remote_addr  remote_port  inode  pid  comm
# proto  tcp tcp6 udp udp6 raw raw6
# state  LISTEN ESTABLISHED TIME_WAIT ... for tcp; UNCONN or ESTABLISHED for udp and raw
# addr   IPv4 dotted quad, IPv6 in compressed form (::, ::1, fe80::1)
# port   decimal; for raw sockets the IP protocol number
# pid    the first process holding the socket, "-" when none was found (kernel sockets,
#        or a process that exited); comm is its /proc/PID/comm, "-" likewise
lib_sockets() {
	{
		# inode -> pid map first, tagged "M"; then the socket tables, tagged by proto.
		# ls, not find -exec readlink: one process for all links, names are only digits.
		# shellcheck disable=SC2012
		ls -l /proc/[0-9]*/fd 2>/dev/null | awk '
			/^\/proc\/[0-9]+\/fd:$/ { split($0, p, "/"); pid = p[3]; next }
			/socket:\[/ { s = $NF; gsub(/[^0-9]/, "", s); if (!(s in seen)) { seen[s] = 1; print "M", s, pid } }'
		for _p in tcp tcp6 udp udp6 raw raw6; do
			[ -r "/proc/net/$_p" ] || continue
			awk -v proto="$_p" 'NR > 1 { print "S", proto, $2, $3, $4, $10 }' "/proc/net/$_p"
		done
	} | awk '
	function hex(h,   i, n, c) {
		n = 0; h = toupper(h)
		for (i = 1; i <= length(h); i++) { c = index("0123456789ABCDEF", substr(h, i, 1)) - 1; n = n * 16 + c }
		return n
	}
	function v4(h) {   # little-endian 32-bit word
		return hex(substr(h, 7, 2)) "." hex(substr(h, 5, 2)) "." hex(substr(h, 3, 2)) "." hex(substr(h, 1, 2))
	}
	function v6(h,   w, i, g, out, word, best, bl, cs, cl, parts) {
		# four little-endian 32-bit words -> eight groups
		g = 0
		for (w = 0; w < 4; w++) {
			word = substr(h, w * 8 + 1, 8)
			word = substr(word, 7, 2) substr(word, 5, 2) substr(word, 3, 2) substr(word, 1, 2)
			parts[++g] = hex(substr(word, 1, 4)); parts[++g] = hex(substr(word, 5, 4))
		}
		if (parts[1] == 0 && parts[2] == 0 && parts[3] == 0 && parts[4] == 0 && parts[5] == 0 && parts[6] == 65535)
			return "::ffff:" int(parts[7] / 256) "." (parts[7] % 256) "." int(parts[8] / 256) "." (parts[8] % 256)
		# longest run of zero groups (at least two) becomes ::
		best = 0; bl = 0; cs = 0; cl = 0
		for (i = 1; i <= 8; i++) {
			if (parts[i] == 0) { if (cl == 0) cs = i; cl++; if (cl > bl) { bl = cl; best = cs } }
			else cl = 0
		}
		if (bl < 2) best = 0
		out = ""
		for (i = 1; i <= 8; i++) {
			if (best && i == best) { out = out "::"; i += bl - 1; continue }
			if (out != "" && substr(out, length(out)) != ":") out = out ":"
			out = out sprintf("%x", parts[i])
		}
		return out
	}
	BEGIN {
		split("ESTABLISHED SYN_SENT SYN_RECV FIN_WAIT1 FIN_WAIT2 TIME_WAIT CLOSE CLOSE_WAIT LAST_ACK LISTEN CLOSING NEW_SYN_RECV", st, " ")
		OFS = "\t"
	}
	$1 == "M" { owner[$2] = $3; next }
	$1 == "S" {
		proto = $2
		split($3, l, ":"); split($4, r, ":")
		if (proto ~ /6$/) { la = v6(l[1]); ra = v6(r[1]) } else { la = v4(l[1]); ra = v4(r[1]) }
		s = hex($5)
		if (proto ~ /^tcp/) state = (s in st) ? st[s] : "STATE_" $5
		else state = (s == 1) ? "ESTABLISHED" : "UNCONN"
		inode = $6
		pid = (inode in owner) ? owner[inode] : "-"
		comm = "-"
		if (pid != "-") { f = "/proc/" pid "/comm"; if ((getline comm < f) <= 0) comm = "-"; close(f); gsub(/[\001-\037\177]/, "?", comm) }
		print proto, state, la, hex(l[2]), ra, hex(r[2]), inode, pid, comm
	}'
}

# lib_procs: one line per process from /proc (no ps), tab separated:
#   pid  ppid  uid  state  rss_kb  start  kthread  comm  exe  cmdline
# uid    real uid from /proc/PID/status
# rss_kb VmRSS in kB, "-" for kernel threads
# start  start time in seconds since the epoch (btime + starttime / USER_HZ, which is
#        100 on every Linux architecture OpenWrt builds for)
# kthread 1 for kernel threads (PF_KTHREAD, or kthreadd and its children)
# exe    the /proc/PID/exe target as the kernel prints it (may end in " (deleted)"),
#        "-" when unreadable (kernel threads, zombies)
# cmdline arguments joined by single spaces, tabs and newlines turned into spaces;
#        empty for kernel threads
# Sorted by pid. One ls, one grep, one cat and one tr per process; no ps, no per-file
# readlink.
lib_procs() {
	{
		awk '$1 == "btime" { printf "B\t%s\n", $2 }' /proc/stat 2>/dev/null
		# shellcheck disable=SC2012
		ls -l /proc/[0-9]*/exe 2>/dev/null | awk '{
			i = index($0, " /proc/"); if (!i) next
			s = substr($0, i + 7); j = index(s, "/exe -> "); if (!j) next
			printf "E\t%s\t%s\n", substr(s, 1, j - 1), substr(s, j + 8) }'
		grep -H -E '^(Uid|VmRSS):' /proc/[0-9]*/status 2>/dev/null
		# stat and cmdline per process with control characters replaced: a comm or an
		# argument holding a newline or tab cannot split or forge a record
		for _d in /proc/[0-9]*; do
			printf 'C\t%s\t' "${_d#/proc/}"
			tr '\000-\037\177' ' ' <"$_d/cmdline" 2>/dev/null
			printf '\nS\t%s\t' "${_d#/proc/}"
			tr '\000-\037\177' '?' <"$_d/stat" 2>/dev/null
			echo
		done
	} | awk -F '\t' '
	$1 == "B" { btime = $2; next }
	$1 == "E" { exe[$2] = $3; next }
	$1 == "C" { c = $3; sub(/ +$/, "", c); cmd[$2] = c; next }
	/^\/proc\/[0-9]+\/status:/ {
		split($0, p, "/"); pid = p[3]
		if (index($0, ":Uid:")) uid[pid] = $2
		else { v = $0; sub(/^.*VmRSS:[ \t]*/, "", v); sub(/ .*/, "", v); rss[pid] = v }
		next
	}
	$1 == "S" {
		line = $3; sub(/\?+$/, "", line)
		pid = $2
		if (substr(line, 1, length(pid) + 2) != pid " (") next
		# comm may contain spaces and parentheses: it ends at the last ")"
		o = index(line, "("); r = 0
		for (i = length(line); i > o; i--) if (substr(line, i, 1) == ")") { r = i; break }
		if (!r) next
		comm = substr(line, o + 1, r - o - 1); gsub(/\t/, " ", comm)
		n = split(substr(line, r + 2), f, " ")
		state[pid] = f[1]; ppid[pid] = f[2]; pflags[pid] = f[7]; stime[pid] = f[20]
		name[pid] = comm; order[++np] = pid
		next
	}
	END {
		OFS = "\t"
		for (k = 1; k <= np; k++) {
			pid = order[k]
			kt = (pid == 2 || ppid[pid] == 2 || and(pflags[pid], 2097152)) ? 1 : 0
			st = (btime != "") ? int(btime + stime[pid] / 100) : 0
			print pid, ppid[pid], (pid in uid) ? uid[pid] : "-", state[pid], \
				(pid in rss) ? rss[pid] : "-", st, kt, name[pid], \
				(pid in exe) ? exe[pid] : "-", (pid in cmd) ? cmd[pid] : ""
		}
	}' | sort -n
}

# lib_fd_inodes: "inode pid" for every socket a process holds (first holder wins),
# the same map lib_sockets builds; for unix sockets and per-process views.
lib_fd_inodes() {
	# shellcheck disable=SC2012
	ls -l /proc/[0-9]*/fd 2>/dev/null | awk '
		/^\/proc\/[0-9]+\/fd:$/ { split($0, p, "/"); pid = p[3]; next }
		/socket:\[/ { s = $NF; gsub(/[^0-9]/, "", s); if (!(s in seen)) { seen[s] = 1; print s, pid } }'
}

# lib_rom_ok: exit status 0 when MCP_ROM looks like a firmware image root that files
# can be compared against (squashfs /rom on a real router): it has etc/, bin/, usr/ or
# lib/. Containers, ext4 and
# initramfs images have none; callers then skip "not in firmware image" flags instead
# of flagging every file.
lib_rom_ok() {
	[ -d "$MCP_ROM/etc" ] || [ -d "$MCP_ROM/bin" ] || [ -d "$MCP_ROM/usr" ] || [ -d "$MCP_ROM/lib" ]
}

# lib_upper: print the overlay upper directory; print nothing and fail when there is
# none. MCP_UPPER when it exists; with the default MCP_UPPER also the upperdir of an
# overlay root mount, then /userdata/overlay/upper (some GL.iNet models).
lib_upper() {
	if [ -d "$MCP_UPPER" ]; then
		printf '%s\n' "${MCP_UPPER%/}"
		return 0
	fi
	# an explicit MCP_UPPER that does not exist means "no overlay"; only the default
	# value falls back to the root mount's upperdir and the GL.iNet location
	[ "$MCP_UPPER" = /overlay/upper ] || return 1
	_lu=$(awk '$2 == "/" && $3 == "overlay" {
		n = split($4, o, ","); for (i = 1; i <= n; i++) if (o[i] ~ /^upperdir=/) u = substr(o[i], 10)
	} END { print u }' /proc/mounts 2>/dev/null)
	if [ -n "$_lu" ] && [ -d "$_lu" ]; then
		printf '%s\n' "${_lu%/}"
		return 0
	fi
	if [ -d /userdata/overlay/upper ]; then
		echo /userdata/overlay/upper
		return 0
	fi
	return 1
}

# lib_ubus OBJECT METHOD [JSON]: ubus call with a 10 s limit; non-zero when ubus is
# missing, ubusd has no socket or does not answer. Output is ubus' indented JSON.
# Redirect the output to a file: run_timeout's watchdog may hold a pipe open.
lib_ubus() {
	have ubus || return 1
	[ -S /var/run/ubus/ubus.sock ] || [ -S /var/run/ubus.sock ] || [ -S /tmp/run/ubus/ubus.sock ] || return 1
	run_timeout 10 ubus call "$@" 2>/dev/null
}

# lib_uci_dump PACKAGE: the uci package in a form awk can read, tab separated:
#   S  section  type
#   O  section  option  value      (one line per list element)
# Anonymous sections are named @type[N] as "uci show" does. Uses uci when present,
# else parses /etc/config/PACKAGE. Values are NOT redacted: print only options that
# cannot hold secrets, or pass the output through redact.
lib_uci_dump() {
	case $1 in '' | *[!A-Za-z0-9_-]*) return 1 ;; esac
	if have uci; then
		uci -q show "$1" 2>/dev/null | awk -v pkg="$1" '
		function vals(s,   i, c, q, cur, st) {
			nv = 0; cur = ""; q = ""; st = 0
			for (i = 1; i <= length(s); i++) {
				c = substr(s, i, 1)
				if (q != "") { if (c == q) q = ""; else cur = cur c; continue }
				if (c == "'"'"'" || c == "\"") { q = c; st = 1; continue }
				if (c == "\\" && i < length(s)) { cur = cur substr(s, i + 1, 1); i++; st = 1; continue }
				if (c == " ") { if (st) { v[++nv] = cur; cur = ""; st = 0 } continue }
				cur = cur c; st = 1
			}
			if (st) v[++nv] = cur
		}
		{
			e = index($0, "="); if (!e) next
			key = substr($0, 1, e - 1); val = substr($0, e + 1)
			if (substr(key, 1, length(pkg) + 1) != pkg ".") next
			key = substr(key, length(pkg) + 2)
			d = index(key, ".")
			if (!d) { printf "S\t%s\t%s\n", key, val; next }
			vals(val)
			for (i = 1; i <= nv; i++) printf "O\t%s\t%s\t%s\n", substr(key, 1, d - 1), substr(key, d + 1), v[i]
		}'
	else
		rd "/etc/config/$1" | awk '
		function vals(s,   i, c, q, cur, st) {
			nv = 0; cur = ""; q = ""; st = 0
			for (i = 1; i <= length(s); i++) {
				c = substr(s, i, 1)
				if (q != "") { if (c == q) q = ""; else cur = cur c; continue }
				if (c == "'"'"'" || c == "\"") { q = c; st = 1; continue }
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
	fi
}

# lib_cfg_snapshot DIR: record the uci configuration (/etc/config) in DIR, one file per
# package, so that lib_cfg_changes can show afterwards what a write tool changed. Each
# file holds "uci -q show PACKAGE" (the raw file where uci is missing or the name has a
# dot, which uci would read as package.section). DIR is created; keep it below the
# call's work directory. Not redacted: lib_cfg_changes redacts what it prints.
lib_cfg_snapshot() {
	mkdir -p "$1" || return 1
	for _cs_f in /etc/config/*; do
		[ -f "$_cs_f" ] || continue
		_cs_p=${_cs_f##*/}
		case $_cs_p in '' | *[!A-Za-z0-9_.-]*) continue ;; esac
		case $_cs_p in
		*.*) rd "$_cs_f" >"$1/$_cs_p" ;;
		*) if have uci; then uci -q show "$_cs_p" >"$1/$_cs_p" 2>/dev/null || :; else rd "$_cs_f" >"$1/$_cs_p"; fi ;;
		esac
	done
	return 0
}

# lib_cfg_changes DIR [MAX]: compare the snapshot in DIR with /etc/config now and print,
# redacted, per changed package "config PACKAGE: N removed, M added" and the lines
# ("- " before, "+ " after; at most MAX per package, default 60). New and removed
# packages are named. Prints "no change in /etc/config" when nothing differs. Lines
# are compared as a multiset, so a reordered list or a renumbered anonymous section
# (@rule[3] becomes @rule[2] after a delete) shows up as removed plus added.
lib_cfg_changes() {
	_cc_b=${1%/}
	_cc_max=${2:-60}
	_cc_a=$_cc_b.after
	rm -rf "$_cc_a"
	lib_cfg_snapshot "$_cc_a" || return 1
	_cc_any=0
	for _cc_p in $({ ls "$_cc_b"; ls "$_cc_a"; } 2>/dev/null | sort -u); do
		if [ ! -f "$_cc_b/$_cc_p" ]; then
			printf 'config %s: new package\n' "$_cc_p"
			_cc_any=1
			continue
		fi
		if [ ! -f "$_cc_a/$_cc_p" ]; then
			printf 'config %s: package removed\n' "$_cc_p"
			_cc_any=1
			continue
		fi
		# removed: in before, not (as often) in after; added: the other way round.
		# redact sees the bare lines (its uci and config patterns are anchored)
		awk 'NR == FNR { n[$0]++; next } { if (n[$0] > 0) n[$0]--; else print }' \
			"$_cc_a/$_cc_p" "$_cc_b/$_cc_p" | redact >"$_cc_a.rm"
		awk 'NR == FNR { n[$0]++; next } { if (n[$0] > 0) n[$0]--; else print }' \
			"$_cc_b/$_cc_p" "$_cc_a/$_cc_p" | redact >"$_cc_a.add"
		[ -s "$_cc_a.rm" ] || [ -s "$_cc_a.add" ] || continue
		_cc_any=1
		printf 'config %s: %s removed, %s added\n' "$_cc_p" \
			"$(wc -l <"$_cc_a.rm" | tr -d ' ')" "$(wc -l <"$_cc_a.add" | tr -d ' ')"
		{ sed 's/^/  - /' "$_cc_a.rm"; sed 's/^/  + /' "$_cc_a.add"; } | awk -v max="$_cc_max" '
			NR <= max { print }
			END { if (NR > max) printf "  ... %d more lines\n", NR - max }'
	done
	rm -f "$_cc_a.rm" "$_cc_a.add"
	[ "$_cc_any" = 1 ] || echo 'no change in /etc/config'
	return 0
}
