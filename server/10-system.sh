# System inventory: system_info, processes, services, packages, logs, kernel_modules,
# uci. Read-only; every source that may be missing is checked and reported as
# "not available" instead of left out silently.
# Handler variables are assigned by arg/arg_int (through eval):
# shellcheck disable=SC2154

# key/value line with an aligned key
_inv_kv() { printf '%-16s %s\n' "$1" "$2"; }

# print a file through rd with a label, or say it is missing
_inv_file() { # LABEL PATH
	if [ -f "$2" ]; then
		rd "$2" | sed "s|^|$1 |"
	else
		_inv_kv "$1" "not present ($2)"
	fi
}

# ============================================================== system_info
mcp_register system_info <<'EOF'
{"name":"system_info","title":"System information","description":"Overview of the router: model and board, OpenWrt release and GL.iNet firmware version, kernel and boot command line, CPU, uptime and load, memory, storage, mounts with their flags, root filesystem layout (squashfs + overlay, ext4, initramfs), hostname, time, timezone and NTP. Call it first to know what device and firmware you are looking at.","inputSchema":{"type":"object","properties":{},"additionalProperties":false},"annotations":{"readOnlyHint":true,"openWorldHint":false}}
EOF
tool_system_info() {
	section "Identity"
	_inv_kv hostname "$(rd /proc/sys/kernel/hostname)"
	for _f in model board_name; do
		if [ -f "/tmp/sysinfo/$_f" ]; then _inv_kv "$_f" "$(rd "/tmp/sysinfo/$_f")"; else _inv_kv "$_f" "not present (/tmp/sysinfo/$_f)"; fi
	done
	if [ -f /etc/board.json ]; then
		_inv_kv board.json "id=$(jsonfilter -i /etc/board.json -e '@.model.id' 2>/dev/null) name=$(jsonfilter -i /etc/board.json -e '@.model.name' 2>/dev/null)"
	else
		_inv_kv board.json "not present (/etc/board.json)"
	fi
	if lib_ubus system board >board.json && [ -s board.json ]; then
		for _k in model board_name system kernel release.description; do
			_inv_kv "ubus $_k" "$(jsonfilter -i board.json -e "@.$_k" 2>/dev/null)"
		done
	else
		_inv_kv "ubus board" "not available (ubus or procd not reachable)"
	fi

	section "Firmware"
	_inv_file release /etc/openwrt_release
	_inv_file version /etc/openwrt_version
	if [ -f /etc/glversion ]; then
		_inv_file glversion /etc/glversion
		_inv_file version.type /etc/version.type
		[ -f /etc/version.date ] && _inv_file version.date /etc/version.date
	else
		_inv_kv glversion "not present (no GL.iNet firmware detected)"
	fi

	section "Kernel"
	_inv_kv uname "$(uname -a 2>/dev/null)"
	_inv_kv cmdline "$(rd /proc/cmdline)"
	_inv_kv tainted "$(rd /proc/sys/kernel/tainted) (decoded by kernel_modules)"

	section "CPU"
	rd /proc/cpuinfo | awk -F ':' '
		{ k = $1; sub(/[ \t]+$/, "", k); v = substr($0, index($0, ":") + 1); sub(/^[ \t]+/, "", v) }
		k == "processor" { n++ }
		k ~ /^(model name|cpu model|system type|machine|Hardware|CPU architecture|BogoMIPS|isa)$/ && !(k in seen) { seen[k] = 1; printf "%-16s %s\n", k, v }
		END { printf "%-16s %d\n", "cores", n }'

	section "Uptime and load"
	{ cat /proc/uptime /proc/loadavg; awk '$1 == "btime" { print $2 }' /proc/stat; } 2>/dev/null | awk '
		NR == 1 { up = int($1) } NR == 2 { load = $1 " " $2 " " $3; tasks = $4 } NR == 3 { bt = $1 }
		END {
			printf "%-16s %dd %02d:%02d:%02d (%d s)\n", "uptime", up / 86400, (up % 86400) / 3600, (up % 3600) / 60, up % 60, up
			if (bt != "") printf "%-16s %s (local time)\n", "booted", strftime("%Y-%m-%d %H:%M:%S", bt)
			printf "%-16s %s (1, 5, 15 min)\n", "load", load
			printf "%-16s %s (running/total)\n", "tasks", tasks
		}'

	section "Memory"
	rd /proc/meminfo | awk '$1 ~ /^(MemTotal|MemFree|MemAvailable|Buffers|Cached|Shmem|SwapTotal|SwapFree):$/ { k = $1; sub(/:$/, "", k); printf "%-16s %s %s\n", k, $2, $3 }'

	section "Storage (df, sizes in KiB)"
	df -k 2>&1

	section "Mounts"
	printf '%-28s %-10s %-22s %s\n' MOUNTPOINT TYPE DEVICE FLAGS
	# /proc/mounts is a link into /proc/self, which rd refuses; it is a kernel file, safe to cat
	cat /proc/mounts 2>/dev/null | awk '{
		n = split($4, o, ","); fl = ""; ex = ""
		for (i = 1; i <= n; i++) {
			if (o[i] ~ /^(ro|rw|noexec|nosuid|nodev)$/) fl = fl "" (fl == "" ? "" : ",") o[i]
			else if (o[i] ~ /^(lowerdir|upperdir|workdir)=/) ex = ex " " o[i]
		}
		printf "%-28s %-10s %-22s %s%s\n", $2, $3, $1, fl, ex
	}'

	section "Root filesystem"
	cat /proc/mounts 2>/dev/null | awk -v rom="$MCP_ROM" '
		$2 == "/" { rt = $3; rd = $1 }
		$2 == "/rom" { rot = $3; rod = $1 }
		$2 == "/overlay" { ot = $3; od = $1 }
		END {
			if (rt == "overlay" && rot == "squashfs") l = "squashfs + overlay: firmware image read-only at /rom (" rod "), changes in /overlay (" ot " on " od ")"
			else if (rt == "overlay") l = "overlay root without a squashfs /rom (container or unusual layout)"
			else if (rt == "squashfs") l = "squashfs root without overlay (read-only; failsafe or no writable partition)"
			else if (rt ~ /^(rootfs|tmpfs|ramfs)$/) l = "initramfs (" rt "): runs from RAM, nothing persists across reboot"
			else if (rt != "") l = rt " root on " rd " (no overlay, no firmware image to compare against)"
			else l = "unknown (no / in /proc/mounts)"
			printf "%-16s %s\n", "layout", l
		}'
	if lib_rom_ok; then _inv_kv "firmware image" "$MCP_ROM (usable for comparisons)"; else _inv_kv "firmware image" "$MCP_ROM not usable (no etc/, bin/, usr/ or lib/ there): not-in-image flags are skipped"; fi
	_up=$(lib_upper)
	_inv_kv "overlay upper" "${_up:-none found ($MCP_UPPER, /userdata/overlay/upper)}"
	_inv_kv "trusted tools" "$MCP_TRUSTED"

	section "Time"
	_inv_kv "local time" "$(date '+%Y-%m-%d %H:%M:%S %Z')"
	_inv_kv "utc" "$(date -u '+%Y-%m-%d %H:%M:%S')"
	if [ -f /etc/TZ ]; then _inv_kv "/etc/TZ" "$(rd /etc/TZ)"; else _inv_kv "/etc/TZ" "not present"; fi
	lib_uci_dump system >system.uci
	if [ -s system.uci ]; then
		awk -F '\t' '
			$1 == "S" { type[$2] = $3; next }
			type[$2] == "system" && $3 ~ /^(zonename|timezone|hostname)$/ { printf "%-16s %s\n", "uci " $3, $4 }
			type[$2] == "timeserver" && $3 ~ /^(enabled|enable_server|server|interface)$/ { printf "%-16s %s\n", "ntp " $3, $4 }
		' system.uci
	else
		_inv_kv "uci system" "not available (no /etc/config/system)"
	fi
	_n=$(grep -l -x -E 'ntpd|chronyd|sntp|ntpclient' /proc/[0-9]*/comm 2>/dev/null | sed 's|^/proc/||; s|/comm$||' | tr '\n' ' ')
	_inv_kv "ntp process" "${_n:-none running}"
	return 0
}

# ============================================================== processes
mcp_register processes <<'EOF'
{"name":"processes","title":"Processes","description":"Lists running processes read from /proc (not ps): pid, parent, user, state, resident memory, start time, name, executable and command line, with flags for suspicious traits (executable deleted, in memory only or under /tmp, executable only in the overlay, deleted or /tmp-backed mappings, name that matches neither executable nor arguments, user process posing as a kernel thread). With pid it examines one process in depth: status, exe/cwd/root, open files, sockets, mapped files and environment (secrets masked). Use the list to see what runs, pid to examine one suspect.","inputSchema":{"type":"object","properties":{"filter":{"type":"string","description":"Only processes whose name, executable or command line contains this text (case-sensitive substring). Default: all.","default":""},"pid":{"type":"integer","description":"Examine this one process in depth instead of listing. Default 0 (list).","default":0,"minimum":0},"include_kernel_threads":{"type":"boolean","description":"List kernel threads too; by default they are only counted.","default":false},"max_results":{"type":"integer","description":"Maximum number of processes listed. Default 500.","default":500,"minimum":1,"maximum":5000}},"additionalProperties":false},"annotations":{"readOnlyHint":true,"openWorldHint":false}}
EOF
tool_processes() {
	arg _filter filter ""
	arg_int _pid pid 0 0 99999999 || return 1
	arg_int _max max_results 500 1 5000 || return 1
	_kth=0
	arg_bool include_kernel_threads false && _kth=1
	if [ "$_pid" != 0 ]; then
		_inv_proc_detail "$_pid"
		return
	fi
	lib_procs >procs.tsv
	rd /etc/passwd >passwd.txt
	grep -H -E ' (/tmp/|/var/|/dev/shm/|/memfd:)| \(deleted\)$' /proc/[0-9]*/maps >maps.txt 2>/dev/null
	: >ovl.txt
	_up=$(lib_upper)
	if [ -n "$_up" ] && lib_rom_ok; then
		_ovl="checked against $_up and $MCP_ROM"
		cut -f9 procs.tsv | sort -u | while IFS= read -r _e; do
			_e=${_e% (deleted)}
			case $_e in /*) ;; *) continue ;; esac
			if [ -e "$_up$_e" ] && ! in_rom "$_e"; then printf '%s\n' "$_e"; fi
		done >ovl.txt
	else
		_ovl="not checked (no overlay upper dir or no usable firmware image at $MCP_ROM)"
	fi
	MYPID=$$ FILTER=$_filter KTH=$_kth MAXR=$_max OVL=$_ovl awk -F '\t' '
	function base(p) { sub(/ \(deleted\)$/, "", p); sub(/.*\//, "", p); return p }
	function addflag(pid, f) { if (!((pid, f) in hasf)) { hasf[pid, f] = 1; flags[pid] = flags[pid] "" (flags[pid] == "" ? "" : ", ") f } }
	FILENAME == "passwd.txt" { split($0, pw, ":"); if (!(pw[3] in user)) user[pw[3]] = pw[1]; next }
	FILENAME == "ovl.txt" { ovl[$0] = 1; next }
	FILENAME == "maps.txt" {
		c = index($0, "/maps:"); if (!c) next
		pid = substr($0, 7, c - 7); rest = substr($0, c + 6)
		split(rest, m, " "); perm = m[2]
		s = index(rest, " /"); if (!s) next
		path = substr(rest, s + 1); sub(/^ +/, "", path)
		del = (path ~ / \(deleted\)$/); b = path; sub(/ \(deleted\)$/, "", b)
		if (b ~ /^\/(dev\/zero|SYSV|\[aio\]|drm mm object)/) next
		if (b ~ /^\/memfd:/) { if (perm ~ /x/) mflag[pid] = mflag[pid] SUBSEP "exec-memfd-mapping:" b; next }
		if (b ~ /^\/dev\/shm\// && perm !~ /x/) next
		if (del) mdel[pid, b] = 1
		else if (perm ~ /x/ && b ~ /^\/(tmp|var|dev\/shm)\//) mflag[pid] = mflag[pid] SUBSEP "exec-mapping-in-tmp:" b
		next
	}
	FILENAME == "procs.tsv" {
		n++; P[n] = $1; pp[$1] = $2; uid[$1] = $3; st[$1] = $4; rss[$1] = $5; start[$1] = $6
		kt[$1] = $7; comm[$1] = $8; exe[$1] = $9; cmd[$1] = $10
		next
	}
	END {
		self[ENVIRON["MYPID"]] = 1
		do { ch = 0; for (i = 1; i <= n; i++) { p = P[i]; if (!(p in self) && (pp[p] in self)) { self[p] = 1; ch = 1 } } } while (ch)
		for (k in mdel) {
			split(k, kk, SUBSEP); p = kk[1]; b = kk[2]
			e = exe[p]; sub(/ \(deleted\)$/, "", e)
			if (b != e) mflag[p] = mflag[p] SUBSEP "mapped-deleted:" b
		}
		for (i = 1; i <= n; i++) {
			p = P[i]
			if (kt[p] || (p in self)) continue
			e = exe[p]
			if (e ~ / \(deleted\)$/) addflag(p, "exe-deleted")
			if (e ~ /^\/memfd:/) addflag(p, "exe-memfd")
			if (e ~ /^\/(tmp|var|dev\/shm|dev)\//) addflag(p, "exe-in-tmp")
			eb = e; sub(/ \(deleted\)$/, "", eb)
			if (eb in ovl) addflag(p, "exe-overlay-only")
			na = split(cmd[p], a, " ")
			if (substr(a[1], 1, 1) == "[" && substr(a[1], length(a[1])) == "]") addflag(p, "fake-kthread-name")
			if (e != "-") {
				c = comm[p]; ok = (c == substr(base(e), 1, 15))
				for (j = 1; j <= 3 && j <= na && !ok; j++) if (c == substr(base(a[j]), 1, 15)) ok = 1
				if (!ok && na > 0) addflag(p, "name-mismatch")
			}
			if (p in mflag) { m = split(substr(mflag[p], 2), mm, SUBSEP); for (j = 1; j <= m && j <= 3; j++) addflag(p, mm[j]) }
		}
		nk = 0; nu = 0; ns = 0
		for (i = 1; i <= n; i++) { p = P[i]; if (p in self) ns++; else if (kt[p]) nk++; else nu++ }
		printf "%d processes: %d user, %d kernel threads%s; this server (pid %s) and its %d children left out\n", nu + nk, nu, nk, \
			(ENVIRON["KTH"] == 1 ? "" : " (not listed; include_kernel_threads=true lists them)"), ENVIRON["MYPID"], ns - 1
		printf "overlay-only check: %s\n", ENVIRON["OVL"]
		if (ENVIRON["FILTER"] != "") printf "filter: \"%s\"\n", ENVIRON["FILTER"]
		f = ENVIRON["FILTER"]; shown = 0; more = 0; nf = 0
		for (i = 1; i <= n; i++) {
			p = P[i]; if (p in self) continue
			if (kt[p] && ENVIRON["KTH"] != 1) continue
			if (f != "" && !index(comm[p], f) && !index(cmd[p], f) && !index(exe[p], f)) continue
			sel[++ns2] = p
			if (flags[p] != "") { nf++; m = split(flags[p], ff, ", "); for (j = 1; j <= m; j++) { k = ff[j]; sub(/:.*/, "", k); fl[k] = 1 } }
		}
		print ""
		print "== Flagged processes"
		if (nf == 0) print "none"
		for (i = 1; i <= ns2; i++) { p = sel[i]; if (flags[p] != "") printf "%-7s %-16s %s\n", p, comm[p], flags[p] }
		print ""
		print "== Process list"
		printf "%-7s %-7s %-9s %-2s %8s  %-19s  %-16s %-24s %s\n", "PID", "PPID", "USER", "S", "RSS_KB", "STARTED", "NAME", "EXE", "COMMAND"
		for (i = 1; i <= ns2; i++) {
			p = sel[i]
			if (++shown > ENVIRON["MAXR"]) { more++; continue }
			u = (uid[p] in user) ? user[uid[p]] : uid[p]
			c = cmd[p]; if (kt[p] || c == "") c = "[" comm[p] "]"
			if (length(c) > 300) c = substr(c, 1, 300) " ...(cut, see pid=" p ")"
			t = (start[p] > 0) ? strftime("%Y-%m-%d %H:%M:%S", start[p]) : "-"
			printf "%-7s %-7s %-9s %-2s %8s  %-19s  %-16s %-24s %s%s\n", p, pp[p], u, st[p], rss[p], t, comm[p], exe[p], c, (flags[p] != "" ? "   !! " flags[p] : "")
		}
		if (more) printf "... %d more not shown (max_results=%s; use filter)\n", more, ENVIRON["MAXR"]
		if (nf) {
			print ""
			print "== Flag meanings"
			if ("exe-deleted" in fl) print "exe-deleted        the program file was deleted after start (malware often does this; also after a package upgrade until restart)"
			if ("exe-memfd" in fl) print "exe-memfd          runs from an anonymous memory file, never stored on disk"
			if ("exe-in-tmp" in fl) print "exe-in-tmp         program lives under /tmp, /var or /dev (RAM): not part of the firmware or a package"
			if ("exe-overlay-only" in fl) print "exe-overlay-only   program exists only in the overlay, not in the firmware image (user-installed packages do this too: compare with packages)"
			if ("fake-kthread-name" in fl) print "fake-kthread-name  a user process whose command line looks like a [kernel thread]"
			if ("name-mismatch" in fl) print "name-mismatch      process name matches neither the executable nor the first arguments (renamed process; some daemons do this legitimately)"
			if ("mapped-deleted" in fl) print "mapped-deleted     a mapped file was deleted (dropped payload, or a library replaced by an upgrade; under qemu emulation also the program itself)"
			if ("exec-mapping-in-tmp" in fl) print "exec-mapping-in-tmp executable code mapped from /tmp, /var or /dev/shm"
			if ("exec-memfd-mapping" in fl) print "exec-memfd-mapping executable code mapped from an anonymous memory file"
		}
	}' passwd.txt ovl.txt maps.txt procs.tsv | redact
}

_inv_proc_detail() { # PID
	_d=/proc/$1
	[ -d "$_d" ] || { tool_error "no process with pid $1"; return 1; }
	section "Process $1"
	rd "$_d/status" | grep -E '^(Name|State|Tgid|PPid|TracerPid|Uid|Gid|VmSize|VmRSS|Threads|Seccomp|CapEff|NoNewPrivs):'
	_btime=$(awk '$1 == "btime" { print $2 }' /proc/stat 2>/dev/null)
	rd "$_d/stat" | awk -v bt="$_btime" '{ r = 0; for (i = length($0); i > 0; i--) if (substr($0, i, 1) == ")") { r = i; break }
		split(substr($0, r + 2), f, " "); if (bt != "") printf "Started:\t%s (local time)\n", strftime("%Y-%m-%d %H:%M:%S", int(bt + f[20] / 100)) }'
	_up=$(lib_upper)
	for _l in exe cwd root; do
		_t=$(readlink "$_d/$_l" 2>/dev/null) || _t="(unreadable)"
		_n=
		case $_t in *" (deleted)") _n="$_n deleted;" ;; esac
		case $_t in /tmp/* | /var/* | /dev/shm/*) _n="$_n under /tmp,/var or /dev/shm (RAM);" ;; esac
		if [ "$_l" = exe ] && lib_rom_ok; then
			_p=${_t% (deleted)}
			case $_p in /*) if in_rom "$_p"; then _n="$_n in firmware image;"; else _n="$_n not in firmware image;"; fi
				[ -n "$_up" ] && [ -e "$_up$_p" ] && _n="$_n present in overlay $_up;" ;; esac
		fi
		printf '%-9s %s%s\n' "$_l:" "$_t" "${_n:+   !!${_n%;}}"
	done

	section "Command line (one argument per line)"
	# a value after password/secret/key-style arguments is masked here, one argument per
	# line being out of reach for redact's command-line rule
	tr '\000' '\n' <"$_d/cmdline" 2>/dev/null | awk -v red="$MCP_REDACT" '
	{
		a = $0
		if (red == 1) {
			la = tolower(a)
			if (maskn) { a = "<redacted>"; maskn = 0 }
			else if (match(la, /^-*(password|passwd|pass|secret|psk|key|token|pin)=/)) a = substr(a, 1, RLENGTH) "<redacted>"
			else if (la ~ /^-*(password|passwd|pass|secret|psk|key|token)$/) maskn = 1
		}
		printf "argv[%d] %s\n", NR - 1, a
	}
	END { if (NR == 0) print "(empty: kernel thread or zombie)" }' | redact

	section "Open files (fd -> target)"
	# shellcheck disable=SC2012
	ls -l "$_d/fd" 2>/dev/null | awk '/ -> / { i = index($0, " -> "); s = substr($0, 1, i - 1); n = split(s, a, " "); fd = a[n]; t = substr($0, i + 4)
		if (++c <= 300) printf "%-5s %s\n", fd, t; if (t ~ /^socket:\[/) { gsub(/[^0-9]/, "", t); print t > "inodes.txt" } }
		END { if (c > 300) printf "... %d more\n", c - 300; if (c == 0) print "none (or not readable)" }'
	[ -f inodes.txt ] || : >inodes.txt

	section "Sockets of this process"
	lib_sockets >sockets.tsv
	rd /proc/net/unix >unix.txt
	awk -F '\t' '
		FILENAME == "inodes.txt" { want[$1] = 1; next }
		FILENAME == "sockets.tsv" { if ($7 in want) { printf "%-5s %-11s %s:%s -> %s:%s\n", $1, $2, $3, $4, $5, $6; found++ } next }
		FILENAME == "unix.txt" { split($0, u, " "); if (u[7] in want) { printf "unix  %-11s %s\n", "inode " u[7], (u[8] == "" ? "(unnamed)" : u[8]); found++ } }
		END { if (!found) print "none" }' inodes.txt sockets.tsv unix.txt

	section "Mapped files"
	rd "$_d/maps" | awk '{
		s = index($0, " /"); if (!s) { if ($2 ~ /x/ && $6 == "") ax++; next }
		p = substr($0, s + 1); sub(/^ +/, "", p)
		if (!(p in perm)) order[++n] = p
		perm[p] = perm[p] $2
	}
	END {
		for (i = 1; i <= n; i++) { p = order[i]; printf "%-4s %s\n", (perm[p] ~ /x/ ? "x" : "-"), p }
		if (n == 0) print "none (kernel thread, or not readable)"
		printf "anonymous executable regions: %d\n", ax
	}'

	section "Environment"
	if [ "$MCP_REDACT" = 1 ]; then _m="names that look secret are masked"; else _m="not masked (redaction off)"; fi
	echo "($_m)"
	tr '\000' '\n' <"$_d/environ" 2>/dev/null | awk -v red="$MCP_REDACT" '
		{ e = index($0, "="); n = (e ? substr($0, 1, e - 1) : $0); v = (e ? substr($0, e + 1) : "")
		  if (red == 1 && toupper(n) ~ /PASS|SECRET|TOKEN|KEY|PSK|AUTH|CRED|PRIVATE|COOKIE|SESSION/) v = "<redacted>"
		  if (length(v) > 300) v = substr(v, 1, 300) "...(cut)"
		  if (++c <= 200) print n "=" v }
		END { if (c > 200) printf "... %d more\n", c - 200; if (c == 0) print "(empty or not readable)" }' | redact
	return 0
}

# ============================================================== services
mcp_register services <<'EOF'
{"name":"services","title":"Services","description":"Every init script in /etc/init.d with its boot links (S/K numbers in /etc/rc.d), whether it runs (from procd over ubus, or matched against the process list when ubus is not reachable), and a flag when the script is not part of the firmware image. Also lists procd services and their instances with command lines, rc.d entries without a script, and procd services without an init script. Use it to find autostart persistence and unexpected daemons.","inputSchema":{"type":"object","properties":{"filter":{"type":"string","description":"Only services whose name contains this text. Default: all.","default":""}},"additionalProperties":false},"annotations":{"readOnlyHint":true,"openWorldHint":false}}
EOF
tool_services() {
	arg _filter filter ""
	_romok=0
	lib_rom_ok && _romok=1
	# init scripts: name, then the daemon paths their procd_set_param command lines name.
	# Every content line gets a "|" in front, so a script cannot forge the "#@" control
	# lines; control characters in file names become "?".
	for _f in /etc/init.d/*; do
		[ -f "$_f" ] || continue
		printf '#@FILE %s\n' "$(printf '%s' "${_f##*/}" | tr '\000-\037\177' '?')"
		[ "$_romok" = 1 ] && { in_rom "$_f" && echo '#@ROM 1' || echo '#@ROM 0'; }
		rd "$_f" | head -n 3000 | sed 's/^/|/'
	done >scripts.txt
	# shellcheck disable=SC2012
	ls -l /etc/rc.d/ 2>/dev/null | awk 'NF >= 9 { n = $9; for (i = 10; i <= NF; i++) n = n " " $i; if (n != "") print substr($1, 1, 1) "\t" n }' >rcd.txt
	lib_procs >procs.tsv
	_src="process list (ubus not reachable; a service counts as running when a process runs the daemon path its init script starts)"
	: >svc.txt
	if lib_ubus service list >svc.json && [ -s svc.json ]; then
		_src="procd (ubus call service list)"
		# ubus prints indented JSON, one tab per level: service, instances, instance, fields
		awk '
		function key(s) { sub(/^\t*"/, "", s); sub(/".*/, "", s); return s }
		{ d = 0; while (substr($0, d + 1, 1) == "\t") d++ }
		d == 1 && /": / { svc = key($0); print "S\t" svc; inst = ""; next }
		d == 2 && /": / { sect = key($0); next }
		d == 3 && sect == "instances" && /": \{/ { inst = key($0); print "I\t" svc "\t" inst; incmd = 0; next }
		d == 4 && inst != "" && /"running": / { v = $0; sub(/.*": /, "", v); sub(/,$/, "", v); print "R\t" svc "\t" inst "\t" v; next }
		d == 4 && inst != "" && /"pid": / { v = $0; sub(/.*": /, "", v); sub(/,$/, "", v); print "P\t" svc "\t" inst "\t" v; next }
		d == 4 && inst != "" && /"command": \[/ { incmd = 1; next }
		incmd && d == 5 { v = $0; sub(/^\t*"/, "", v); sub(/",?$/, "", v); print "C\t" svc "\t" inst "\t" v; next }
		incmd && d <= 4 { incmd = 0 }
		' svc.json >svc.txt
	fi
	FILTER=$_filter ROMOK=$_romok SRC=$_src awk -F '\t' '
	function base(p) { sub(/ \(deleted\)$/, "", p); sub(/.*\//, "", p); return p }
	FILENAME == "scripts.txt" {
		if (substr($0, 1, 1) != "|") {
			if (substr($0, 1, 7) == "#@FILE ") { cur = substr($0, 8); names[++ns] = cur; delete var }
			else if (substr($0, 1, 6) == "#@ROM ") rom[cur] = substr($0, 7)
			next
		}
		line = substr($0, 2); sub(/^[ \t]+/, "", line)
		if (match(line, /^[A-Za-z_][A-Za-z0-9_]*=/)) { vn = substr(line, 1, RLENGTH - 1); vv = substr(line, RLENGTH + 1); gsub(/["'"'"']/, "", vv); sub(/[ \t;].*/, "", vv); var[vn] = vv }
		if (line ~ /^START=/) { v = line; sub(/^START=/, "", v); start[cur] = v }
		if (line ~ /^USE_PROCD=1/) procd[cur] = 1
		if (line ~ /^procd_set_param[ \t]+command[ \t]/) {
			split(line, w, /[ \t]+/); c = w[3]; gsub(/["'"'"']/, "", c)
			if (substr(c, 1, 1) == "$") { vn = c; gsub(/[${}]/, "", vn); c = (vn in var) ? var[vn] : "" }
			if (c ~ /^\// && !index(" " daemon[cur] " ", " " c " ")) daemon[cur] = daemon[cur] "" (daemon[cur] == "" ? "" : " ") c
		}
		next
	}
	FILENAME == "rcd.txt" {
		t = $1; n = $2; tgt = ""; i = index(n, " -> "); if (i) { tgt = substr(n, i + 4); n = substr(n, 1, i - 1) }
		if (n !~ /^[SK][0-9][0-9]/) next
		s = substr(n, 4); kind = substr(n, 1, 3)
		lk[s] = lk[s] "" (lk[s] == "" ? "" : " ") kind
		rcn[++nr] = n; rcs[nr] = s; rct[nr] = tgt; rctype[nr] = t
		next
	}
	FILENAME == "procs.tsv" {
		if ($7 == 1) next
		e = $9; sub(/ \(deleted\)$/, "", e)
		na = split($10, a, " ")
		for (j = 1; j <= 3 && j <= na; j++) if (substr(a[j], 1, 1) == "/") { if (!((a[j]) in run)) run[a[j]] = $1 }
		if (!(e in run)) run[e] = $1
		if (!(("comm:" $8) in run)) run["comm:" $8] = $1
		next
	}
	FILENAME == "svc.txt" {
		if ($1 == "S") { psvc[$2] = 1; porder[++np] = $2 }
		else if ($1 == "I") { ninst[$2]++; iorder[$2, ninst[$2]] = $3 }
		else if ($1 == "R") { irun[$2, $3] = $4; if ($4 == "true") nrun[$2]++ }
		else if ($1 == "P") ipid[$2, $3] = $4
		else if ($1 == "C") icmd[$2, $3] = icmd[$2, $3] "" (icmd[$2, $3] == "" ? "" : " ") $4
		next
	}
	END {
		f = ENVIRON["FILTER"]; pu = (np > 0)
		printf "running state from: %s\n", ENVIRON["SRC"]
		if (ENVIRON["ROMOK"] != 1) print "firmware image: not usable, so scripts are not checked against it"
		print ""
		print "== Init scripts (/etc/init.d)"
		printf "%-22s %-9s %-9s %-34s %s\n", "NAME", "BOOT", "LINKS", "RUNNING", "NOTE"
		for (i = 1; i <= ns; i++) {
			s = names[i]; if (f != "" && !index(s, f)) continue
			links = (s in lk) ? lk[s] : "-"
			boot = (links ~ /S/) ? "enabled" : "disabled"
			if (pu) {
				if (s in psvc) r = (nrun[s] > 0) ? "running (" nrun[s] "/" ninst[s] " instances)" : (ninst[s] > 0 ? "not running (" ninst[s] " instances)" : "loaded, no instances")
				else r = "not running"
			} else if (daemon[s] != "") {
				r = "not running"; nd = split(daemon[s], dd, " ")
				for (j = 1; j <= nd; j++) {
					if (dd[j] in run) { r = "running (pid " run[dd[j]] ")"; break }
					if (("comm:" substr(base(dd[j]), 1, 15)) in run) { r = "running (pid " run["comm:" substr(base(dd[j]), 1, 15)] ", by name)"; break }
				}
			} else r = "- (no procd daemon in script)"
			note = ""
			if (ENVIRON["ROMOK"] == 1 && rom[s] == "0") note = "!! not in firmware image"
			if (daemon[s] != "") note = note "" (note == "" ? "" : "; ") "starts " daemon[s]
			printf "%-22s %-9s %-9s %-34s %s\n", s, boot, links, r, note
		}
		print ""
		print "== rc.d entries that are not plain links to their init script"
		bad = 0
		for (i = 1; i <= nr; i++) {
			s = rcs[i]; ok = 0
			for (j = 1; j <= ns; j++) if (names[j] == s) ok = 1
			if (rctype[i] != "l") { printf "%-24s %s\n", rcn[i], "!! not a symlink (regular file or other)"; bad++ }
			else if (!ok) { printf "%-24s -> %s   %s\n", rcn[i], rct[i], "!! no /etc/init.d/" s; bad++ }
			else if (rct[i] != "../init.d/" s && rct[i] != "/etc/init.d/" s) { printf "%-24s -> %s   %s\n", rcn[i], rct[i], "!! unusual target"; bad++ }
		}
		if (!bad) print "none"
		print ""
		print "== procd services and instances"
		if (!pu) { print "not available (ubus or procd not reachable)"; exit }
		for (i = 1; i <= np; i++) {
			s = porder[i]; if (f != "" && !index(s, f)) continue
			has = 0; for (j = 1; j <= ns; j++) if (names[j] == s) has = 1
			printf "%s%s\n", s, (has ? "" : "   !! no /etc/init.d/" s " (registered with procd directly)")
			for (j = 1; j <= ninst[s]; j++) {
				in_ = iorder[s, j]
				printf "  %-14s running=%-5s pid=%-7s %s\n", in_, irun[s, in_], ((s, in_) in ipid ? ipid[s, in_] : "-"), icmd[s, in_]
			}
		}
	}' scripts.txt rcd.txt procs.tsv svc.txt | redact
}

# ============================================================== packages
mcp_register packages <<'EOF'
{"name":"packages","title":"Packages","description":"Installed packages from opkg (OpenWrt up to 24.10) or apk (25.12) with version and origin: shipped in the firmware image, installed later by the user, or upgraded. Also config files changed against their package, and with audit=true (apk only) every package file whose content differs from the package database. Use it to see what was added to the stock firmware.","inputSchema":{"type":"object","properties":{"filter":{"type":"string","description":"Only packages whose name contains this text. Default: all.","default":""},"user_installed_only":{"type":"boolean","description":"List only packages that are not in the firmware image (installed or upgraded later).","default":false},"audit":{"type":"boolean","description":"apk: also run 'apk audit --system' to list package files whose content changed. opkg keeps no file hashes, so this only explains that.","default":false},"max_results":{"type":"integer","description":"Maximum number of packages listed. Default 1000.","default":1000,"minimum":1,"maximum":10000}},"additionalProperties":false},"annotations":{"readOnlyHint":true,"openWorldHint":false}}
EOF
tool_packages() {
	arg _filter filter ""
	arg_int _max max_results 1000 1 10000 || return 1
	_uo=0
	arg_bool user_installed_only false && _uo=1
	_audit=0
	arg_bool audit false && _audit=1
	_rom=
	if [ -f /usr/lib/opkg/status ]; then
		_pm=opkg
		lib_rom_ok && [ -f "$(rom_path /usr/lib/opkg/status)" ] && _rom=$(rom_path /usr/lib/opkg/status)
		rd /usr/lib/opkg/status >db.txt
	elif [ -f /lib/apk/db/installed ]; then
		_pm=apk
		lib_rom_ok && [ -f "$(rom_path /lib/apk/db/installed)" ] && _rom=$(rom_path /lib/apk/db/installed)
		rd /lib/apk/db/installed >db.txt
	else
		echo "no package database found (/usr/lib/opkg/status, /lib/apk/db/installed)"
		return 0
	fi
	if [ -n "$_rom" ]; then rd "$_rom" >rom.txt; else : >rom.txt; fi
	rd /etc/apk/world >world.txt
	# The list is built first and printed last: it can be long, and the changed config
	# files below must not be lost to the output cap.
	PM=$_pm FILTER=$_filter UO=$_uo MAXR=$_max ROM=$_rom awk '
	function rec_end() {
		if (name == "") return
		if (curf == "rom.txt") rv[name] = ver
		else { n++; N[n] = name; V[n] = ver; T[n] = itime; A[n] = auto; tc[itime]++ }
		name = ""; ver = ""; itime = ""; auto = ""
	}
	FILENAME == "world.txt" { w = $1; sub(/[=<>~].*/, "", w); world[w] = 1; next }
	FNR == 1 { rec_end(); curf = FILENAME }
	ENVIRON["PM"] == "opkg" {
		if ($0 == "") { rec_end(); next }
		if ($1 == "Package:") name = $2
		else if ($1 == "Version:") ver = $2
		else if ($1 == "Installed-Time:") itime = $2
		else if ($1 == "Auto-Installed:") auto = $2
		next
	}
	ENVIRON["PM"] == "apk" {
		if ($0 == "") { rec_end(); next }
		if (substr($0, 1, 2) == "P:") name = substr($0, 3)
		else if (substr($0, 1, 2) == "V:") ver = substr($0, 3)
		next
	}
	END {
		rec_end()
		haverom = (ENVIRON["ROM"] != "")
		if (haverom) method = "compared with the firmware image (" ENVIRON["ROM"] ")"
		else if (ENVIRON["PM"] == "opkg") {
			best = 0; for (t in tc) if (tc[t] > best) { best = tc[t]; img = t }
			method = "heuristic: no firmware image, so packages installed more than 10 minutes after the image time (" strftime("%Y-%m-%d %H:%M:%S", img) ", shared by " best " packages) count as user-installed"
		} else method = "unknown: no firmware image to compare with; REQ marks packages named in /etc/apk/world"
		printf "%d packages; origin %s\n", n, method
		if (ENVIRON["FILTER"] != "") printf "filter: \"%s\"\n", ENVIRON["FILTER"]
		printf "%-36s %-32s %-10s %s\n", "NAME", "VERSION", "ORIGIN", "NOTE"
		f = ENVIRON["FILTER"]; shown = 0; more = 0; nu = 0; byworld = 0
		# packages that did not come with the image first: on a router with 800 packages
		# the list may hit max_results or the output cap, and these are the ones that matter
		for (i = 1; i <= n; i++) {
			if (haverom && (N[i] in rv) && rv[N[i]] == V[i]) continue
			if (!haverom && ENVIRON["PM"] == "opkg" && T[i] != "" && T[i] <= img + 600) continue
			order[++no] = i; first[i] = 1
		}
		for (i = 1; i <= n; i++) if (!(i in first)) order[++no] = i
		for (k = 1; k <= no; k++) {
			i = order[k]
			o = "-"; note = ""
			if (haverom) {
				if (!(N[i] in rv)) o = "user"
				else if (rv[N[i]] != V[i]) { o = "upgraded"; note = "image has " rv[N[i]] }
				else o = "image"
			} else if (ENVIRON["PM"] == "opkg" && T[i] != "") {
				o = (T[i] > img + 600) ? "user" : "image"
			}
			if (ENVIRON["PM"] == "opkg" && T[i] != "") note = note "" (note == "" ? "" : "; ") "installed " strftime("%Y-%m-%d %H:%M:%S", T[i])
			if (A[i] == "yes") note = note "" (note == "" ? "" : "; ") "dependency"
			if (ENVIRON["PM"] == "apk" && (N[i] in world)) note = note "" (note == "" ? "" : "; ") "REQ"
			if (o == "user" || o == "upgraded") nu++
			if (f != "" && !index(N[i], f)) continue
			if (ENVIRON["UO"] == 1) {
				if (o == "-" && ENVIRON["PM"] == "apk") { byworld = 1; if (!(N[i] in world)) continue }
				else if (o != "user" && o != "upgraded") continue
			}
			if (++shown > ENVIRON["MAXR"]) { more++; continue }
			printf "%-36s %-32s %-10s %s\n", N[i], V[i], o, note
		}
		if (more) printf "... %d more not shown (max_results)\n", more
		printf "user-installed or upgraded: %d\n", nu
		if (byworld) print "note: without the firmware image user_installed_only shows the packages named in /etc/apk/world"
	}' world.txt rom.txt db.txt >pk.txt

	section "Config files changed against their package"
	if [ "$_pm" = opkg ]; then
		# Conffiles blocks: " /path hash" (md5 32 or sha256 64 hex). opkg list-changed-conffiles
		# is not used: it needs a lock file, which would be a write.
		awk '$1 == "Package:" { p = $2 } /^Conffiles:/ { c = 1; next } c && /^ \// { print $1, $2, p; next } { c = 0 }' db.txt >conf.txt
		_n=0
		while read -r _path _hash _pkg; do
			_n=$((_n + 1))
			if [ ! -e "$_path" ] && [ ! -L "$_path" ]; then printf '%-40s %-9s %s\n' "$_path" missing "$_pkg"; continue; fi
			# rd refuses FIFOs, devices and links into /proc, /sys, /dev
			if ! rd "$_path" >conf.cur; then printf '%-40s %-9s %s\n' "$_path" unreadable "$_pkg"; continue; fi
			case ${#_hash} in 32) _cur=$(md5sum <conf.cur) ;; *) _cur=$(sha256sum <conf.cur) ;; esac
			[ "${_cur%% *}" = "$_hash" ] || printf '%-40s %-9s %s\n' "$_path" changed "$_pkg"
		done <conf.txt >changed.txt
		if [ -s changed.txt ]; then
			printf '%-40s %-9s %s\n' FILE STATE PACKAGE
			cat changed.txt
		else
			echo "none"
		fi
		echo "($(wc -l <conf.txt) config files checked against the hashes in /usr/lib/opkg/status; changed config is normal after setup; unreadable = not a regular file, or a link into /proc, /sys or /dev)"
	else
		if have apk; then
			run_timeout 30 apk audit --no-network --no-cache >audit.txt 2>&1
			_rc=$?
			if [ "$_rc" = 0 ]; then
				if [ -s audit.txt ]; then head -n 500 audit.txt; else echo none; fi
				[ "$(wc -l <audit.txt)" -gt 500 ] && echo "... cut at 500 lines"
				echo "(apk audit: U = content differs from the package, A = file in a protected path that no package owns; other letters: apk-audit(8). Changed config is normal after setup.)"
			else
				echo "apk audit failed (exit $_rc):"
				head -n 20 audit.txt
			fi
		else
			echo "apk: not available"
		fi
	fi

	section "Packages ($_pm), not from the image first"
	cat pk.txt

	if [ "$_audit" = 1 ]; then
		section "Package files changed against the package database"
		if [ "$_pm" = opkg ]; then
			echo "opkg keeps hashes only for config files (above), not for programs and libraries, so a file audit is not possible with opkg. Files changed after flashing show up in the overlay; compare against the firmware image with the forensics tools (overlay_diff)."
		elif have apk; then
			run_timeout 90 apk audit --system --no-network --no-cache >audit.txt 2>&1
			_rc=$?
			if [ "$_rc" = 0 ]; then
				if [ -s audit.txt ]; then head -n 1000 audit.txt; else echo "none: every package file matches the database"; fi
				echo "($(wc -l <audit.txt) lines; U = content differs from the package. Files no package owns are not listed: that is overlay_diff's job.)"
			else
				echo "apk audit --system failed (exit $_rc$([ "$_rc" = 124 ] && echo ', time limit')):"
				head -n 20 audit.txt
			fi
		else
			echo "apk: not available"
		fi
	fi
	return 0
}

# ============================================================== logs
mcp_register logs <<'EOF'
{"name":"logs","title":"Logs","description":"Reads the system log (logread), the kernel ring buffer (dmesg) or a log file under /tmp/log or /var/log: the last N lines, optionally only those matching a pattern. Without a file name for source=file it lists the available log files. Use it to see boot messages, logins, daemon errors and what happened recently.","inputSchema":{"type":"object","properties":{"source":{"type":"string","enum":["syslog","kernel","file"],"description":"syslog (logread, the default), kernel (dmesg) or file (a file under /tmp/log or /var/log).","default":"syslog"},"lines":{"type":"integer","description":"How many of the last lines to show. Default 200.","default":200,"minimum":1,"maximum":5000},"pattern":{"type":"string","description":"Only lines matching this extended regular expression (grep -E), e.g. 'dropbear|login'. Default: all lines.","default":""},"file":{"type":"string","description":"For source=file: the file name or path under /tmp/log or /var/log. Default: list the files.","default":""}},"additionalProperties":false},"annotations":{"readOnlyHint":true,"openWorldHint":false}}
EOF
tool_logs() {
	arg _src source syslog
	arg_int _lines lines 200 1 5000 || return 1
	arg _pat pattern ""
	arg _file file ""
	case $_src in
	syslog)
		section "System log (logread, last $_lines lines${_pat:+, matching \"$_pat\"})"
		if have logread && run_timeout 15 logread >log.txt 2>err.txt; then
			_inv_tail log.txt "$_lines" "$_pat"
		else
			echo "logread: not available ($(head -n 1 err.txt 2>/dev/null || echo 'not installed'))"
			for _f in /tmp/log/messages /var/log/messages /tmp/messages; do
				[ -f "$_f" ] || continue
				echo "falling back to $_f:"
				rd "$_f" >log.txt
				_inv_tail log.txt "$_lines" "$_pat"
				return
			done
			echo "no log file found either (/tmp/log/messages, /var/log/messages)"
		fi
		;;
	kernel)
		section "Kernel ring buffer (dmesg, last $_lines lines${_pat:+, matching \"$_pat\"})"
		if have dmesg && dmesg >log.txt 2>err.txt; then
			_inv_tail log.txt "$_lines" "$_pat"
		else
			echo "dmesg: not available ($(head -n 1 err.txt 2>/dev/null))"
		fi
		;;
	file)
		if [ -z "$_file" ]; then
			section "Log files under /tmp/log and /var/log"
			_found=0
			_seen=
			for _d in /tmp/log /var/log; do
				[ -d "$_d" ] || continue
				_r=$(readlink -f "$_d" 2>/dev/null) || _r=$_d
				case " $_seen " in *" $_r "*) continue ;; esac
				_seen="$_seen $_r"
				find "$_r" -xdev -maxdepth 2 -type f 2>/dev/null | while IFS= read -r _f; do ls -ln --full-time "$_f" 2>/dev/null; done
				_found=1
			done
			[ "$_found" = 1 ] || echo "neither /tmp/log nor /var/log exists"
			return 0
		fi
		case $_file in /*) _p=$_file ;; *) _p=/tmp/log/$_file; [ -e "$_p" ] || _p=/var/log/$_file ;; esac
		_r=$(readlink -f "$_p" 2>/dev/null) || _r=
		_ok=0
		for _d in /tmp/log /var/log; do
			_dr=$(readlink -f "$_d" 2>/dev/null) || continue
			[ -n "$_dr" ] && [ -d "$_dr" ] || continue
			case $_r in "$_dr"/*) _ok=1 ;; esac
		done
		case $_r in *'/../'* | *'/..') _ok=0 ;; esac
		if [ "$_ok" != 1 ]; then tool_error "file must be an existing file under /tmp/log or /var/log (got '$_file')"; return 1; fi
		section "$_r (last $_lines lines${_pat:+, matching \"$_pat\"})"
		if rd "$_r" >log.txt; then
			_inv_tail log.txt "$_lines" "$_pat"
		else
			echo "not a readable regular file: $_r"
		fi
		;;
	*) tool_error "source must be syslog, kernel or file, got '$_src'"; return 1 ;;
	esac
	return 0
}

_inv_tail() { # FILE LINES PATTERN
	if [ -n "$3" ]; then
		grep -E -e "$3" "$1" >sel.txt
		[ $? -le 1 ] || { echo "error: bad pattern '$3'"; return 1; }
	else
		cp "$1" sel.txt
	fi
	_t=$(wc -l <sel.txt)
	tail -n "$2" sel.txt | redact
	echo "($_t matching lines in total, showing up to $2)"
}

# ============================================================== kernel_modules
mcp_register kernel_modules <<'EOF'
{"name":"kernel_modules","title":"Kernel modules","description":"Loaded kernel modules from /proc/modules with size, use count, users and taint marks, a flag for modules whose .ko file is not in the firmware image, the kernel taint value decoded, and the boot module lists in /etc/modules.d with a flag for entries not in the image. Use it to spot rootkits or unexpected drivers.","inputSchema":{"type":"object","properties":{},"additionalProperties":false},"annotations":{"readOnlyHint":true,"openWorldHint":false}}
EOF
tool_kernel_modules() {
	_rel=$(uname -r 2>/dev/null)
	_md=/lib/modules/$_rel
	_romok=0
	lib_rom_ok && _romok=1
	: >ko.txt
	: >romko.txt
	if [ -d "$_md" ]; then
		find "$_md" -xdev -name '*.ko' 2>/dev/null >ko.txt
		[ "$_romok" = 1 ] && find "$(rom_path "$_md")" -xdev -name '*.ko' 2>/dev/null | sed "s|^${MCP_ROM%/}||" >romko.txt
	fi
	section "Kernel taint"
	_t=$(rd /proc/sys/kernel/tainted)
	echo "value ${_t:-unreadable}"
	[ -n "$_t" ] && awk -v t="$_t" 'BEGIN {
		split("P:proprietary module loaded|F:module force-loaded|S:kernel running on out-of-spec hardware|R:module force-unloaded|M:machine check exception|B:bad page reference|U:taint requested by user space|D:kernel oops or BUG|A:ACPI table overridden|W:kernel warning|C:staging driver loaded|I:firmware bug workaround|O:out-of-tree module loaded|E:unsigned module loaded|L:soft lockup|K:kernel live-patched|X:auxiliary taint|T:built with struct randomization|N:test module", d, "|")
		if (t == 0) { print "not tainted"; exit }
		for (i = 0; i < 19; i++) if (and(t, 2 ^ i)) printf "bit %-2d %s\n", i, d[i + 1]
		if (and(t, 4096)) print "note: O is normal on OpenWrt (many drivers, e.g. wireless and vendor drivers, are built out of tree)"
	}'


	# the long lists go to files first so the flagged entries can lead
	{
		section "Loaded modules"
		if [ ! -d "$_md" ]; then
			echo "note: no $_md for the running kernel $_rel (/lib/modules has: $(cd /lib/modules 2>/dev/null && echo *)): container, or kernel and userland do not match"
		fi
		[ "$_romok" = 1 ] || echo "note: firmware image not usable, .ko files are not checked against it"
		if [ ! -r /proc/modules ]; then
			echo "/proc/modules: not available (kernel without module support?)"
		else
			ROMOK=$_romok MD=$_md HAVEMD=$([ -d "$_md" ] && echo 1 || echo 0) awk '
			FILENAME == "ko.txt" { b = $0; sub(/.*\//, "", b); sub(/\.ko$/, "", b); gsub(/-/, "_", b); ko[b] = $0; next }
			FILENAME == "romko.txt" { rom[$0] = 1; next }
			{
				n++; users = $4; if (users == "-") users = ""; sub(/,$/, "", users)
				taint = ""; if (match($0, /\([A-Z]+\)$/)) taint = substr($0, RSTART + 1, RLENGTH - 2)
				note = ""
				if ($1 in ko) {
					if (ENVIRON["ROMOK"] == 1 && !(ko[$1] in rom)) note = "!! " ko[$1] " not in firmware image"
				} else if (ENVIRON["HAVEMD"] == 1) note = "!! no .ko file under " ENVIRON["MD"] ": loaded from elsewhere (e.g. /tmp) or deleted after loading"
				line[n] = sprintf("%-24s %9s %4s %-6s %-8s %-28s %s", $1, $2, $3, taint, $5, users, note)
			}
			END {
				printf "%d modules\n", n
				printf "%-24s %9s %4s %-6s %-8s %-28s %s\n", "NAME", "SIZE_B", "USED", "TAINT", "STATE", "USED_BY", "NOTE"
				for (i = 1; i <= n; i++) print line[i]
			}' ko.txt romko.txt /proc/modules
		fi
	} >mods.txt
	{
		section "Boot module lists (/etc/modules.d, /etc/modules-boot.d)"
		_any=0
		for _f in /etc/modules.d/* /etc/modules-boot.d/*; do
			[ -e "$_f" ] || [ -L "$_f" ] || continue
			_any=1
			_n=
			[ "$_romok" = 1 ] && ! in_rom "$_f" && _n="   !! not in firmware image"
			printf '%-40s %s%s\n' "$_f" "$(rd "$_f" | grep -v -E '^[[:space:]]*(#|$)' | head -n 20 | tr '\n' ' ' | sed 's/ $//')" "$_n"
		done
		[ "$_any" = 1 ] || echo "none"
	} >boot.txt

	section "Flagged (module file missing or not in the firmware image)"
	grep -h '!!' mods.txt boot.txt || echo "none"
	[ "$_romok" = 1 ] || echo "(firmware image at $MCP_ROM not usable: files are not compared with it)"
	[ -d "$_md" ] || echo "(no $_md: .ko files cannot be checked)"
	echo "(/proc/modules lists only loadable modules, never code built into the kernel; a loaded module whose .ko is missing is worth a look)"
	cat mods.txt boot.txt
	return 0
}

# ============================================================== uci
mcp_register uci <<'EOF'
{"name":"uci","title":"UCI configuration","description":"Shows the router's UCI configuration (/etc/config) with secrets masked: without package the list of config packages, with package the output of 'uci show PACKAGE'. With changes=true it lists uncommitted changes instead (uci changes). Read only: never sets or commits. Use it to read the network, wireless, firewall, dhcp or system settings in detail.","inputSchema":{"type":"object","properties":{"package":{"type":"string","description":"Config package (file in /etc/config) to show, e.g. network, wireless, firewall; also package.section. Default: list the packages.","default":""},"changes":{"type":"boolean","description":"Show uncommitted changes (for package, or all) instead of the configuration.","default":false}},"additionalProperties":false},"annotations":{"readOnlyHint":true,"openWorldHint":false}}
EOF
tool_uci() {
	arg _pkg package ""
	case $_pkg in *[!A-Za-z0-9_.@\[\]-]*) tool_error "package may only contain letters, digits and _ . @ [ ] -"; return 1 ;; esac
	if arg_bool changes false; then
		section "Uncommitted changes${_pkg:+ ($_pkg)}"
		if ! have uci; then echo "uci: not available"; return 0; fi
		# shellcheck disable=SC2086
		uci changes $_pkg >ch.txt 2>&1 || { tool_error "$(cat ch.txt)"; return 1; }
		if [ -s ch.txt ]; then redact <ch.txt; else echo "none"; fi
		return 0
	fi
	if [ -z "$_pkg" ]; then
		section "Config packages (/etc/config)"
		_romok=0
		lib_rom_ok && _romok=1
		for _f in /etc/config/*; do
			[ -f "$_f" ] || continue
			_n=$(grep -c -E '^[[:space:]]*config[[:space:]]' "$_f" 2>/dev/null)
			_x=
			[ "$_romok" = 1 ] && ! in_rom "$_f" && _x="   (not in firmware image: created after flashing)"
			printf '%-24s %4s sections%s\n' "${_f##*/}" "$_n" "$_x"
		done
		have uci || echo "(uci: not available; package views are read from /etc/config directly)"
		echo "call uci with package=NAME to see one"
		return 0
	fi
	section "uci show $_pkg"
	if have uci; then
		uci -q show "$_pkg" >show.txt 2>&1 || { tool_error "uci show $_pkg: no such config, section or option (call uci without package for the list)"; return 1; }
		redact <show.txt
	else
		echo "(uci: not available; /etc/config/${_pkg%%.*} as stored)"
		rd "/etc/config/${_pkg%%.*}" >show.txt || { tool_error "no /etc/config/${_pkg%%.*}"; return 1; }
		redact <show.txt
	fi
	return 0
}
