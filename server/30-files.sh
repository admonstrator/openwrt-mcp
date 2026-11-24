# Files: read_file, list_dir, find_files, file_hash, and the fx_* readers that the
# forensic modules (40-forensics.sh, 50-audit.sh) share.
#
# Everything here lists files with one "ls -lnd --full-time" per batch (never one process
# per file) and compares against the firmware image by content (size, then sha256), not
# by "is it in the overlay": a bind mount over an image file shows up that way too.

# shellcheck disable=SC2154,SC2016  # arg/arg_int/fx_path assign through eval; awk programs are single-quoted on purpose

# ---------------------------------------------------------------- shared readers
# shellcheck disable=SC2034  # used by 40-forensics.sh and 50-audit.sh
FX_TAB=$(printf '\t')

# The firmware image is usable for comparisons when it holds a system tree.
fx_rom_ok() {
	[ -d "$MCP_ROM/etc" ] || [ -d "$MCP_ROM/bin" ] || [ -d "$MCP_ROM/usr" ] || [ -d "$MCP_ROM/lib" ]
}

# Prints the overlay's upper directory; fails when the device has none. MCP_UPPER wins
# when it exists; with the default value the upperdir of the root mount and the
# location some GL.iNet models use are tried too.
fx_upper() {
	if [ -d "$MCP_UPPER" ]; then
		printf '%s\n' "${MCP_UPPER%/}"
		return 0
	fi
	[ "$MCP_UPPER" = /overlay/upper ] || return 1
	_fu=$(awk '$2 == "/" && $3 == "overlay" {
		n = split($4, o, ","); for (i = 1; i <= n; i++) if (o[i] ~ /^upperdir=/) u = substr(o[i], 10)
	} END { print u }' /proc/mounts 2>/dev/null)
	if [ -n "$_fu" ] && [ -d "$_fu" ]; then
		printf '%s\n' "${_fu%/}"
		return 0
	fi
	if [ -d /userdata/overlay/upper ]; then
		echo /userdata/overlay/upper
		return 0
	fi
	return 1
}

# awk library: fx_ls(line) parses one "ls -lnd --full-time" line into F_type (f d l c b
# p s), F_mode (octal), F_uid, F_gid, F_size (devices: "major,minor"), F_mtime, F_path,
# F_target. busybox ls prints "?" for bytes outside printable ASCII, so a newline in a
# file name cannot forge a second record.
FX_AWK_LS='
function fx_oct(s,   v, c) {
	v = 0
	if (substr(s, 2, 1) == "r") v += 256
	if (substr(s, 3, 1) == "w") v += 128
	c = substr(s, 4, 1); if (c == "x" || c == "s") v += 64; if (c == "s" || c == "S") v += 2048
	if (substr(s, 5, 1) == "r") v += 32
	if (substr(s, 6, 1) == "w") v += 16
	c = substr(s, 7, 1); if (c == "x" || c == "s") v += 8; if (c == "s" || c == "S") v += 1024
	if (substr(s, 8, 1) == "r") v += 4
	if (substr(s, 9, 1) == "w") v += 2
	c = substr(s, 10, 1); if (c == "x" || c == "t") v += 1; if (c == "t" || c == "T") v += 512
	return sprintf("%04o", v)
}
# A link target as an absolute path without "." and "..": "busybox" in /bin and
# "/bin/busybox" are the same target.
function fx_resolve(link, t,   n, a, i, m, o, out) {
	if (substr(t, 1, 1) != "/") { sub(/\/[^\/]*$/, "", link); t = link "/" t }
	n = split(t, a, "/"); m = 0
	for (i = 1; i <= n; i++) {
		if (a[i] == "" || a[i] == ".") continue
		if (a[i] == "..") { if (m > 0) m--; continue }
		o[++m] = a[i]
	}
	out = ""; for (i = 1; i <= m; i++) out = out "/" o[i]
	return (out == "") ? "/" : out
}
function fx_ls(line,   h, n, f, r, i) {
	if (!match(line, / [0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9] [0-9][0-9]:[0-9][0-9]:[0-9][0-9] [+-][0-9][0-9][0-9][0-9] /)) return 0
	h = substr(line, 1, RSTART - 1); F_mtime = substr(line, RSTART + 1, 19); r = substr(line, RSTART + RLENGTH)
	n = split(h, f, / +/)
	F_type = substr(f[1], 1, 1); if (F_type == "-") F_type = "f"
	F_mode = fx_oct(f[1]); F_uid = f[3]; F_gid = f[4]
	F_size = f[5]; for (i = 6; i <= n; i++) F_size = F_size f[i]
	F_target = ""
	if (F_type == "l") { i = index(r, " -> "); if (i) { F_target = substr(r, i + 4); r = substr(r, 1, i - 1) } }
	F_path = r
	return 1
}
'

# awk library: fx_fmt() formats a record (see fx_cmp) as one aligned line.
# Needs R_* variables set by fx_rec(); owner names come from /etc/passwd and /etc/group.
FX_AWK_FMT='
function fx_names(   l, f) {
	while ((getline l < "/etc/passwd") > 0) { split(l, f, ":"); if (!(f[3] in UN)) UN[f[3]] = f[1] }
	close("/etc/passwd")
	while ((getline l < "/etc/group") > 0) { split(l, f, ":"); if (!(f[3] in GN)) GN[f[3]] = f[1] }
	close("/etc/group")
	SW["same"] = "same"; SW["changed"] = "CHANGED"; SW["meta"] = "meta"; SW["new"] = "new"
	SW["noimage"] = "-"; SW["uncmp"] = "?"
}
function fx_rec(   ) {
	R_state = $1; R_detail = $2; R_type = $3; R_mode = $4; R_uid = $5; R_gid = $6
	R_size = $7; R_mtime = $8; R_path = $9; R_target = $10
}
function fx_owner(   ) {
	return ((R_uid in UN) ? UN[R_uid] : R_uid) ":" ((R_gid in GN) ? GN[R_gid] : R_gid)
}
function fx_fmt(   ) {
	return sprintf("%s %s %-13s %9s %s %-7s %s%s", R_type, R_mode, fx_owner(), R_size, R_mtime,
		SW[R_state], R_path, (R_target != "-") ? " -> " R_target : "")
}
'
FX_LEGEND='columns: type(f file, d dir, l link, c/b device, p fifo, s socket) mode owner:group bytes mtime image path
image: same = identical to the firmware image, CHANGED = differs from it, meta = same content but mode or owner differ, new = not in the image, - = not compared, ? = could not be compared'

# stdin: NUL-separated paths. stdout: one "ls -lnd --full-time" line per existing path.
fx_ls() { xargs -0 -r ls -lnd --full-time 2>/dev/null; }

# fx_sortk N [r]: sorts tab separated records by field N (r: descending). busybox sort
# on OpenWrt is built without -k and -t, so the key is put in front and cut off again.
fx_sortk() {
	awk -F'\t' -v n="$1" '{ print $n "\t" $0 }' | if [ "${2-}" = r ]; then sort -r; else sort; fi | cut -f2-
}

# Helpers that run under run_timeout. They write to a file, never into a pipe: the
# watchdog of run_timeout keeps the pipe open and the reader would wait for it.
fx_snap() { cat "$1" 2>/dev/null | head -c 1048576; }
fx_find_ls() { find "$@" -print0 2>/dev/null | fx_ls | head -n 20001; }
fx_sum() { rd "$2" | "${1}sum" | cut -d' ' -f1; }

# fx_cmp ROOT COMPARE
# stdin: ls lines (from fx_ls) of paths below ROOT ("" for the live system, or the
# overlay's upper directory). stdout, tab separated, one record per line:
#   state detail type mode uid gid size mtime path target
# path has ROOT stripped; empty fields are "-". state compares with the same path in the
# firmware image: same | changed | meta | new | uncmp (could not be hashed) | noimage
# (COMPARE is 0 or there is no usable image). detail says what the image has instead.
fx_cmp() {
	fx_seq=$((${fx_seq:-0} + 1))
	_ct=$MCP_TMP/cmp.$fx_seq
	_cc=$2
	fx_rom_ok || _cc=0
	cat >"$_ct.L"
	: >"$_ct.R"
	: >"$_ct.S"
	if [ "$_cc" = 1 ] && [ -s "$_ct.L" ]; then
		FX_ROOT=${1%/} FX_ROM=${MCP_ROM%/} awk "$FX_AWK_LS"'
			{ if (fx_ls($0)) print ENVIRON["FX_ROM"] substr(F_path, length(ENVIRON["FX_ROOT"]) + 1) }' "$_ct.L" |
			tr '\n' '\0' | fx_ls >"$_ct.R"
		# hash only pairs of regular files with the same non-zero size
		FX_ROOT=${1%/} FX_ROM=${MCP_ROM%/} FX_R="$_ct.R" awk "$FX_AWK_LS"'
			BEGIN { rl = length(ENVIRON["FX_ROM"]); ll = length(ENVIRON["FX_ROOT"]) }
			FILENAME == ENVIRON["FX_R"] { if (fx_ls($0) && F_type == "f") rs[substr(F_path, rl + 1)] = F_size; next }
			{
				if (!fx_ls($0) || F_type != "f") next
				k = substr(F_path, ll + 1)
				if ((k in rs) && rs[k] == F_size && F_size != "0") { print F_path; print ENVIRON["FX_ROM"] k }
			}' "$_ct.R" "$_ct.L" | tr '\n' '\0' | xargs -0 -r sha256sum 2>/dev/null >"$_ct.S"
	fi
	FX_ROOT=${1%/} FX_ROM=${MCP_ROM%/} FX_R="$_ct.R" FX_S="$_ct.S" FX_CC="$_cc" awk "$FX_AWK_LS"'
		function desc(t, size, mode, target) {
			if (t == "f") return "file, " size " bytes, mode " mode
			if (t == "l") return "symlink -> " target
			if (t == "d") return "directory"
			return "type " t
		}
		BEGIN { OFS = "\t"; rl = length(ENVIRON["FX_ROM"]); ll = length(ENVIRON["FX_ROOT"]); cc = ENVIRON["FX_CC"] }
		FILENAME == ENVIRON["FX_S"] { sum[substr($0, 67)] = substr($0, 1, 64); next }
		FILENAME == ENVIRON["FX_R"] {
			if (fx_ls($0)) {
				k = substr(F_path, rl + 1)
				rt[k] = F_type; rm[k] = F_mode; ro[k] = F_uid ":" F_gid; rs[k] = F_size; rg[k] = F_target
			}
			next
		}
		{
			if (!fx_ls($0)) next
			k = substr(F_path, ll + 1); if (k == "") k = "/"
			st = "same"; d = "-"
			if (cc != 1) st = "noimage"
			else if (!(k in rt)) st = "new"
			else if (rt[k] != F_type) { st = "changed"; d = "image: " desc(rt[k], rs[k], rm[k], rg[k]) }
			else if (F_type == "l") { if (fx_resolve(k, rg[k]) != fx_resolve(k, F_target)) { st = "changed"; d = "image: -> " rg[k] } }
			else if (F_type == "f") {
				if (rs[k] != F_size) { st = "changed"; d = "image: " rs[k] " bytes" }
				else if (F_size != "0") {
					a = F_path; b = ENVIRON["FX_ROM"] k
					if (!(a in sum) || !(b in sum)) { st = "uncmp"; d = "could not be hashed" }
					else if (sum[a] != sum[b]) { st = "changed"; d = "image: same size, other content" }
				}
			}
			else if (F_type == "c" || F_type == "b") { if (rs[k] != F_size) { st = "changed"; d = "image: device " rs[k] } }
			if (st == "same" && (rm[k] != F_mode || ro[k] != F_uid ":" F_gid)) {
				st = "meta"; d = "image: mode " rm[k] " owner " ro[k]
			}
			print st, d, F_type, F_mode, F_uid, F_gid, F_size, F_mtime, k, (F_target == "") ? "-" : F_target
		}' "$_ct.S" "$_ct.R" "$_ct.L"
	rm -f "$_ct.L" "$_ct.R" "$_ct.S"
}

# fx_pkgdb ROOT: the package database below ROOT ("" = live, or $MCP_ROM) as
#   F<TAB>path<TAB>package      one line per file a package owns
#   V<TAB>package<TAB>version   one line per installed package
# opkg (info/*.list, status) on 21.02-24.10, apk (db/installed) on 25.12.
fx_pkgdb() {
	_pr=${1%/}
	# /opt/lib/opkg is Entware's database: its packages live below /opt
	for _pd in "$_pr/usr/lib/opkg" "$_pr/opt/lib/opkg"; do
		[ -d "$_pd/info" ] || continue
		find "$_pd/info" -maxdepth 1 -name '*.list' -print0 2>/dev/null |
			xargs -0 -r awk 'FNR == 1 { p = FILENAME; sub(/.*\//, "", p); sub(/\.list$/, "", p) }
				{ print "F\t" $0 "\t" p }' 2>/dev/null
		[ -f "$_pd/status" ] && awk '
			/^Package: / { p = $2 }
			/^Version: / { if (p != "") print "V\t" p "\t" $2; p = "" }' "$_pd/status" 2>/dev/null
	done
	[ -f "$_pr/lib/apk/db/installed" ] && awk '
		/^P:/ { p = substr($0, 3); d = "" }
		/^V:/ { print "V\t" p "\t" substr($0, 3) }
		/^F:/ { d = substr($0, 3) }
		/^R:/ { print "F\t/" (d == "" ? "" : d "/") substr($0, 3) "\t" p }' "$_pr/lib/apk/db/installed" 2>/dev/null
	return 0
}

# fx_pkg: filter. Appends two fields to fx_cmp records: the package that owns the path
# ("-" when none) and how that package relates to the image:
#   image        preinstalled, same version as in the image
#   upgraded A>B preinstalled, but the installed version differs from the image's
#   added        installed after flashing
#   removed      (deleted paths) owned by an image package that is no longer installed
# The database is an ordinary writable file, so ownership is a hint, never proof.
fx_pkg() {
	_pt=$MCP_TMP/pkg.$$
	fx_pkgdb "" >"$_pt.l"
	: >"$_pt.r"
	fx_rom_ok && fx_pkgdb "$MCP_ROM" >"$_pt.r"
	FX_PL="$_pt.l" FX_PR="$_pt.r" awk '
		BEGIN { FS = "\t"; OFS = "\t" }
		FILENAME == ENVIRON["FX_PL"] { if ($1 == "F") own[$2] = $3; else lv[$2] = $3; next }
		FILENAME == ENVIRON["FX_PR"] { if ($1 == "F") rown[$2] = $3; else { rv[$2] = $3; hasrom = 1 } next }
		{
			p = "-"; q = "-"; k = $9
			if (k in own) {
				p = own[k]
				if (!hasrom) q = "installed"
				else if (!(p in rv)) q = "added"
				else if (rv[p] != lv[p]) q = "upgraded " rv[p] ">" lv[p]
				else q = "image"
			} else if (k in rown) {
				p = rown[k]
				q = (p in lv) ? "image" : "removed"
				if (q == "image" && rv[p] != lv[p]) q = "upgraded " rv[p] ">" lv[p]
			}
			print $0, p, q
		}' "$_pt.l" "$_pt.r" -
	rm -f "$_pt.l" "$_pt.r"
}

# ---------------------------------------------------------------- first boot
# What the firmware writes at its first boot looks like a change against the image, and
# is none. It can be told apart by time: OpenWrt has no clock at first boot, sysfixtime
# sets it to the newest file below /etc of the image, and it runs from there until NTP
# answers. So everything the first-boot scripts (uci-defaults) write is dated within
# minutes after the newest file of $MCP_ROM/etc, while a later change carries the real
# date, which lies after the day the firmware was installed.
#
# fx_fbwindow prints "START<TAB>END" (ls time format): the newest file below
# $MCP_ROM/etc and one hour later. It fails when there is no image, or when the clock
# of the device is itself inside the window (not yet set): then nothing can be told.
FX_FB_SECONDS=3600
fx_fbwindow() {
	fx_rom_ok || return 1
	_fb0=$(find "${MCP_ROM%/}/etc" -xdev -type f -print0 2>/dev/null | fx_ls |
		awk "$FX_AWK_LS"'{ if (fx_ls($0) && F_mtime > m) m = F_mtime } END { print m }')
	[ -n "$_fb0" ] || return 1
	_fbs=$(date -d "$_fb0" +%s 2>/dev/null) || return 1
	[ "$(date +%s)" -gt $((_fbs + FX_FB_SECONDS)) ] || return 1
	printf '%s\t%s\n' "$_fb0" "$(date -d "@$((_fbs + FX_FB_SECONDS))" '+%Y-%m-%d %H:%M:%S')"
}

# fx_firstboot ROOT: filter. Appends one field to fx_cmp/fx_pkg records: "firstboot"
# when the entry was written in the first-boot window, else "-". Both times must lie in
# the window: the mtime, and the ctime, which touch cannot set (only a changed system
# clock can). MCP_FIRSTBOOT_CTIME=0 judges by mtime alone; it exists for the tests, which
# cannot create a file with an old ctime.
: "${MCP_FIRSTBOOT_CTIME:=1}"
fx_firstboot() {
	_ft=$MCP_TMP/fb.$$
	cat >"$_ft.in"
	: >"$_ft.c"
	if _fw=$(fx_fbwindow); then
		_f0=${_fw%%"$FX_TAB"*}
		_f1=${_fw#*"$FX_TAB"}
		if [ "$MCP_FIRSTBOOT_CTIME" = 1 ]; then
			# shellcheck disable=SC2012
			FX_ROOT=${1%/} awk -F'\t' -v a="$_f0" -v b="$_f1" '$8 >= a && $8 <= b { print ENVIRON["FX_ROOT"] $9 }' "$_ft.in" |
				tr '\n' '\0' | xargs -0 -r ls -lndc --full-time 2>/dev/null >"$_ft.c"
		fi
	else
		_f0=
		_f1=
	fi
	FX_ROOT=${1%/} FX_C="$_ft.c" awk -F'\t' -v a="$_f0" -v b="$_f1" -v usec="$MCP_FIRSTBOOT_CTIME" "$FX_AWK_LS"'
		BEGIN { OFS = "\t"; ll = length(ENVIRON["FX_ROOT"]) }
		FILENAME == ENVIRON["FX_C"] { if (fx_ls($0)) ct[substr(F_path, ll + 1)] = F_mtime; next }
		{
			fb = "-"
			if (a != "" && $8 >= a && $8 <= b) {
				if (usec != 1) fb = "firstboot"
				else if (($9 in ct) && ct[$9] >= a && ct[$9] <= b) fb = "firstboot"
			}
			print $0, fb
		}' "$_ft.c" "$_ft.in"
	rm -f "$_ft.in" "$_ft.c"
}

# fx_path VAR ARGNAME [DEFAULT]: an absolute path argument without trailing slashes.
fx_path() {
	arg "$1" "$2" "${3-}"
	eval "_fp=\$$1"
	case $_fp in
	'') tool_error "$2 is required (an absolute path)"; return 1 ;;
	/*) ;;
	*) tool_error "$2 must be an absolute path, got '$_fp'"; return 1 ;;
	esac
	while [ "$_fp" != / ] && [ "${_fp%/}" != "$_fp" ]; do _fp=${_fp%/}; done
	eval "$1=\$_fp"
}

# fx_refuse PATH: prints why PATH must not be opened and returns 0; returns 1 when it is
# a regular file that is safe to read to the end (the same rule as rd, plus the /proc
# and /sys files that block or never end).
fx_refuse() {
	if [ -L "$1" ]; then
		_ft=$(readlink -f "$1" 2>/dev/null)
		case $1 in
		/proc/* | /sys/*) ;; # the kernel's own links (/proc/mounts, /proc/PID/exe): judged by what they resolve to
		*)
			case $_ft in
			/proc/* | /sys/* | /dev/*) echo "symlink into $_ft (links into /proc, /sys and /dev are not followed)"; return 0 ;;
			esac
			;;
		esac
	fi
	if [ -d "$1" ]; then echo "is a directory (use list_dir)"; return 0; fi
	if [ ! -e "$1" ]; then
		if [ -L "$1" ]; then echo "dangling symlink -> $(readlink "$1" 2>/dev/null)"; else echo "no such file"; fi
		return 0
	fi
	if [ ! -f "$1" ]; then
		echo "not a regular file (FIFOs, sockets and device nodes are never opened; list_dir shows its type)"
		return 0
	fi
	case $1 in
	/proc/kmsg | /proc/kcore | /proc/kpage* | /proc/*/mem | /proc/*/pagemap | /proc/*/clear_refs | /proc/sysrq-trigger | \
		/proc/*/fd/* | /proc/*/task/* | /sys/kernel/debug/* | /sys/kernel/tracing/* | */trace_pipe*)
		echo "a kernel file that blocks, never ends or has side effects"
		return 0
		;;
	esac
	return 1
}

# Names that hold key material in binary form (dropbear host keys, DER keys). With
# redaction on, the raw views of read_file refuse them: redact only understands text.
fx_secret_name() {
	case $1 in
	*/dropbear_*_host_key | */ssh_host_*_key | *.key | *.pem | *.der | *.p12 | *.pfx | */id_rsa | */id_dsa | \
		*/id_ecdsa | */id_ed25519 | */shadow | */shadow- | */shadow.* | *-secrets | *.kdbx | *.jks)
		return 0
		;;
	esac
	return 1
}

# Second redaction pass for the file tools: "name=value", "name: value" and JSON pairs
# whose name is a secret (hostapd and wpa_supplicant configs, env files, ppp secrets).
# The core's redact covers uci, shadow and PEM blocks; this covers what it does not.
fx_redact_kv() {
	if [ "$MCP_REDACT" != 1 ]; then
		cat
		return
	fi
	FX_RNAME=${1-} awk '
	BEGIN {
		w = "(key|password|passwd|pass|psk|secret|private_key|privatekey|preshared_key|presharedkey|token|auth_secret|sae_password|wpa_passphrase|passphrase|wep_key[0-9]|wpa_psk|pin|community|credentials)"
		re = "(^|[_.-])" w "$"
		ppp = (ENVIRON["FX_RNAME"] ~ /-secrets$/)
	}
	{
		line = $0
		if (ppp && line !~ /^[ \t]*#/ && NF >= 3) { print $1, $2, "<redacted>"; next }
		# WEP key slots of /etc/config/wireless (key1..key4), which redact does not know
		if (match(line, /^[ \t]*(option|list)[ \t]+["\047]?key[1-4]["\047]?[ \t]+/) || match(line, /^[^=. ]+\.[^=. ]+\.key[1-4]=/)) {
			print substr(line, 1, RLENGTH) "\047<redacted>\047"; next
		}
		if (match(line, /^[ \t]*(export[ \t]+)?[A-Za-z0-9_.-]+[ \t]*[=:][ \t]*/)) {
			head = substr(line, 1, RLENGTH); val = substr(line, RLENGTH + 1)
			name = head; sub(/^[ \t]*(export[ \t]+)?/, "", name); sub(/[ \t]*[=:][ \t]*$/, "", name)
			if (val != "" && val !~ /^<redacted/ && tolower(name) ~ re) { print head "<redacted>"; next }
		}
		out = ""
		while (match(line, /"[A-Za-z0-9_.-]+"[ \t]*:[ \t]*"[^"]*"/)) {
			pair = substr(line, RSTART, RLENGTH); name = pair; sub(/^"/, "", name); sub(/".*/, "", name)
			if (tolower(name) ~ re) { sub(/:[ \t]*"[^"]*"$/, ": \"<redacted>\"", pair) }
			out = out substr(line, 1, RSTART - 1) pair; line = substr(line, RSTART + RLENGTH)
		}
		line = out line; out = ""
		# password=... inside a command line or a URL (cron jobs for DDNS, rc.local)
		while (match(line, /([Pp]ass(word|wd)?|PASS(WORD|WD)?|[Ss]ecret|SECRET|[Tt]oken|TOKEN)=[^ \t&;"\047<]+/)) {
			pair = substr(line, RSTART, RLENGTH); sub(/=.*/, "=<redacted>", pair)
			out = out substr(line, 1, RSTART - 1) pair; line = substr(line, RSTART + RLENGTH)
		}
		line = out line
		# scheme://user:password@host
		if (match(line, /:\/\/[^\/ \t:@]+:[^\/ \t@]+@/)) {
			cred = substr(line, RSTART, RLENGTH); sub(/:[^:@]+@$/, ":<redacted>@", cred)
			line = substr(line, 1, RSTART - 1) cred substr(line, RSTART + RLENGTH)
		}
		print line
	}'
}

# fx_show PATH MAXLINES [all]: the active lines of a text file (comments and blank
# lines dropped unless "all"), redacted, indented, cut after MAXLINES.
fx_show() {
	if _fr=$(fx_refuse "$1"); then
		printf '      (not shown: %s)\n' "$_fr"
		return 0
	fi
	if [ "$(rd "$1" | head -c 2048 | wc -c)" != "$(rd "$1" | head -c 2048 | tr -d '\000' | wc -c)" ]; then
		echo "      (binary file: read_file view=strings and file_hash look inside)"
		return 0
	fi
	rd "$1" | tr -d '\000\r' | redact | fx_redact_kv "$1" | awk -v max="$2" -v all="${3-}" '
		all == "" && /^[ \t]*(#|$)/ { next }
		{ n++; if (n <= max) print "      " ((length($0) > 400) ? substr($0, 1, 400) " [+" (length($0) - 400) " chars]" : $0) }
		END {
			if (n > max) print "      [" (n - max) " more lines; read_file shows the whole file]"
			if (n == 0) print "      (no active lines)"
		}'
}

# ---------------------------------------------------------------- read_file
mcp_register read_file <<'EOF'
{"name":"read_file","title":"Read a file","description":"Reads one file on the router with paging: text with line numbers, a binary file as hex dump (view=hex) or as its printable strings (view=strings). The header gives type, mode, owner, size, mtime and whether the file equals the same path in the firmware image. While redaction is on, text passes through the secret filter (Wi-Fi keys, password hashes and private keys are masked) and the raw views of key files are refused. FIFOs, sockets, device nodes and links into /proc, /sys or /dev are never opened.","inputSchema":{"type":"object","properties":{"path":{"type":"string","description":"Absolute path of the file."},"view":{"type":"string","enum":["auto","text","hex","strings"],"description":"auto (default): text for text files; for binary files the first 256 bytes as hex. text: lines. hex: hexdump -C. strings: printable strings of at least min_length characters.","default":"auto"},"offset":{"type":"integer","description":"Where to start: lines to skip for text and strings, bytes to skip for hex. Default 0.","default":0,"minimum":0},"limit":{"type":"integer","description":"How much to return: lines for text and strings (default 200, at most 2000), bytes for hex (default 512, at most 8192).","minimum":1},"min_length":{"type":"integer","description":"Shortest string for view=strings. Default 6.","default":6,"minimum":2,"maximum":64},"line_numbers":{"type":"boolean","description":"Prefix text lines with their line number. Default true.","default":true}},"required":["path"],"additionalProperties":false},"annotations":{"readOnlyHint":true,"openWorldHint":false}}
EOF
tool_read_file() {
	fx_path p path || return 1
	arg view view auto
	case $view in auto | text | hex | strings) ;; *) tool_error "view must be auto, text, hex or strings, got '$view'"; return 1 ;; esac
	arg_int off offset 0 0 2000000000 || return 1
	arg_int minlen min_length 6 2 64 || return 1
	if why=$(fx_refuse "$p"); then
		tool_error "$p: $why"
		return 1
	fi
	src=$p
	note=
	kernel=0
	case $p in
	/proc/* | /sys/*)
		# Kernel files have no size and may stall: copy at most 1 MB with a time limit.
		# This is the one read that does not go through rd: rd refuses links into /proc,
		# and /proc/mounts or /proc/PID/exe (which still reads a deleted binary) are such
		# links. fx_refuse has already ruled out the files that block.
		kernel=1
		src=$MCP_TMP/read.snap
		run_timeout 5 fx_snap "$p" >"$src"
		note="kernel file: read once with a 5 s limit, at most 1048576 bytes"
		;;
	esac
	# binary when the first 8192 bytes hold a NUL byte
	n1=$(rd "$src" | head -c 8192 | wc -c)
	n2=$(rd "$src" | head -c 8192 | tr -d '\000' | wc -c)
	binary=0
	[ "$n1" = "$n2" ] || binary=1
	[ "$view" = auto ] && { if [ "$binary" = 1 ]; then view=hexhead; else view=text; fi; }
	case $view in
	hex) arg_int lim limit 512 1 8192 || return 1 ;;
	hexhead)
		lim=256
		off=0
		;;
	*) arg_int lim limit 200 1 2000 || return 1 ;;
	esac

	printf '%s\0' "$p" | fx_ls | fx_cmp "" "$((1 - kernel))" | FX_P="$p" FX_BIN="$binary" FX_K="$kernel" awk -F'\t' "$FX_AWK_FMT"'
		BEGIN { fx_names() }
		{
			fx_rec()
			printf "path   %s%s\n", ENVIRON["FX_P"], (R_target != "-") ? " -> " R_target : ""
			printf "type   %s, mode %s, owner %s, mtime %s\n", (ENVIRON["FX_BIN"] == 1) ? "binary file" : "text file", R_mode, fx_owner(), R_mtime
			w = SW[R_state]
			if (R_state == "noimage") w = "not compared (no usable firmware image)"
			if (R_state == "new") w = "not in the firmware image"
			if (R_state == "same") w = "same as the firmware image"
			if (ENVIRON["FX_K"] == 1) w = "not applicable (kernel file)"
			printf "image  %s%s\n", w, (R_detail != "-") ? " (" R_detail ")" : ""
		}'
	size=$(rd "$src" | wc -c)
	printf 'size   %s bytes\n' "$size"
	[ -n "$note" ] && printf 'note   %s\n' "$note"

	raw_ok=1
	if [ "$MCP_REDACT" = 1 ] && fx_secret_name "$p"; then raw_ok=0; fi
	case $view in
	text)
		total=$(rd "$src" | wc -l)
		if [ "$binary" = 1 ] && [ "$raw_ok" = 0 ]; then
			tool_error "binary key material; not shown while redaction is on (file_hash still works)"
			return 1
		fi
		arg_bool line_numbers true && num=1 || num=0
		echo
		rd "$src" | tr -d '\000' | redact | fx_redact_kv "$p" | awk -v off="$off" -v lim="$lim" -v num="$num" -v total="$total" '
			NR <= off { next }
			NR > off + lim { more = 1; exit }
			{
				line = $0
				if (length(line) > 2000) line = substr(line, 1, 2000) " [+" (length($0) - 2000) " chars]"
				if (num) printf "%6d  %s\n", NR, line; else print line
				shown++
			}
			END {
				if (!shown) printf "[no lines after offset %d; the file has %d lines]\n", off, total
				else if (more) printf "\n[lines %d-%d of %d; continue with offset=%d]\n", off + 1, off + shown, total, off + shown
				else printf "\n[lines %d-%d, end of file]\n", off + 1, off + shown
			}'
		;;
	hex | hexhead)
		if [ "$raw_ok" = 0 ]; then
			tool_error "key material; raw views are refused while redaction is on (view=text masks it, file_hash still works)"
			return 1
		fi
		echo
		if [ "$binary" = 1 ]; then rd "$src"; else rd "$src" | redact | fx_redact_kv "$p"; fi |
			tail -c +$((off + 1)) | head -c "$lim" | hexdump -C | awk -v off="$off" '
			function hex(h,   i, n) { n = 0; for (i = 1; i <= length(h); i++) n = n * 16 + index("0123456789abcdef", substr(h, i, 1)) - 1; return n }
			/^[0-9a-f]+/ { a = $1; printf "%08x%s\n", hex(a) + off, substr($0, length(a) + 1); next }
			{ print }'
		end=$((off + lim))
		if [ "$end" -lt "$size" ]; then
			printf '\n[bytes %s-%s of %s; continue with view=hex offset=%s' "$off" "$((end - 1))" "$size" "$end"
			[ "$view" = hexhead ] && printf '; view=strings lists the readable strings'
			printf ']\n'
		else
			printf '\n[bytes from %s to the end of the file (%s bytes)]\n' "$off" "$size"
		fi
		[ "$binary" = 0 ] && [ "$MCP_REDACT" = 1 ] && echo "[text file: offsets count the redacted text]"
		;;
	strings)
		if [ "$raw_ok" = 0 ]; then
			tool_error "key material; raw views are refused while redaction is on (view=text masks it, file_hash still works)"
			return 1
		fi
		have strings || { tool_error "strings: not available"; return 1; }
		echo
		rd "$src" | strings -n "$minlen" | redact | fx_redact_kv "$p" | awk -v off="$off" -v lim="$lim" '
			NR <= off { next }
			NR > off + lim { more = 1; exit }
			{ print (length($0) > 500) ? substr($0, 1, 500) " [+" (length($0) - 500) " chars]" : $0; shown++ }
			END {
				if (!shown) printf "[no strings after offset %d]\n", off
				else if (more) printf "\n[strings %d-%d; continue with offset=%d]\n", off + 1, off + shown, off + shown
				else printf "\n[strings %d-%d, end of file]\n", off + 1, off + shown
			}'
		;;
	esac
	rm -f "$MCP_TMP/read.snap"
	return 0
}

# ---------------------------------------------------------------- list_dir
mcp_register list_dir <<'EOF'
{"name":"list_dir","title":"List a directory","description":"Lists a directory: type, mode, owner, size, mtime, link target and, per entry, whether it equals the same path in the firmware image (same, CHANGED, meta, new). Use it to look around a suspicious location; depth lists subdirectories too. Entries are sorted by path; mount points are listed but not entered, and /proc, /sys and /dev are only listed one level deep.","inputSchema":{"type":"object","properties":{"path":{"type":"string","description":"Absolute path of the directory. Default /.","default":"/"},"depth":{"type":"integer","description":"Levels to descend. Default 1 (the directory's own entries).","default":1,"minimum":1,"maximum":6},"max_entries":{"type":"integer","description":"Stop after this many entries. Default 300.","default":300,"minimum":1,"maximum":2000},"compare_image":{"type":"boolean","description":"Compare each entry with the firmware image (hashes files of equal size). Default true.","default":true}},"additionalProperties":false},"annotations":{"readOnlyHint":true,"openWorldHint":false}}
EOF
tool_list_dir() {
	fx_path p path / || return 1
	arg_int depth depth 1 1 6 || return 1
	arg_int max max_entries 300 1 2000 || return 1
	cmp=1
	arg_bool compare_image true || cmp=0
	if [ ! -d "$p" ]; then
		if [ -e "$p" ] || [ -L "$p" ]; then tool_error "$p is not a directory (read_file reads files)"; else tool_error "$p: no such directory"; fi
		return 1
	fi
	real=$(readlink -f "$p" 2>/dev/null)
	note=
	case ${real:-$p} in
	/proc | /proc/* | /sys | /sys/* | /dev | /dev/*)
		[ "$depth" -gt 1 ] && note="depth forced to 1 below /proc, /sys and /dev"
		depth=1
		case ${real:-$p} in /dev/shm | /dev/shm/*) ;; *) cmp=0 ;; esac
		;;
	esac
	start=$p/
	[ "$p" = / ] && start=/
	lst=$MCP_TMP/list.ls
	# 5001 lines at most are ever kept; the listing says when that cut it short
	find "$start" -xdev -mindepth 1 -maxdepth "$depth" ! -path '/tmp/openwrt-mcp.*' -print0 2>/dev/null |
		fx_ls | head -n 5001 >"$lst"
	total=$(wc -l <"$lst")
	printf 'directory %s' "$p"
	[ -n "$real" ] && [ "$real" != "$p" ] && printf ' -> %s' "$real"
	printf ', depth %s\n' "$depth"
	if [ "$total" -eq 0 ]; then
		echo "(empty)"
		rm -f "$lst"
		return 0
	fi
	echo "$FX_LEGEND"
	[ -n "$note" ] && echo "note: $note"
	echo
	awk "$FX_AWK_LS"'{ if (fx_ls($0)) print F_path "\t" $0 }' "$lst" | sort | head -n "$max" | cut -f2- |
		fx_cmp "" "$cmp" | fx_sortk 9 | awk -F'\t' "$FX_AWK_FMT"'
		BEGIN { fx_names() }
		{ fx_rec(); print fx_fmt() }'
	echo
	if [ "$total" -gt 5000 ]; then
		echo "[showing $max entries of more than 5000; lower depth or list a subdirectory]"
	elif [ "$total" -gt "$max" ]; then
		echo "[showing $max of $total entries; raise max_entries or list a subdirectory]"
	else
		echo "[entries: $total]"
	fi
	if ! fx_rom_ok; then
		echo "[no usable firmware image at $MCP_ROM: the image column is empty]"
	fi
	rm -f "$lst"
	return 0
}

# ---------------------------------------------------------------- find_files
mcp_register find_files <<'EOF'
{"name":"find_files","title":"Find files","description":"Searches the filesystem by name, type, modification time, permission bits (setuid, setgid, world-writable, executable) and size, and lists the matches like list_dir, newest first, with the firmware-image comparison per match. Use it for questions like 'what changed in the last hour', 'which setuid files exist' or 'where is a file called X'. It stays on the filesystem of each root (never /proc, /sys, /dev); without a path it searches / and /tmp.","inputSchema":{"type":"object","properties":{"path":{"type":"string","description":"Absolute directory to search. Default: / and /tmp (the RAM disk)."},"name":{"type":"string","description":"Shell pattern for the file name, e.g. '*.sh' or 'gl_*'. A pattern with a slash matches the whole path, e.g. '*/init.d/*'."},"type":{"type":"string","enum":["file","dir","symlink","char","block","fifo","socket"],"description":"Only entries of this type. Default: any."},"perm":{"type":"string","enum":["suid","sgid","world_writable","executable"],"description":"Only entries with this permission: setuid bit, setgid bit, writable by everyone (symlinks excluded), or any execute bit. Default: any."},"modified_within_minutes":{"type":"integer","description":"Only entries modified less than this many minutes ago.","minimum":1},"modified_before_minutes":{"type":"integer","description":"Only entries modified more than this many minutes ago.","minimum":1},"newer_than":{"type":"string","description":"Absolute path of a reference file: only entries modified after it."},"min_size":{"type":"integer","description":"Only files of at least this many bytes.","minimum":0},"max_size":{"type":"integer","description":"Only files of at most this many bytes.","minimum":0},"max_depth":{"type":"integer","description":"Levels to descend below the root. Default: unlimited.","minimum":1,"maximum":64},"order":{"type":"string","enum":["mtime","path"],"description":"mtime (default): newest first. path: sorted by path.","default":"mtime"},"max_results":{"type":"integer","description":"Stop after this many matches. Default 200.","default":200,"minimum":1,"maximum":2000},"compare_image":{"type":"boolean","description":"Compare each match with the firmware image. Default true.","default":true}},"additionalProperties":false},"annotations":{"readOnlyHint":true,"openWorldHint":false}}
EOF
tool_find_files() {
	arg_int max max_results 200 1 2000 || return 1
	arg order order mtime
	case $order in mtime | path) ;; *) tool_error "order must be mtime or path, got '$order'"; return 1 ;; esac
	cmp=1
	arg_bool compare_image true || cmp=0
	if arg_has path; then
		fx_path p path || return 1
		[ -d "$p" ] || { tool_error "$p: no such directory"; return 1; }
		case $(readlink -f "$p" 2>/dev/null) in
		/proc | /proc/* | /sys | /sys/*) tool_error "find_files does not walk /proc or /sys (list_dir shows one level)"; return 1 ;;
		esac
		roots=$p
		[ "$p" = / ] || p=$p/
		set -- "$p"
	else
		# /tmp is a RAM disk of its own on a router; in a container it is part of /
		if grep -q '^[^ ]* /tmp ' /proc/mounts 2>/dev/null; then
			roots="/ /tmp"
			set -- / /tmp/
		else
			roots=/
			set -- /
		fi
	fi
	set -- "$@" -xdev -mindepth 1
	desc=
	if arg_has max_depth; then
		arg_int n max_depth 64 1 64 || return 1
		set -- "$@" -maxdepth "$n"
		desc="$desc depth<=$n"
	fi
	set -- "$@" ! -path '/tmp/openwrt-mcp.*'
	if arg_has name; then
		arg name name
		case $name in */*) set -- "$@" -path "$name" ;; *) set -- "$@" -name "$name" ;; esac
		desc="$desc name=$name"
	fi
	if arg_has type; then
		arg type type
		case $type in
		file) t=f ;; dir) t=d ;; symlink) t=l ;; char) t=c ;; block) t=b ;; fifo) t=p ;; socket) t=s ;;
		*) tool_error "type must be file, dir, symlink, char, block, fifo or socket, got '$type'"; return 1 ;;
		esac
		set -- "$@" -type "$t"
		desc="$desc type=$type"
	fi
	if arg_has perm; then
		arg perm perm
		case $perm in
		suid) set -- "$@" -perm -4000 ;;
		sgid) set -- "$@" -perm -2000 ;;
		world_writable) set -- "$@" -perm -0002 ! -type l ;;
		executable) set -- "$@" -perm /0111 ! -type l ! -type d ;;
		*) tool_error "perm must be suid, sgid, world_writable or executable, got '$perm'"; return 1 ;;
		esac
		desc="$desc perm=$perm"
	fi
	if arg_has modified_within_minutes; then
		arg_int n modified_within_minutes 1 1 100000000 || return 1
		set -- "$@" -mmin "-$n"
		desc="$desc modified<${n}min"
	fi
	if arg_has modified_before_minutes; then
		arg_int n modified_before_minutes 1 1 100000000 || return 1
		set -- "$@" -mmin "+$n"
		desc="$desc modified>${n}min"
	fi
	if arg_has newer_than; then
		fx_path ref newer_than || return 1
		[ -e "$ref" ] || { tool_error "newer_than: $ref does not exist"; return 1; }
		set -- "$@" -newer "$ref"
		desc="$desc newer_than=$ref"
	fi
	if arg_has min_size; then
		arg_int n min_size 0 0 2000000000 || return 1
		[ "$n" -gt 0 ] && set -- "$@" -type f -size "+$((n - 1))c"
		desc="$desc size>=$n"
	fi
	if arg_has max_size; then
		arg_int n max_size 0 0 2000000000 || return 1
		set -- "$@" -type f -size "-$((n + 1))c"
		desc="$desc size<=$n"
	fi
	lst=$MCP_TMP/find.ls
	run_timeout 40 fx_find_ls "$@" >"$lst"
	[ $? = 124 ] && echo "note: the search hit its 40 s limit, the result is incomplete"
	total=$(wc -l <"$lst")
	printf 'search in %s:%s\n' "$roots" "${desc:- (no filter)}"
	if [ "$total" -eq 0 ]; then
		echo "no matches"
		rm -f "$lst"
		return 0
	fi
	echo "$FX_LEGEND"
	echo
	if [ "$order" = mtime ]; then
		awk "$FX_AWK_LS"'{ if (fx_ls($0)) print F_mtime "\t" $0 }' "$lst" | sort -r
	else
		awk "$FX_AWK_LS"'{ if (fx_ls($0)) print F_path "\t" $0 }' "$lst" | sort
	fi | head -n "$max" | cut -f2- | fx_cmp "" "$cmp" |
		if [ "$order" = mtime ]; then fx_sortk 8 r; else fx_sortk 9; fi |
		awk -F'\t' "$FX_AWK_FMT"'
		BEGIN { fx_names() }
		{ fx_rec(); print fx_fmt() }'
	echo
	if [ "$total" -gt 20000 ]; then
		echo "[showing $max matches of more than 20000 (search stopped there); narrow the search]"
	elif [ "$total" -gt "$max" ]; then
		echo "[showing $max of $total matches ($([ "$order" = mtime ] && echo "the newest" || echo "the first by path")); raise max_results or narrow the search]"
	else
		echo "[matches: $total]"
	fi
	rm -f "$lst"
	return 0
}

# ---------------------------------------------------------------- file_hash
mcp_register file_hash <<'EOF'
{"name":"file_hash","title":"Hash files","description":"SHA-256 (or MD5) of up to 50 files, each compared with the same path in the firmware image when the image has it, plus the package that owns the path. Use it to prove that a binary was replaced, or to get a hash for a threat-intelligence lookup. Only regular files are hashed; FIFOs, devices and links into /proc, /sys or /dev are refused.","inputSchema":{"type":"object","properties":{"paths":{"type":"array","items":{"type":"string"},"description":"Absolute paths of the files, at most 50.","minItems":1,"maxItems":50},"algorithm":{"type":"string","enum":["sha256","md5"],"description":"Hash algorithm. Default sha256.","default":"sha256"}},"required":["paths"],"additionalProperties":false},"annotations":{"readOnlyHint":true,"openWorldHint":false}}
EOF
tool_file_hash() {
	arg alg algorithm sha256
	case $alg in sha256 | md5) ;; *) tool_error "algorithm must be sha256 or md5, got '$alg'"; return 1 ;; esac
	have "${alg}sum" || { tool_error "${alg}sum: not available"; return 1; }
	arg_has paths || { tool_error "paths is required (an array of absolute paths)"; return 1; }
	lst=$MCP_TMP/hash.paths
	arg_list paths >"$lst"
	n=$(wc -l <"$lst")
	[ "$n" -ge 1 ] || { tool_error "paths is empty"; return 1; }
	[ "$n" -le 50 ] || { tool_error "at most 50 paths per call, got $n"; return 1; }
	fx_rom_ok || echo "note: no usable firmware image at $MCP_ROM, hashes are not compared"
	meta=$MCP_TMP/hash.meta
	# only absolute paths reach ls: anything else could be read as an option
	grep '^/' "$lst" | tr '\n' '\0' | fx_ls | fx_cmp "" 0 | fx_pkg >"$meta"
	while IFS= read -r p; do
		echo
		echo "$p"
		case $p in
		/*) ;;
		*) echo "  error    not an absolute path"; continue ;;
		esac
		if why=$(fx_refuse "$p"); then
			echo "  error    $why"
			continue
		fi
		run_timeout 60 fx_sum "$alg" "$p" >"$MCP_TMP/hash.one"
		h=$(cat "$MCP_TMP/hash.one")
		[ -n "$h" ] || h="(not hashed within 60 s)"
		FX_P="$p" awk -F'\t' -v alg="$alg" -v h="$h" '$9 == ENVIRON["FX_P"] {
			printf "  %-8s %s\n  file     %s bytes, mode %s, owner %s:%s, mtime %s\n", alg, h, $7, $4, $5, $6, $8
			if ($11 != "-") printf "  package  %s (%s)\n", $11, $12; else print "  package  none owns this path"
			exit }' "$meta"
		r=$(rom_path "$p")
		if ! fx_rom_ok; then
			:
		elif [ -L "$r" ]; then
			echo "  image    DIFFERENT TYPE: the image has a symlink -> $(readlink "$r" 2>/dev/null)"
		elif [ -f "$r" ]; then
			rh=$(fx_sum "$alg" "$r")
			if [ "$rh" = "$h" ]; then
				echo "  image    same content ($r)"
			else
				echo "  image    DIFFERENT: $rh ($r)"
			fi
		elif [ -e "$r" ]; then
			echo "  image    DIFFERENT TYPE: $r is not a regular file"
		else
			echo "  image    not in the firmware image"
		fi
	done <"$lst"
	rm -f "$lst" "$meta" "$MCP_TMP/hash.one"
	return 0
}
