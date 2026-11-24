#!/bin/sh
# openwrt-mcp: an MCP server for OpenWrt routers, JSON-RPC 2.0 over stdio.
#
# bin/openwrt-mcp joins server/*.sh (in name order) into one file, copies it to /tmp on
# the router (RAM) and runs it through SSH. Nothing is written to flash.
#
# ---------------------------------------------------------------- module contract
# Every server/NN-name.sh file may:
#
#   mcp_register NAME <<'EOF'        register a tool; stdin is its JSON definition, one
#   {"name":"NAME",...}              object with name, title, description, inputSchema
#   EOF                              and annotations. Tools are listed in registration
#                                    order, so in file order.
#
#   tool_NAME() { ...; }             the handler. It writes plain text to stdout (stderr
#                                    is merged into it), never reads stdin (it is
#                                    /dev/null) and returns 0. A non-zero return, or
#                                    "tool_error MSG; return", marks the result isError.
#                                    It runs in a subshell: it may cd, set variables and
#                                    exit without harming the server. It starts in
#                                    $MCP_TMP/work, which is emptied before every call:
#                                    scratch files there never leak into the next call.
#
# Helpers a handler may use (and nothing else from this file):
#   arg VAR NAME [DEFAULT]           string argument into VAR (default if absent or null)
#   arg_int VAR NAME DEF MIN MAX     integer argument, validated; prints an error and
#                                    returns 1 when it is not an integer in range
#   arg_bool NAME DEFAULT            exit status 0 when the boolean is true
#   arg_list NAME                    array argument, one element per line
#   arg_has NAME                     exit status 0 when the argument is present
#   tool_error MSG                   print "error: MSG", return 1
#   section TITLE                    print a "== TITLE" heading
#   have CMD                         exit status 0 when CMD can be run
#   rd PATH                          cat PATH only when it is a regular file that is safe
#                                    to read to the end (no FIFO, no link anywhere in
#                                    the path into /proc, /sys or /dev)
#   in_rom PATH                      exit status 0 when PATH exists in the firmware image
#   rom_path PATH                    print PATH's location inside the firmware image
#   redact                           filter: masks secrets unless redaction is off
#   run_timeout SECS CMD [ARG...]    run CMD, kill it (and its children) after SECS
#   json_str                         filter: stdin to one JSON string literal
#   json_quote STRING                STRING as a JSON string literal
#   lib_sockets                      (server/05-lib.sh) one TSV line per socket
#
# Globals a handler may read: MCP_TMP (private temp dir, cleaned on exit), MCP_ROM,
# MCP_UPPER, MCP_REDACT, MCP_TRUSTED, MCP_MAX_OUTPUT, MCP_SERVER_VERSION.
#
# Environment knobs (set by the launcher or the tests):
#   MCP_ROM            firmware image root        default /rom
#   MCP_UPPER          overlay upper dir          default /overlay/upper
#   MCP_REDACT         1 masks secrets, 0 not     default 1
#   MCP_MAX_OUTPUT     bytes per tool result      default 60000
#   MCP_CALL_TIMEOUT   seconds per tool call      default 120
#   MCP_SELF_DELETE    1 removes this script file after start (launcher sets it)
#   MCP_DEBUG          1 logs requests to stderr
#   MCP_PROC           proc root for the audit's process checks (tests)  default /proc
#
# ---------------------------------------------------------------- how a call runs
# The arguments are checked against the tool's inputSchema first (unknown names, JSON
# types, required ones); a mismatch is a tool result with isError, not a protocol error.
# The handler then runs in a background subshell, in an emptied $MCP_TMP/work, and
# writes into a FIFO. A reader (cat under a file size limit) copies a little more than
# MCP_MAX_OUTPUT bytes into $MCP_TMP/out and, when that limit is hit, stops the
# producer: a tool that prints 50 MB never fills /tmp. The text is cut again where its
# escaped JSON form reaches MCP_MAX_OUTPUT bytes. A watchdog kills the
# call's whole process tree after MCP_CALL_TIMEOUT seconds. Every process a call starts
# carries MCP_CALL_TAG in its environment, so the watchdog also catches children that
# left the tree (daemonized). The result text is checked as UTF-8: invalid bytes become
# U+FFFD, NUL bytes are dropped, control characters are escaped. Protocol messages go
# to the original stdout (fd 3 inside mcp_main); everything else goes to stderr.

MCP_SERVER_NAME=openwrt-mcp
MCP_SERVER_VERSION=0.1.0
MCP_PROTOCOLS="2025-11-25 2025-06-18 2025-03-26 2024-11-05"

: "${MCP_ROM:=/rom}"
: "${MCP_UPPER:=/overlay/upper}"
: "${MCP_REDACT:=1}"
: "${MCP_MAX_OUTPUT:=60000}"
: "${MCP_CALL_TIMEOUT:=120}"
: "${MCP_SELF_DELETE:=0}"
: "${MCP_DEBUG:=0}"
case $MCP_MAX_OUTPUT in '' | *[!0-9]* | 0* | ??????????*) MCP_MAX_OUTPUT=60000 ;; esac
case $MCP_CALL_TIMEOUT in '' | *[!0-9]* | 0* | ??????*) MCP_CALL_TIMEOUT=120 ;; esac

unset LD_PRELOAD LD_LIBRARY_PATH MCP_CALL_TAG
umask 077
MCP_TMP=$(mktemp -d /tmp/openwrt-mcp.XXXXXX) || { echo "openwrt-mcp: no temp dir" >&2; exit 1; }
MCP_REQ=$MCP_TMP/request.json
mkdir "$MCP_TMP/tools" "$MCP_TMP/work"

# pids of the running call (producer, reader, watchdog, grace timer) and its tag; the
# exit handler kills what is left of them
_mcp_P='' _mcp_R='' _mcp_W='' _mcp_G='' _mcp_tag=''
_mcp_cleanup() {
	trap '' HUP INT TERM PIPE
	# the alarms first, so they cannot act any more; then the call
	for _c in $_mcp_W $_mcp_G $_mcp_P $_mcp_R; do _mcp_kill_tree "$_c"; done
	[ -n "$_mcp_tag" ] && _mcp_kill_tree 0 "$_mcp_tag"
	rm -rf "$MCP_TMP"
}
trap '_mcp_cleanup' EXIT
# SIGHUP/SIGTERM (client gone, SSH dropped) and a broken stdout are a normal shutdown
trap 'exit 0' HUP TERM PIPE
trap 'exit 130' INT

[ "$MCP_SELF_DELETE" = 1 ] && case $0 in /tmp/*.sh) rm -f "$0" ;; esac

mcp_log() { [ "$MCP_DEBUG" = 1 ] && printf 'openwrt-mcp: %s\n' "$*" >&2; return 0; }

# ---------------------------------------------------------------- trusted tools
# A compromised router may have replaced applets in the overlay. Every tool call runs
# with the busybox of the firmware image first in PATH when the image has one, and
# with the image's jsonfilter when that works. OpenWrt builds busybox without
# "busybox --list", so the applet names come from the image's own links to it in
# bin, sbin, usr/bin and usr/sbin (relative or absolute targets); --list is a fallback
# where it works. The links are made with the image's own ln (the overlay's may be
# replaced too). MCP_PATH_ORIG keeps the router's own PATH (the exec tool offers it).
# shellcheck disable=SC2034  # used by server/90-exec.sh
MCP_PATH_ORIG=$PATH
MCP_TRUSTED=no
_mcp_bb=$MCP_ROM/bin/busybox
_mcp_ln() { $_mcp_lncmd -s "$1" "$2" 2>/dev/null; }
if [ -x "$_mcp_bb" ] && "$_mcp_bb" true 2>/dev/null; then
	mkdir "$MCP_TMP/bin"
	_mcp_lncmd="$_mcp_bb ln"
	case $_mcp_bb in *[!A-Za-z0-9_./-]*) _mcp_lncmd='ln' ;; esac
	$_mcp_lncmd -s "$_mcp_bb" "$MCP_TMP/bin/.probe" 2>/dev/null || _mcp_lncmd='ln'
	rm -f "$MCP_TMP/bin/.probe"
	# "R <rom path of a link>" for relative links (ln -s with many sources makes all of
	# them in one go, each resolving through the image's link), "A <name>" for absolute
	for _d in bin sbin usr/bin usr/sbin; do
		[ -d "$MCP_ROM/$_d" ] || continue
		echo "D /$_d"
		# shellcheck disable=SC2012
		ls -l "$MCP_ROM/$_d" 2>/dev/null
	done | awk -v rom="${MCP_ROM%/}" '
	function norm(p,   n, i, part, out, k, st) {
		n = split(p, part, "/"); k = 0
		for (i = 1; i <= n; i++) {
			if (part[i] == "" || part[i] == ".") continue
			if (part[i] == "..") { if (k > 0) k--; continue }
			st[++k] = part[i]
		}
		out = ""
		for (i = 1; i <= k; i++) out = out "/" st[i]
		return out
	}
	$1 == "D" { d = $2; next }
	/^l/ && $(NF - 1) == "->" {
		name = $(NF - 2); t = $NF
		if (name ~ /\// || name == "busybox") next
		if (substr(t, 1, 1) == "/") { if (norm(t) == "/bin/busybox") print "A " name }
		else if (norm(d "/" t) == "/bin/busybox") print "R " rom d "/" name
	}' >"$MCP_TMP/applets"
	# shellcheck disable=SC2016  # the inner script expands its own arguments
	sed -n 's/^R //p' "$MCP_TMP/applets" |
		xargs sh -c 'l=$1 d=$2; shift 2; $l -s "$@" "$d" 2>/dev/null' sh "$_mcp_lncmd" "$MCP_TMP/bin"
	for _a in $(sed -n 's/^A //p' "$MCP_TMP/applets") $("$_mcp_bb" --list 2>/dev/null); do
		case $_a in */* | . | .. | busybox) continue ;; esac
		[ -e "$MCP_TMP/bin/$_a" ] || [ -L "$MCP_TMP/bin/$_a" ] || _mcp_ln "$_mcp_bb" "$MCP_TMP/bin/$_a"
	done
	rm -f "$MCP_TMP/applets"
	# shellcheck disable=SC2012
	_mcp_napplets=$(ls "$MCP_TMP/bin" | wc -l)
	if [ "$_mcp_napplets" -gt 0 ]; then
		MCP_TRUSTED="yes ($_mcp_bb, $_mcp_napplets applets"
		if [ -x "$MCP_ROM/usr/bin/jsonfilter" ] &&
			[ "$("$MCP_ROM/usr/bin/jsonfilter" -s '{"a":7}' -e @.a 2>/dev/null)" = 7 ]; then
			_mcp_ln "$MCP_ROM/usr/bin/jsonfilter" "$MCP_TMP/bin/jsonfilter"
			MCP_TRUSTED="$MCP_TRUSTED; $MCP_ROM/usr/bin/jsonfilter"
		fi
		MCP_TRUSTED="$MCP_TRUSTED)"
		PATH="$MCP_TMP/bin:$PATH"
	else
		MCP_TRUSTED="no ($_mcp_bb runs, but no applet links to it were found in the image)"
	fi
fi
export PATH

# ---------------------------------------------------------------- JSON output
# _mcp_json_text CUT NOTE EMPTY [LIMIT CUTNOTE]: stdin bytes -> one JSON string literal.
# Valid UTF-8 passes through; every invalid byte sequence becomes U+FFFD (one per
# maximal invalid subpart); NUL bytes are dropped; other control characters and DEL
# are escaped. One trailing newline is dropped. CUT=1: the input was cut at a byte
# limit, so an incomplete sequence at the very end is dropped instead of replaced.
# NOTE: plain ASCII (no quote, no backslash) appended on a line of its own. EMPTY: the
# text used when the input has nothing but newlines and NULs. LIMIT: stop once the
# escaped text reaches LIMIT bytes (it ends on a whole character or escape, at most 9
# bytes over) and append CUTNOTE (unless NOTE is CUTNOTE already).
# awk gets numbers from hexdump, not bytes: busybox awk strings end at NUL, its substr
# is O(length) (quadratic on long binary lines), and its gsub replacement escapes
# differ between 1.33 and 1.37.
_mcp_json_text() {
	if ! have hexdump; then
		# fallback without hexdump: every byte outside ASCII becomes "?"
		tr -d '\000' | tr '\200-\377' '?' | awk -v note="$2" -v empty="$3" -v lim="${4:-0}" -v cutnote="${5-}" '
		function escl(s,   o) {
			o = ""
			while (match(s, /[\\"\001-\037\177]/)) {
				o = o substr(s, 1, RSTART - 1) esc[substr(s, RSTART, 1)]
				s = substr(s, RSTART + 1)
			}
			return o s
		}
		BEGIN {
			for (i = 1; i < 32; i++) esc[sprintf("%c", i)] = sprintf("\\u%04x", i)
			esc[sprintf("%c", 127)] = "\\u007f"
			esc["\t"] = "\\t"; esc["\r"] = "\\r"
			esc["\\"] = "\\\\"; esc["\""] = "\\\""
			printf "\""
		}
		{
			if ($0 != "") any = 1
			o = ((NR > 1) ? "\\n" : "") escl($0)
			# over the limit: cut the raw line by the worst case (6 bytes per byte)
			if (lim && w + length(o) > lim) { o = ((NR > 1) ? "\\n" : "") escl(substr($0, 1, int((lim - w) / 6))); stopped = 1 }
			w += length(o)
			printf "%s", o
			if (stopped) exit
		}
		END {
			if (!any && empty != "") printf "%s", empty
			if (stopped && cutnote != "" && note != cutnote) printf "\\n%s", cutnote
			if (note != "") printf "\\n%s", note
			printf "\""
		}'
		return
	fi
	hexdump -v -e '32/1 "%u " "\n"' | awk -v cut="$1" -v note="$2" -v empty="$3" -v lim="${4:-0}" -v cutnote="${5-}" '
	BEGIN {
		for (i = 1; i < 256; i++) chr[i] = sprintf("%c", i)
		for (i = 1; i < 32; i++) esc[i] = sprintf("\\u%04x", i)
		for (i = 32; i < 127; i++) esc[i] = chr[i]
		esc[9] = "\\t"; esc[13] = "\\r"; esc[127] = "\\u007f"
		esc[34] = "\\\""; esc[92] = "\\\\"
		for (i = 1; i < 128; i++) elen[i] = length(esc[i])
		bad = chr[239] chr[191] chr[189]
		need = 0; nl = 0; any = 0; seq = ""; w = 0
		printf "\""
	}
	{
		o = ""
		for (i = 1; i <= NF; i++) {
			if (lim && w >= lim) { stopped = 1; break }
			b = $i + 0
			if (need) {
				if (b >= lo && b <= hi) {
					seq = seq chr[b]; lo = 128; hi = 191
					if (--need == 0) { o = o seq; w += length(seq); seq = "" }
					continue
				}
				o = o bad; w += 3; need = 0; seq = ""
			}
			if (b == 10) { nl++; continue }
			if (b == 0) continue
			for (; nl > 0; nl--) { o = o "\\n"; w += 2; if (lim && w >= lim) break }
			if (nl) { stopped = 1; break }
			any = 1
			if (b < 128) { o = o esc[b]; w += elen[b]; continue }
			if (b >= 194 && b <= 223) { need = 1; lo = 128; hi = 191 }
			else if (b >= 224 && b <= 239) { need = 2; lo = (b == 224) ? 160 : 128; hi = (b == 237) ? 159 : 191 }
			else if (b >= 240 && b <= 244) { need = 3; lo = (b == 240) ? 144 : 128; hi = (b == 244) ? 143 : 191 }
			else { o = o bad; w += 3; continue }
			seq = chr[b]
		}
		printf "%s", o
		if (stopped) exit
	}
	END {
		if (!stopped) {
			if (need && !cut) printf "%s", bad
			if (any) for (; nl > 1; nl--) printf "\\n"
		}
		if (!any && empty != "") printf "%s", empty
		if (stopped && cutnote != "" && note != cutnote) printf "\\n%s", cutnote
		if (note != "") printf "\\n%s", note
		printf "\""
	}'
}

# stdin -> one JSON string literal (see _mcp_json_text; one trailing newline dropped)
json_str() { _mcp_json_text 0 "" ""; }

# STRING -> JSON string literal, exactly (a trailing newline in STRING is kept)
json_quote() { printf '%s\n' "$1" | _mcp_json_text 0 "" ""; }

# ---------------------------------------------------------------- arguments
_mcp_jf() { jsonfilter -i "$MCP_REQ" "$@" 2>/dev/null; }

arg() {
	_av=$(_mcp_jf -e "@.params.arguments.$2") || _av=${3-}
	eval "$1=\$_av"
}

arg_has() {
	case $(_mcp_jf -t "@.params.arguments.$1") in '' | null) return 1 ;; esac
	return 0
}

arg_int() {
	_av=$(_mcp_jf -e "@.params.arguments.$2") || _av=$3
	case $_av in
	'' | - | *[!0-9-]* | ?*-*) tool_error "$2 must be an integer, got '$_av'"; return 1 ;;
	*[0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9]*)
		tool_error "$2 must be between $4 and $5, got $_av"; return 1 ;;
	esac
	if [ "$_av" -lt "$4" ] || [ "$_av" -gt "$5" ]; then
		tool_error "$2 must be between $4 and $5, got $_av"; return 1
	fi
	eval "$1=\$_av"
}

arg_bool() {
	_av=$(_mcp_jf -e "@.params.arguments.$1") || _av=$2
	case $_av in true | 1) return 0 ;; *) return 1 ;; esac
}

arg_list() { _mcp_jf -e "@.params.arguments.$1[*]"; }

# _mcp_keys: stdin is one JSON object as jsonfilter prints it; prints "key<TAB>type"
# for each top-level member (type: string int double boolean null object array). Keys
# stay in their JSON-escaped form.
_mcp_keys() {
	awk '
	{ s = s $0 " " }
	END {
		d = 0
		while (s != "") {
			c = substr(s, 1, 1)
			if (c == "\"") {
				if (!match(s, /^"([^"\\]|\\.)*"/)) break
				k = substr(s, 2, RLENGTH - 2); s = substr(s, RLENGTH + 1)
				if (d != 1) continue
				sub(/^[ \t\n]+/, "", s)
				if (substr(s, 1, 1) != ":") continue
				s = substr(s, 2); sub(/^[ \t\n]+/, "", s)
				v = substr(s, 1, 1)
				if (v == "\"") t = "string"
				else if (v == "{") t = "object"
				else if (v == "[") t = "array"
				else if (v == "t" || v == "f") t = "boolean"
				else if (v == "n") t = "null"
				else { match(s, /^[-+0-9.eE]+/); t = (substr(s, 1, RLENGTH) ~ /[.eE]/) ? "double" : "int" }
				print k "\t" t
				continue
			}
			if (c == "{" || c == "[") d++
			else if (c == "}" || c == "]") d--
			if (match(s, /^.[^]["{}]*/)) s = substr(s, RLENGTH + 1)
			else s = substr(s, 2)
		}
	}'
}

# _mcp_schema NAME: the tool's declared arguments, cached: "arg NAME TYPE" lines, "req
# NAME" lines, and "strict" when additionalProperties is false.
_mcp_schema() {
	_sc=$MCP_TMP/tools/$1.args
	if [ ! -f "$_sc" ]; then
		for _sd in "$MCP_TMP"/tools/[0-9][0-9][0-9]-"$1".json; do :; done
		{
			jsonfilter -i "$_sd" -e '@.inputSchema.properties' 2>/dev/null | _mcp_keys |
				while IFS='	' read -r _sk _st; do
					printf 'arg %s %s\n' "$_sk" "$(jsonfilter -i "$_sd" -e "@.inputSchema.properties[\"$_sk\"].type" 2>/dev/null)"
				done
			jsonfilter -i "$_sd" -e '@.inputSchema.required[*]' 2>/dev/null | sed 's/^/req /'
			[ "$(jsonfilter -i "$_sd" -e '@.inputSchema.additionalProperties' 2>/dev/null)" = false ] && echo strict
		} >"$_sc"
	fi
	cat "$_sc"
}

# _mcp_check_args NAME: prints an error and returns 1 when the call's arguments do not
# fit the tool's inputSchema (unknown name, wrong JSON type, a required one missing).
_mcp_check_args() {
	case $(_mcp_jf -t @.params.arguments) in
	'' | null) _ca= ;;
	object) _ca=$(_mcp_jf -e @.params.arguments | _mcp_keys) ;;
	*) echo "error: invalid arguments: \"arguments\" must be a JSON object"; return 1 ;;
	esac
	{ _mcp_schema "$1"; printf '%s\n' "$_ca" | sed '/^$/d; s/^/got /'; } | awk -F '[ \t]' '
	$1 == "arg" { type[$2] = $3; sep = (names == "") ? "" : ", "; names = names sep $2 " (" ($3 == "" ? "any" : $3) ")"; next }
	$1 == "req" { req[$2] = 1; next }
	$1 == "strict" { strict = 1; next }
	$1 == "got" {
		k = $2; t = $3; got[k] = t
		if (t == "null") next
		if (!(k in type)) { if (strict && err == "") err = "unknown argument \"" k "\""; next }
		w = type[k]
		ok = (w == t || (w == "integer" && t == "int") || (w == "number" && (t == "int" || t == "double")))
		if (w != "string" && w != "integer" && w != "number" && w != "boolean" && w != "array" && w != "object") ok = 1
		if (!ok && err == "") err = "argument \"" k "\" must be " ((w == "integer" || w == "array" || w == "object") ? "an " : "a ") w ", got " (t == "int" ? "an integer" : t == "double" ? "a number" : t == "array" ? "an array" : t == "object" ? "an object" : "a " t)
	}
	END {
		if (err == "") for (k in req) if (!(k in got) || got[k] == "null") { err = "missing required argument \"" k "\""; break }
		if (err == "") exit 0
		print "error: invalid arguments: " err ". This tool takes: " (names == "" ? "no arguments" : names) "."
		exit 1
	}'
}

# ---------------------------------------------------------------- helpers
tool_error() { printf 'error: %s\n' "$*"; return 1; }

section() { printf '\n== %s\n' "$*"; }

have() { command -v "$1" >/dev/null 2>&1; }

rd() {
	[ -f "$1" ] || return 1
	# the whole path is resolved: a link anywhere in it (also a directory link, as in
	# /tmp/x/kmsg with /tmp/x -> /proc) must not lead into /proc, /sys or /dev unless
	# the path names that tree itself; after resolving it must still be a regular file
	if _t=$(readlink -f "$1" 2>/dev/null) && [ -n "$_t" ]; then
		[ -f "$_t" ] || return 1
		case $1 in /*) _l=$1 ;; *) _l=$PWD/$1 ;; esac
		case $_t in
		/proc/kmsg | */trace_pipe | */trace_pipe_raw) return 1 ;;
		/proc/*) case $_l in /proc/*) ;; *) return 1 ;; esac ;;
		/sys/*) case $_l in /sys/*) ;; *) return 1 ;; esac ;;
		/dev/*) case $_l in /dev/*) ;; *) return 1 ;; esac ;;
		esac
		cat "$_t" 2>/dev/null
		return
	fi
	# no readlink -f: only the last component can be checked
	case $1 in /proc/kmsg | */trace_pipe | */trace_pipe_raw) return 1 ;; esac
	if [ -L "$1" ]; then
		_t=$(readlink "$1" 2>/dev/null)
		case $_t in '' | /proc/* | /sys/* | /dev/*) return 1 ;; esac
	fi
	cat "$1" 2>/dev/null
}

rom_path() { printf '%s/%s' "${MCP_ROM%/}" "${1#/}"; }

in_rom() { [ -e "$(rom_path "$1")" ] || [ -L "$(rom_path "$1")" ]; }

# Masks secrets, line by line. Names count as secret when they contain password,
# passwd, passphrase, secret, token, credential, psk, privatekey, presharedkey or pwd, or
# have a word part pass, pin, pin<N>, pincode, community, keys, r0kh, r1kh or one ending
# in key (key, key1, apikey, private_key); public_key, pubkey, keyid, key_mgmt and
# *PasswordAuth stay readable. Formats: uci show (pkg.section.option=value), config
# files (option/list name value), shadow lines (any hash, also behind ! or *, DES),
# PEM private key blocks, WireGuard PrivateKey/PresharedKey =, hostapd r0kh=/r1kh=
# (last field) and per-station PSK files (... MAC PSK), name=value lines (hostapd,
# wpa_supplicant, shell, env; not when the value is a shell expansion), pretty-printed
# JSON members, and command lines: --name=value / --name value for secret names, and
# on lines that run something from a bin directory also pppd style "password value".
# A value that starts with $ (a shell variable) is never masked in name=value lines and
# command lines: it is not the secret, and scripts stay readable.
redact() {
	if [ "$MCP_REDACT" != 1 ]; then cat; return; fi
	awk '
	function issecret(n,   k, i, part) {
		n = tolower(n); gsub(/["'"'"']/, "", n)
		if (n ~ /^(.*[_-])?(pub|public)_?key$|^(.*[_-])?key_?(mgmt|id|index|type|len|length|size|format)$|password_?auth$/) return 0
		if (n ~ /password|passwd|passphrase|secret|token|credential|psk|privatekey|presharedkey|pwd/) return 1
		k = split(n, part, /[^a-z0-9]+/)
		for (i = 1; i <= k; i++)
			if (part[i] ~ /^(pass|pin|pin[0-9]+|pincode|community|keys|r[01]kh)$/ || part[i] ~ /key[0-9]*$/) return 1
		return 0
	}
	function isexp(v) { return v ~ /^["'"'"']?[$`]/ }
	function cmdl(s,   out, pre, t, mask, isbin, name, v) {
		isbin = (s ~ /(^|[ \t])(\/usr)?\/s?bin\//)
		out = ""; mask = 0
		while (match(s, /[^ \t]+/)) {
			pre = substr(s, 1, RSTART - 1); t = substr(s, RSTART, RLENGTH); s = substr(s, RSTART + RLENGTH)
			if (mask) { if (!isexp(t)) t = "<redacted>"; mask = 0 }
			else if (t ~ /^--?[A-Za-z][A-Za-z0-9_-]*=/) {
				name = substr(t, 1, index(t, "=") - 1); sub(/^--?/, "", name); v = substr(t, index(t, "=") + 1)
				if (issecret(name) && v != "" && !isexp(v)) t = substr(t, 1, index(t, "=")) "<redacted>"
			}
			else if (t ~ /^--?[A-Za-z][A-Za-z0-9_-]*$/) { name = t; sub(/^--?/, "", name); if (length(name) > 1 && issecret(name)) mask = 1 }
			else if (isbin && tolower(t) ~ /^(password|passwd|pass|secret|psk|key|pwd|token)$/) mask = 1
			out = out pre t
		}
		return out s
	}
	/-----BEGIN [A-Z ]*PRIVATE KEY-----/ { print; inkey = 1; next }
	inkey && /-----END [A-Z ]*PRIVATE KEY-----/ { print "<redacted>"; print; inkey = 0; next }
	inkey { next }
	{
		line = $0
		# uci show:  pkg.section.option=value
		if (match(line, /^[^=. ]+\.[^=. ]+\.[^= ]+=/)) {
			opt = substr(line, 1, RLENGTH - 1); sub(/^.*\./, "", opt)
			if (issecret(opt)) print substr(line, 1, RLENGTH) "'"'"'<redacted>'"'"'"
			else print line
			next
		}
		# config file:  option name value / list name value
		if (match(line, /^[ \t]*(option|list)[ \t]+[^ \t]+[ \t]+/)) {
			n = split(line, f, /[ \t]+/); opt = (f[1] == "") ? f[3] : f[2]
			if (issecret(opt)) print substr(line, 1, RLENGTH) "'"'"'<redacted>'"'"'"
			else print line
			next
		}
		# shadow:  name:hash:lastchg:min:max:warn:inactive:expire:reserved, the hash
		# maybe behind ! or * (locked); a bare ! or * holds no hash
		if (split(line, f, ":") == 9 && f[1] ~ /^[A-Za-z0-9_.][A-Za-z0-9_.-]*[$]?$/ && f[3] ~ /^[0-9]*$/ && f[4] ~ /^[0-9]*$/) {
			h = f[2]; pre = ""
			if (match(h, /^[!*]+/)) { pre = substr(h, 1, RLENGTH); h = substr(h, RLENGTH + 1) }
			d = ""
			if (h ~ /^[$][^$]+[$]/) { d = h; sub(/^[$]/, "", d); sub(/[$].*/, "", d); d = "$" d }
			else if (h ~ /^[.\/0-9A-Za-z]+$/ && length(h) == 13) d = "DES"
			else if (h != "" && h != "x") d = "unknown format"
			if (d != "") {
				print f[1] ":" pre "<redacted hash, " d ">" substr(line, length(f[1]) + length(f[2]) + 2); next
			}
		}
		# wireguard:  PrivateKey = ... / PresharedKey = ...
		if (tolower(line) ~ /^[ \t]*(privatekey|presharedkey)[ \t]*=/) { sub(/=.*/, "= <redacted>", line); print line; next }
		# hostapd r0kh= / r1kh=: MAC, id, key; the last field is the key
		if (line ~ /^[ \t]*r[01]kh=[^ \t]*[ \t]+[^ \t]/) { sub(/[^ \t]+[ \t]*$/, "<redacted>", line); print line; next }
		# hostapd per-station PSK file:  [keyid=..] [vlanid=..] [wps=1] MAC PSK
		if (match(line, /^[ \t]*([A-Za-z_]+=[^ \t]*[ \t]+)*[0-9A-Fa-f][0-9A-Fa-f]:[0-9A-Fa-f][0-9A-Fa-f]:[0-9A-Fa-f][0-9A-Fa-f]:[0-9A-Fa-f][0-9A-Fa-f]:[0-9A-Fa-f][0-9A-Fa-f]:[0-9A-Fa-f][0-9A-Fa-f][ \t]+/) &&
			substr(line, RLENGTH + 1) ~ /^[^ \t]+[ \t]*$/) { print substr(line, 1, RLENGTH) "<redacted>"; next }
		# name=value (hostapd, wpa_supplicant, shell, environment)
		if (match(line, /^[ \t]*(export[ \t]+)?[A-Za-z_][A-Za-z0-9_]*=/)) {
			opt = substr(line, 1, RLENGTH - 1); sub(/^[ \t]*(export[ \t]+)?/, "", opt); v = substr(line, RLENGTH + 1)
			if (issecret(opt) && v != "" && !isexp(v)) { print substr(line, 1, RLENGTH) "<redacted>"; next }
		}
		# pretty-printed JSON (ubus call ...):  "key": "value"
		if (match(line, /^[ \t]*"[A-Za-z0-9_]+"[ \t]*:[ \t]*"/)) {
			opt = substr(line, 1, RLENGTH); sub(/^[ \t]*"/, "", opt); sub(/".*/, "", opt)
			if (issecret(opt)) { print substr(line, 1, RLENGTH - 1) "\"<redacted>\"" (line ~ /,[ \t]*$/ ? "," : ""); next }
		}
		# command lines
		if (line ~ /(^|[ \t])--?[A-Za-z]/ || line ~ /(^|[ \t])(\/usr)?\/s?bin\//) line = cmdl(line)
		print line
	}'
}

# ---------------------------------------------------------------- processes
# _mcp_pids ROOT [TAG]: ROOT and all its descendants (from /proc/*/stat) and, with TAG,
# every process whose environment holds MCP_CALL_TAG=TAG; one line, space separated.
# Zombies count as gone. Prints nothing when ROOT (other than 0) is gone: then the
# work it stood for is over. Never lists this shell, pid 1 or pid 0.
_mcp_pids() {
	{
		[ -n "${2-}" ] && grep -lsF "MCP_CALL_TAG=$2" /proc/[0-9]*/environ 2>/dev/null | sed 's|^/proc/||; s|/.*||; s|^|T |'
		cat /proc/[0-9]*/stat 2>/dev/null
	} | awk -v root="$1" -v self="$$" '
	$1 == "T" { tag[$2] = 1; next }
	{
		n = split($0, a, ")"); split(a[n], f, " ")
		if (f[1] == "Z") next
		kids[f[2]] = kids[f[2]] " " $1; alive[$1] = 1
	}
	END {
		out = ""; nq = 0; skip[self] = 1; skip[1] = 1; skip[0] = 1
		if (root != 0 && (!(root in alive) || (root in skip))) exit
		if (root != 0) { q[++nq] = root; seen[root] = 1 }
		for (h = 1; h <= nq; h++) {
			p = q[h]; out = out " " p
			m = split(kids[p], c, " ")
			for (i = 1; i <= m; i++) if (!(c[i] in seen) && !(c[i] in skip)) { seen[c[i]] = 1; q[++nq] = c[i] }
		}
		for (t in tag) if ((t in alive) && !(t in seen) && !(t in skip)) out = out " " t
		print substr(out, 2)
	}'
}

# _mcp_kill_tree ROOT [TAG]: SIGKILL for ROOT, its descendants and (with TAG) tagged
# processes; ROOT 0 means tagged processes only. They are stopped first, until the set
# stops growing, so nothing can fork away or be re-parented while the list is built.
# Exit status 0 when something was killed, 1 when there was nothing (ROOT gone).
_mcp_kill_tree() {
	[ -n "$1" ] || return 1
	_kt_all='' _kt_prev='' _kt_i=0
	while [ "$_kt_i" -lt 20 ]; do
		_kt_now=$(_mcp_pids "$1" "${2-}")
		[ -n "$_kt_now" ] || break
		# shellcheck disable=SC2086
		kill -STOP $_kt_now 2>/dev/null
		_kt_all="$_kt_all $_kt_now"
		[ "$_kt_now" = "$_kt_prev" ] && break
		_kt_prev=$_kt_now _kt_i=$((_kt_i + 1))
	done
	[ -n "$_kt_all" ] || return 1
	# shellcheck disable=SC2086
	{ kill -KILL $_kt_all; kill -CONT $_kt_all; } 2>/dev/null
	return 0
}

# Alarms. No signal trap decides anything: a lock directory does.
# _mcp_alarm ID SECS CMD [ARG...]: in the background, sleeps SECS seconds, then takes the
#   lock $MCP_TMP/alarm.ID (mkdir) and runs CMD; when CMD succeeds (for _mcp_kill_tree:
#   something was killed) it leaves the marker "fired" in the lock directory. The
#   alarm's pid is in _mcp_alarm_pid. ID: the pid of the process the alarm guards (unique
#   while that process is not reaped).
# _mcp_alarm_end ID PID: ends the alarm. When the caller gets the lock first, the alarm
#   can no longer fire: it is stopped, killed with its sleep and reaped, exit status 1.
#   Otherwise the alarm is firing or has fired: it is waited for, and the exit status
#   is 0 when it left the "fired" marker.
_mcp_alarm() {
	_al_d=$MCP_TMP/alarm.$1 _al_s=$2
	shift 2
	rm -rf "$_al_d"
	(
		sleep "$_al_s"
		mkdir "$_al_d" 2>/dev/null || exit 0
		"$@" && : >"$_al_d/fired"
		exit 0
	) </dev/null >/dev/null 2>&1 3>&- &
	_mcp_alarm_pid=$!
}

_mcp_alarm_end() {
	_ae_d=$MCP_TMP/alarm.$1
	if mkdir "$_ae_d" 2>/dev/null; then
		# frozen, the alarm cannot fork or exit, so one look finds its sleep
		kill -STOP "$2" 2>/dev/null
		_ae_p=$(_mcp_pids "$2")
		# shellcheck disable=SC2086
		[ -n "$_ae_p" ] && { kill -KILL $_ae_p; kill -CONT $_ae_p; } 2>/dev/null
		wait "$2" 2>/dev/null
		rm -rf "$_ae_d"
		return 1
	fi
	wait "$2" 2>/dev/null
	if [ -e "$_ae_d/fired" ]; then _ae_rc=0; else _ae_rc=1; fi
	rm -rf "$_ae_d"
	return "$_ae_rc"
}

# Runs CMD with a time limit. Exit status 124 when the limit hit; then CMD and every
# process it started are killed. Otherwise CMD's exit status, also when the limit hit
# just after CMD ended. CMD's stdout and stderr stay where they were; its stdin is
# /dev/null. _rt_fired is 1 after a timeout, else 0 (exec uses it to tell a timeout
# from an exit status 124).
run_timeout() {
	_rt_s=$1; shift
	case $_rt_s in '' | *[!0-9]*) _rt_s=1 ;; esac
	"$@" </dev/null &
	_rt_p=$!
	_mcp_alarm "$_rt_p" "$_rt_s" _mcp_kill_tree "$_rt_p"
	_rt_w=$_mcp_alarm_pid
	wait "$_rt_p" 2>/dev/null
	_rt_rc=$?
	if _mcp_alarm_end "$_rt_p" "$_rt_w"; then _rt_fired=1; return 124; fi
	_rt_fired=0
	return "$_rt_rc"
}

# ---------------------------------------------------------------- tool registry
MCP_TOOLS=
_mcp_ntools=0
mcp_register() {
	_mcp_ntools=$((_mcp_ntools + 1))
	cat >"$MCP_TMP/tools/$(printf '%03d' "$_mcp_ntools")-$1.json"
	MCP_TOOLS="$MCP_TOOLS $1"
}

# ---------------------------------------------------------------- protocol
_mcp_send() { printf '%s\n' "$1" >&3; }

_mcp_error() { # ID CODE MESSAGE
	_mcp_send "{\"jsonrpc\":\"2.0\",\"id\":$1,\"error\":{\"code\":$2,\"message\":$(json_quote "$3")}}"
}

_mcp_initialize() { # ID
	_want=$(_mcp_jf -e @.params.protocolVersion)
	_proto=${MCP_PROTOCOLS%% *}
	for _p in $MCP_PROTOCOLS; do [ "$_p" = "$_want" ] && _proto=$_want; done
	_instr="Read-only tools for inspecting an OpenWrt router; start with system_info and audit. Tools run with the firmware image's busybox first in PATH when /rom has one ($MCP_TRUSTED). Output over $MCP_MAX_OUTPUT bytes is cut and a call is stopped after $MCP_CALL_TIMEOUT s. Secrets are masked unless the launcher was started with --no-redact (now: MCP_REDACT=$MCP_REDACT). The exec tool runs any shell command as root: prefer the dedicated tools."
	_mcp_send "{\"jsonrpc\":\"2.0\",\"id\":$1,\"result\":{\"protocolVersion\":\"$_proto\",\"capabilities\":{\"tools\":{\"listChanged\":false}},\"serverInfo\":{\"name\":\"$MCP_SERVER_NAME\",\"title\":\"OpenWrt\",\"version\":\"$MCP_SERVER_VERSION\"},\"instructions\":$(json_quote "$_instr")}}"
}

_mcp_tools_list() { # ID
	{
		printf '{"jsonrpc":"2.0","id":%s,"result":{"tools":[' "$1"
		_first=1
		for _f in "$MCP_TMP"/tools/*.json; do
			[ -f "$_f" ] || continue
			[ "$_first" = 1 ] || printf ','
			_first=0
			tr -d '\n' <"$_f"
		done
		printf ']}}\n'
	} >&3
}

# _mcp_result ID ISERROR CUT NOTE: the tool result, text from $MCP_TMP/out. The text
# is cut where its escaped form reaches MCP_MAX_OUTPUT bytes (control characters take 6,
# invalid bytes 3), so the result line stays near the limit whatever the tool printed.
_mcp_result() {
	_rs_cut="[output cut at $MCP_MAX_OUTPUT bytes of text (control characters and invalid bytes take more room escaped); narrow the request or page with offset/limit where the tool has them]"
	case $4 in "[output cut"*) _rs_cut=$4 ;; esac
	{
		printf '{"jsonrpc":"2.0","id":%s,"result":{"content":[{"type":"text","text":' "$1"
		head -c "$MCP_MAX_OUTPUT" "$MCP_TMP/out" 2>/dev/null |
			_mcp_json_text "$3" "$4" "(no output)" "$MCP_MAX_OUTPUT" "$_rs_cut"
		printf '}],"isError":%s}}\n' "$2"
	} >&3
}

_mcp_tools_call() { # ID
	case $(_mcp_jf -t @.params.name) in
	string) _name=$(_mcp_jf -e @.params.name) ;;
	*) _mcp_error "$1" -32602 "Invalid params: tools/call needs a string \"name\""; return ;;
	esac
	case $_name in '' | *[!a-z0-9_]*) _mcp_error "$1" -32602 "Unknown tool: $_name"; return ;; esac
	case " $MCP_TOOLS " in *" $_name "*) ;; *) _mcp_error "$1" -32602 "Unknown tool: $_name"; return ;; esac
	_out=$MCP_TMP/out
	if ! _mcp_check_args "$_name" >"$_out" 2>&1; then
		_mcp_result "$1" true 0 ""
		rm -f "$_out"
		return
	fi
	mcp_log "call $_name"

	# the exec tool brings its own timeout; the call limit is at least that plus 5 s
	_ct_to=$MCP_CALL_TIMEOUT
	if [ "$_name" = exec ]; then
		_ct_x=$(_mcp_jf -e @.params.arguments.timeout)
		case $_ct_x in '' | *[!0-9]* | ?????*) ;; *) [ $((_ct_x + 5)) -gt "$_ct_to" ] && _ct_to=$((_ct_x + 5)) ;; esac
	fi

	_mcp_ncall=$((${_mcp_ncall:-0} + 1))
	_mcp_tag="$$.$_mcp_ncall."
	_ct_fifo=$MCP_TMP/pipe
	rm -f "$_ct_fifo" "$_out" "$MCP_TMP/cut"
	mkfifo "$_ct_fifo" 2>/dev/null || mknod "$_ct_fifo" p 2>/dev/null
	if [ ! -p "$_ct_fifo" ]; then
		echo "error: cannot create a FIFO in $MCP_TMP (is /tmp full?)" >"$_out"
		_mcp_result "$1" true 0 ""
		rm -f "$_out" "$_ct_fifo"
		_mcp_tag=''
		return
	fi
	# every call starts in an empty work directory
	rm -rf "$MCP_TMP/work"
	mkdir "$MCP_TMP/work"
	# producer: the handler, writing into the FIFO
	(
		MCP_CALL_TAG=$_mcp_tag
		export MCP_CALL_TAG
		cd "$MCP_TMP/work" || exit 1
		"tool_$_name"
	) </dev/null >"$_ct_fifo" 2>&1 3>&- &
	_mcp_P=$!
	# reader: keeps at least MCP_MAX_OUTPUT+1 bytes (rounded up to 512-byte blocks by the
	# file size limit), then stops the producer. cat writes what it reads at once, so
	# nothing read is lost when the reader is killed (head -c buffers).
	(
		ulimit -f $(((MCP_MAX_OUTPUT + 512) / 512))
		cat >"$_out"
		if [ "$(wc -c <"$_out")" -gt "$MCP_MAX_OUTPUT" ]; then
			: >"$MCP_TMP/cut"
			_mcp_kill_tree "$_mcp_P" "$_mcp_tag"
		fi
	) <"$_ct_fifo" 2>/dev/null 3>&- &
	_mcp_R=$!
	_mcp_alarm "$_mcp_P" "$_ct_to" _mcp_kill_tree "$_mcp_P" "$_mcp_tag"
	_mcp_W=$_mcp_alarm_pid

	wait "$_mcp_P" 2>/dev/null
	_rc=$?
	_ct_fired=0
	_mcp_alarm_end "$_mcp_P" "$_mcp_W" && _ct_fired=1
	# a background process of the tool may still hold the FIFO open: give the reader
	# 2 s to drain what is left, then stop it
	_ct_held=0
	if kill -0 "$_mcp_R" 2>/dev/null; then
		_mcp_alarm "$_mcp_R" 2 _mcp_kill_tree "$_mcp_R"
		_mcp_G=$_mcp_alarm_pid
		wait "$_mcp_R" 2>/dev/null
		_mcp_alarm_end "$_mcp_R" "$_mcp_G" && _ct_held=1
	else
		wait "$_mcp_R" 2>/dev/null
	fi
	_mcp_P='' _mcp_R='' _mcp_W='' _mcp_G=''
	rm -f "$_ct_fifo"

	_err=false _cut=0 _note=
	[ "$_rc" = 0 ] || _err=true
	[ -e "$MCP_TMP/cut" ] && _cut=1
	if [ "$_ct_fired" = 1 ]; then
		_err=true
		_note="[timeout: the call was stopped after $_ct_to s and every process it started was killed; narrow the request, or raise the limit with the launcher option --call-timeout]"
	elif [ "$_cut" = 1 ]; then
		_err=false
		_note="[output cut at $MCP_MAX_OUTPUT bytes and the tool was stopped; narrow the request or page with offset/limit where the tool has them]"
	elif [ "$_ct_held" = 1 ]; then
		_note="[a background process started by this call still holds its output open 2 s after the call ended; it keeps running, and what it prints from now on is not shown (redirect it: cmd >/dev/null 2>&1 &)]"
	fi
	_mcp_result "$1" "$_err" "$_cut" "$_note"
	_mcp_tag=
	rm -f "$_out" "$MCP_TMP/cut"
}

_mcp_handle() {
	unset _q_t _q_j _q_m _q_mt _q_it _q_i _q_pt
	eval "$(jsonfilter -i "$MCP_REQ" -t '_q_t=@' -e '_q_j=@.jsonrpc' -t '_q_mt=@.method' -e '_q_m=@.method' -t '_q_it=@.id' -e '_q_i=@.id' -t '_q_pt=@.params' 2>/dev/null)"
	_t=${_q_t-} _j=${_q_j-} _mt=${_q_mt-} _method=${_q_m-} _it=${_q_it-} _i=${_q_i-} _pt=${_q_pt-}
	unset _q_t _q_j _q_m _q_mt _q_it _q_i _q_pt
	case $_t in
	'') _mcp_error null -32700 "Parse error: the line is not valid JSON"; return ;;
	object) ;;
	array) _mcp_error null -32600 "Invalid Request: batches are not supported"; return ;;
	*) _mcp_error null -32600 "Invalid Request: expected a JSON object"; return ;;
	esac
	# numeric ids: integers of up to 15 digits only, echoed as jsonfilter read them;
	# jsonfilter reformats fractions and exponents (1e999 -> inf) and clamps big
	# integers to int64, so such an id could not be echoed as sent
	case $_it in
	int)
		case ${_i#-} in
		'' | *[!0-9]* | ????????????????*) _mcp_error null -32600 "Invalid Request: a numeric id must be an integer of at most 15 digits"; return ;;
		esac
		_id=$_i ;;
	string) _id=$(json_quote "$_i") ;;
	'') _id= ;;
	double) _mcp_error null -32600 "Invalid Request: a numeric id must be an integer of at most 15 digits"; return ;;
	*) _mcp_error null -32600 "Invalid Request: id must be a string or an integer"; return ;;
	esac
	mcp_log "<- ${_method:-?} id=${_id:-none}"
	if [ -z "$_id" ]; then return; fi # a notification never gets a reply
	if [ "$_j" != 2.0 ]; then _mcp_error "$_id" -32600 "Invalid Request: jsonrpc must be \"2.0\""; return; fi
	case $_mt in
	string) ;;
	'') _mcp_error "$_id" -32600 "Invalid Request: no method"; return ;;
	*) _mcp_error "$_id" -32600 "Invalid Request: method must be a string"; return ;;
	esac
	case $_pt in
	'' | object) ;;
	*) _mcp_error "$_id" -32602 "Invalid params: params must be an object"; return ;;
	esac
	case $_method in
	initialize) _mcp_initialize "$_id" ;;
	ping) _mcp_send "{\"jsonrpc\":\"2.0\",\"id\":$_id,\"result\":{}}" ;;
	tools/list) _mcp_tools_list "$_id" ;;
	tools/call) _mcp_tools_call "$_id" ;;
	*) _mcp_error "$_id" -32601 "Method not found: $_method" ;;
	esac
}

# Reads one request per line until EOF, then exits 0. Protocol messages go to fd 3
# (the original stdout); stdout itself is pointed at stderr so nothing else reaches
# the client.
mcp_main() {
	exec 3>&1 1>&2
	_mcp_cr=$(printf '\r')
	while IFS= read -r _line || [ -n "$_line" ]; do
		_line=${_line%"$_mcp_cr"}
		case $_line in *[!\ \	]*) ;; *) _line=; continue ;; esac
		printf '%s' "$_line" >"$MCP_REQ"
		_line=
		_mcp_handle
	done
	exit 0
}

# ---------------------------------------------------------------- server_info
mcp_register server_info <<'EOF'
{"name":"server_info","title":"Server info","description":"Version of this MCP server, the protocol, whether the firmware image's busybox is used (trusted tools), whether secrets are masked, the output and time limits and the list of tools. Cheap; call it first if unsure what the server can do.","inputSchema":{"type":"object","properties":{},"additionalProperties":false},"annotations":{"readOnlyHint":true,"openWorldHint":false}}
EOF
tool_server_info() {
	printf 'server        %s %s\n' "$MCP_SERVER_NAME" "$MCP_SERVER_VERSION"
	printf 'protocols     %s\n' "$MCP_PROTOCOLS"
	printf 'trusted tools %s\n' "$MCP_TRUSTED"
	printf 'redaction     %s\n' "$([ "$MCP_REDACT" = 1 ] && echo on || echo off)"
	printf 'max output    %s bytes per result (more is cut while the tool runs)\n' "$MCP_MAX_OUTPUT"
	printf 'call timeout  %s s per call (exec: its own timeout + 5 s when that is longer)\n' "$MCP_CALL_TIMEOUT"
	printf 'text          UTF-8; invalid bytes shown as U+FFFD, NUL bytes dropped\n'
	printf 'firmware root %s\n' "$MCP_ROM"
	printf 'overlay upper %s\n' "$MCP_UPPER"
	printf 'temp dir      %s\n' "$MCP_TMP"
	printf 'tools        %s\n' "$MCP_TOOLS"
}
