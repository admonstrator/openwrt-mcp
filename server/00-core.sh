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
#                                    exit without harming the server.
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
#                                    to read to the end (no FIFO, no link into /proc,
#                                    /sys or /dev)
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
#
# ---------------------------------------------------------------- how a call runs
# The arguments are checked against the tool's inputSchema first (unknown names, JSON
# types, required ones); a mismatch is a tool result with isError, not a protocol error.
# The handler then runs in a background subshell that writes into a FIFO. A reader
# copies at most MCP_MAX_OUTPUT+1 bytes into $MCP_TMP/out and, when that limit is hit,
# stops the producer: a tool that prints 50 MB never fills /tmp. A watchdog kills the
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
	for _c in $_mcp_P $_mcp_R $_mcp_W $_mcp_G; do _mcp_kill_tree "$_c"; done
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
# with the busybox of the firmware image first in PATH when the image has one.
# MCP_PATH_ORIG keeps the router's own PATH (the exec tool offers it).
# shellcheck disable=SC2034  # used by server/90-exec.sh
MCP_PATH_ORIG=$PATH
MCP_TRUSTED=no
if [ -x "$MCP_ROM/bin/busybox" ] && "$MCP_ROM/bin/busybox" true 2>/dev/null; then
	mkdir "$MCP_TMP/bin"
	for _a in $("$MCP_ROM/bin/busybox" --list 2>/dev/null); do
		case $_a in */* | . | ..) continue ;; esac
		ln -s "$MCP_ROM/bin/busybox" "$MCP_TMP/bin/$_a" 2>/dev/null
	done
	PATH="$MCP_TMP/bin:$PATH"
	MCP_TRUSTED="yes ($MCP_ROM/bin/busybox)"
fi
export PATH

# ---------------------------------------------------------------- JSON output
# _mcp_json_text CUT NOTE EMPTY: stdin bytes -> one JSON string literal.
# Valid UTF-8 passes through; every invalid byte sequence becomes U+FFFD (one per
# maximal invalid subpart); NUL bytes are dropped; other control characters and DEL
# are escaped. One trailing newline is dropped. CUT=1: the input was cut at a byte
# limit, so an incomplete sequence at the very end is dropped instead of replaced.
# NOTE: plain ASCII (no quote, no backslash) appended on a line of its own. EMPTY: the
# text used when the input has nothing but newlines and NULs.
# awk gets numbers from hexdump, not bytes: busybox awk strings end at NUL, its substr
# is O(length) (quadratic on long binary lines), and its gsub replacement escapes
# differ between 1.33 and 1.37.
_mcp_json_text() {
	if ! have hexdump; then
		# fallback without hexdump: every byte outside ASCII becomes "?"
		tr -d '\000' | tr '\200-\377' '?' | awk -v note="$2" -v empty="$3" '
		BEGIN {
			for (i = 1; i < 32; i++) esc[sprintf("%c", i)] = sprintf("\\u%04x", i)
			esc[sprintf("%c", 127)] = "\\u007f"
			esc["\t"] = "\\t"; esc["\r"] = "\\r"
			esc["\\"] = "\\\\"; esc["\""] = "\\\""
			printf "\""
		}
		{
			if (NR > 1) printf "\\n"
			s = $0; o = ""
			if (s != "") any = 1
			while (match(s, /[\\"\001-\037\177]/)) {
				o = o substr(s, 1, RSTART - 1) esc[substr(s, RSTART, 1)]
				s = substr(s, RSTART + 1)
			}
			printf "%s%s", o, s
		}
		END {
			if (!any && empty != "") printf "%s", empty
			if (note != "") printf "\\n%s", note
			printf "\""
		}'
		return
	fi
	hexdump -v -e '32/1 "%u " "\n"' | awk -v cut="$1" -v note="$2" -v empty="$3" '
	BEGIN {
		for (i = 1; i < 256; i++) chr[i] = sprintf("%c", i)
		for (i = 1; i < 32; i++) esc[i] = sprintf("\\u%04x", i)
		for (i = 32; i < 127; i++) esc[i] = chr[i]
		esc[9] = "\\t"; esc[13] = "\\r"; esc[127] = "\\u007f"
		esc[34] = "\\\""; esc[92] = "\\\\"
		bad = chr[239] chr[191] chr[189]
		need = 0; nl = 0; any = 0; seq = ""
		printf "\""
	}
	{
		o = ""
		for (i = 1; i <= NF; i++) {
			b = $i + 0
			if (need) {
				if (b >= lo && b <= hi) {
					seq = seq chr[b]; lo = 128; hi = 191
					if (--need == 0) { o = o seq; seq = "" }
					continue
				}
				o = o bad; need = 0; seq = ""
			}
			if (b == 10) { nl++; continue }
			if (b == 0) continue
			for (; nl > 0; nl--) o = o "\\n"
			any = 1
			if (b < 128) { o = o esc[b]; continue }
			if (b >= 194 && b <= 223) { need = 1; lo = 128; hi = 191 }
			else if (b >= 224 && b <= 239) { need = 2; lo = (b == 224) ? 160 : 128; hi = (b == 237) ? 159 : 191 }
			else if (b >= 240 && b <= 244) { need = 3; lo = (b == 240) ? 144 : 128; hi = (b == 244) ? 143 : 191 }
			else { o = o bad; continue }
			seq = chr[b]
		}
		printf "%s", o
	}
	END {
		if (need && !cut) printf "%s", bad
		if (any) for (; nl > 1; nl--) printf "\\n"
		else if (empty != "") printf "%s", empty
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
	case $1 in /proc/kmsg | */trace_pipe | */trace_pipe_raw) return 1 ;; esac
	if [ -L "$1" ]; then
		_t=$(readlink -f "$1" 2>/dev/null) || _t=$(readlink "$1" 2>/dev/null)
		case $_t in '' | /proc/* | /sys/* | /dev/*) return 1 ;; esac
	fi
	cat "$1" 2>/dev/null
}

rom_path() { printf '%s/%s' "${MCP_ROM%/}" "${1#/}"; }

in_rom() { [ -e "$(rom_path "$1")" ] || [ -L "$(rom_path "$1")" ]; }

# Masks secrets in uci show output, config files, shadow lines, key blocks, hostapd and
# wpa_supplicant files and pretty-printed JSON (ubus call output).
redact() {
	if [ "$MCP_REDACT" != 1 ]; then cat; return; fi
	awk '
	BEGIN { secret = "(key|password|passwd|pass|psk|secret|private_key|privatekey|preshared_key|presharedkey|token|auth_secret|sae_password|wpa_passphrase|passphrase|pin|community)" }
	/-----BEGIN [A-Z ]*PRIVATE KEY-----/ { print; inkey = 1; next }
	inkey && /-----END [A-Z ]*PRIVATE KEY-----/ { print "<redacted>"; print; inkey = 0; next }
	inkey { next }
	{
		line = $0
		# uci show:  pkg.section.option=value
		if (match(line, /^[^=. ]+\.[^=. ]+\.[^= ]+=/)) {
			opt = substr(line, 1, RLENGTH - 1); sub(/^.*\./, "", opt)
			if (tolower(opt) ~ ("^" secret "$|_" secret "$")) { print substr(line, 1, RLENGTH) "'"'"'<redacted>'"'"'"; next }
		}
		# config file:  option name value / list name value
		if (match(line, /^[ \t]*(option|list)[ \t]+[^ \t]+[ \t]+/)) {
			n = split(line, f, /[ \t]+/); opt = (f[1] == "") ? f[3] : f[2]
			gsub(/["'"'"']/, "", opt)
			if (tolower(opt) ~ ("^" secret "$|_" secret "$")) { print substr(line, 1, RLENGTH) "'"'"'<redacted>'"'"'"; next }
		}
		# shadow:  name:hash:...
		if (match(line, /^[^:]+:\$[^:]+:/)) {
			split(line, f, ":"); rest = substr(line, length(f[1]) + length(f[2]) + 2)
			alg = f[2]; sub(/^\$/, "", alg); sub(/\$.*/, "", alg)
			print f[1] ":<redacted hash, $" alg ">" rest; next
		}
		# wireguard / generic:  PrivateKey = ...
		if (tolower(line) ~ /^[ \t]*(privatekey|presharedkey)[ \t]*=/) { sub(/=.*/, "= <redacted>", line); print line; next }
		# hostapd / wpa_supplicant:  wpa_passphrase=..., psk="...", sae_password=...
		if (match(line, /^[ \t]*(wpa_passphrase|wpa_psk|sae_password|psk|password|private_key_passwd)=/)) { print substr(line, 1, RLENGTH) "<redacted>"; next }
		# pretty-printed JSON (ubus call ...):  "key": "value"
		if (match(line, /^[ \t]*"[A-Za-z0-9_]+"[ \t]*:[ \t]*"/)) {
			opt = substr(line, 1, RLENGTH); sub(/^[ \t]*"/, "", opt); sub(/".*/, "", opt)
			if (tolower(opt) ~ ("^" secret "$|_" secret "$")) {
				print substr(line, 1, RLENGTH - 1) "\"<redacted>\"" (line ~ /,[ \t]*$/ ? "," : ""); next
			}
		}
		print line
	}'
}

# ---------------------------------------------------------------- processes
# _mcp_pids ROOT [TAG]: ROOT and all its descendants (from /proc/*/stat) and, with TAG,
# every process whose environment holds MCP_CALL_TAG=TAG; one line, space separated.
# Never lists this shell, pid 1 or pid 0.
_mcp_pids() {
	{
		[ -n "${2-}" ] && grep -lsF "MCP_CALL_TAG=$2" /proc/[0-9]*/environ 2>/dev/null | sed 's|^/proc/||; s|/.*||; s|^|T |'
		cat /proc/[0-9]*/stat 2>/dev/null
	} | awk -v root="$1" -v self="$$" '
	$1 == "T" { tag[$2] = 1; next }
	{ n = split($0, a, ")"); split(a[n], f, " "); kids[f[2]] = kids[f[2]] " " $1; alive[$1] = 1 }
	END {
		out = ""; nq = 0; skip[self] = 1; skip[1] = 1; skip[0] = 1
		if ((root in alive) && !(root in skip)) { q[++nq] = root; seen[root] = 1 }
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
# processes. They are stopped first, until the set stops growing, so nothing can fork
# away or be re-parented while the list is built.
_mcp_kill_tree() {
	[ -n "$1" ] || return 0
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
	# shellcheck disable=SC2086
	[ -n "$_kt_all" ] && { kill -KILL $_kt_all; kill -CONT $_kt_all; } 2>/dev/null
	return 0
}

# _mcp_alarm SECS CMD [ARG...]: runs CMD in the background after SECS seconds; the
# alarm's pid is in _mcp_alarm_pid. "kill PID" before it fires cancels it (its sleep
# goes too); once it fires it ignores TERM until CMD is done. "wait PID" returns 9 when
# it fired.
_mcp_alarm() {
	_al_s=$1; shift
	(
		_al_z=
		trap 'kill "$_al_z" 2>/dev/null; exit 0' TERM
		sleep "$_al_s" &
		_al_z=$!
		wait "$_al_z" || exit 0
		trap '' TERM
		"$@"
		exit 9
	) </dev/null >/dev/null 2>&1 3>&- &
	_mcp_alarm_pid=$!
}

# Runs CMD with a time limit. Exit status 124 when the limit hit; then CMD and every
# process it started are killed. Otherwise CMD's exit status. CMD's stdout and stderr
# stay where they were; its stdin is /dev/null.
run_timeout() {
	_rt_s=$1; shift
	case $_rt_s in '' | *[!0-9]*) _rt_s=1 ;; esac
	"$@" </dev/null &
	_rt_p=$!
	_mcp_alarm "$_rt_s" _mcp_kill_tree "$_rt_p"
	_rt_w=$_mcp_alarm_pid
	wait "$_rt_p" 2>/dev/null
	_rt_rc=$?
	kill "$_rt_w" 2>/dev/null
	wait "$_rt_w"
	# _rt_fired tells a caller that knows it (exec) a timeout from an exit status 124
	[ $? = 9 ] && { _rt_fired=1; return 124; }
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

# _mcp_result ID ISERROR CUT NOTE: the tool result, text from $MCP_TMP/out
_mcp_result() {
	{
		printf '{"jsonrpc":"2.0","id":%s,"result":{"content":[{"type":"text","text":' "$1"
		head -c "$MCP_MAX_OUTPUT" "$MCP_TMP/out" 2>/dev/null | _mcp_json_text "$3" "$4" "(no output)"
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
	mkfifo "$_ct_fifo" 2>/dev/null || mknod "$_ct_fifo" p
	# producer: the handler, writing into the FIFO
	(
		MCP_CALL_TAG=$_mcp_tag
		export MCP_CALL_TAG
		cd "$MCP_TMP/work" || exit 1
		"tool_$_name"
	) </dev/null >"$_ct_fifo" 2>&1 3>&- &
	_mcp_P=$!
	# reader: keeps at most MCP_MAX_OUTPUT+1 bytes, then stops the producer
	(
		head -c $((MCP_MAX_OUTPUT + 1)) >"$_out"
		if [ "$(wc -c <"$_out")" -gt "$MCP_MAX_OUTPUT" ]; then
			: >"$MCP_TMP/cut"
			_mcp_kill_tree "$_mcp_P" "$_mcp_tag"
		fi
	) <"$_ct_fifo" 3>&- &
	_mcp_R=$!
	_mcp_alarm "$_ct_to" _mcp_kill_tree "$_mcp_P" "$_mcp_tag"
	_mcp_W=$_mcp_alarm_pid

	wait "$_mcp_P" 2>/dev/null
	_rc=$?
	kill "$_mcp_W" 2>/dev/null
	wait "$_mcp_W"
	_ct_fired=$?
	# a background process of the tool may still hold the FIFO open: give the reader
	# 2 s to drain what is left, then stop it
	_ct_held=0
	if kill -0 "$_mcp_R" 2>/dev/null; then
		_mcp_alarm 2 _mcp_kill_tree "$_mcp_R"
		_mcp_G=$_mcp_alarm_pid
		wait "$_mcp_R" 2>/dev/null
		kill "$_mcp_G" 2>/dev/null
		wait "$_mcp_G"
		[ $? = 9 ] && _ct_held=1
	else
		wait "$_mcp_R" 2>/dev/null
	fi
	_mcp_P='' _mcp_R='' _mcp_W='' _mcp_G=''
	rm -f "$_ct_fifo"

	_err=false _cut=0 _note=
	[ "$_rc" = 0 ] || _err=true
	[ -e "$MCP_TMP/cut" ] && _cut=1
	if [ "$_ct_fired" = 9 ]; then
		_err=true
		_note="[timeout: the call was stopped after $_ct_to s and every process it started was killed; narrow the request, or raise the limit with the launcher option --call-timeout]"
	elif [ "$_cut" = 1 ]; then
		_err=false
		_note="[output cut at $MCP_MAX_OUTPUT bytes and the tool was stopped; narrow the request or page with offset/limit where the tool has them]"
	elif [ "$_ct_held" = 1 ]; then
		_note="[a background process started by this call still holds its output open; what it prints after the call ended is not shown (redirect it: cmd >/dev/null 2>&1 &)]"
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
	case $_it in
	int | double) _id=$_i ;;
	string) _id=$(json_quote "$_i") ;;
	'') _id= ;;
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
