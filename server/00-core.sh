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

unset LD_PRELOAD LD_LIBRARY_PATH
umask 077
MCP_TMP=$(mktemp -d /tmp/openwrt-mcp.XXXXXX) || { echo "openwrt-mcp: no temp dir" >&2; exit 1; }
MCP_REQ=$MCP_TMP/request.json
mkdir "$MCP_TMP/tools" "$MCP_TMP/work"
trap 'rm -rf "$MCP_TMP"' EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

[ "$MCP_SELF_DELETE" = 1 ] && case $0 in /tmp/*.sh) rm -f "$0" ;; esac

mcp_log() { [ "$MCP_DEBUG" = 1 ] && printf 'openwrt-mcp: %s\n' "$*" >&2; return 0; }

# ---------------------------------------------------------------- trusted tools
# A compromised router may have replaced applets in the overlay. Every tool call runs
# with the busybox of the firmware image first in PATH when the image has one.
MCP_TRUSTED=no
if [ -x "$MCP_ROM/bin/busybox" ] && "$MCP_ROM/bin/busybox" true 2>/dev/null; then
	mkdir "$MCP_TMP/bin"
	for _a in $("$MCP_ROM/bin/busybox" --list 2>/dev/null); do
		ln -s "$MCP_ROM/bin/busybox" "$MCP_TMP/bin/$_a" 2>/dev/null
	done
	PATH="$MCP_TMP/bin:$PATH"
	MCP_TRUSTED="yes ($MCP_ROM/bin/busybox)"
fi
export PATH

# ---------------------------------------------------------------- JSON output
# stdin -> one JSON string literal. NUL bytes are dropped, control characters escaped.
# No gsub: busybox 1.37 reads "\\\"" in a gsub replacement differently from 1.33, and
# busybox 1.33 reads "t (x)" as a call of function t. A lookup table avoids both.
json_str() {
	tr -d '\000' | awk '
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
		while (match(s, /[\\"\001-\037\177]/)) {
			o = o substr(s, 1, RSTART - 1) esc[substr(s, RSTART, 1)]
			s = substr(s, RSTART + 1)
		}
		printf "%s%s", o, s
	}
	END { printf "\"" }'
}

json_quote() { printf '%s' "$1" | json_str; }

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
	'' | *[!0-9-]* | ?*-*) tool_error "$2 must be an integer, got '$_av'"; return 1 ;;
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

# ---------------------------------------------------------------- helpers
tool_error() { printf 'error: %s\n' "$*"; return 1; }

section() { printf '\n== %s\n' "$*"; }

have() { command -v "$1" >/dev/null 2>&1; }

rd() {
	[ -f "$1" ] || return 1
	if [ -L "$1" ]; then
		_t=$(readlink -f "$1" 2>/dev/null) || _t=$(readlink "$1" 2>/dev/null)
		case $_t in '' | /proc/* | /sys/* | /dev/*) return 1 ;; esac
	fi
	cat "$1" 2>/dev/null
}

rom_path() { printf '%s/%s' "${MCP_ROM%/}" "${1#/}"; }

in_rom() { [ -e "$(rom_path "$1")" ] || [ -L "$(rom_path "$1")" ]; }

# Masks secrets in uci show output, config files, shadow lines and key blocks.
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
		print line
	}'
}

# Runs CMD with a time limit. Exit status 124 when the limit hit.
# Contract version; server/00-core.sh owner hardens it (process tree, no setsid).
run_timeout() {
	_secs=$1; shift
	"$@" &
	_pid=$!
	( sleep "$_secs"; kill -TERM "$_pid" 2>/dev/null; sleep 2; kill -KILL "$_pid" 2>/dev/null ) &
	_wd=$!
	wait "$_pid"; _rc=$?
	kill "$_wd" 2>/dev/null; wait "$_wd" 2>/dev/null
	[ "$_rc" -ge 128 ] && [ "$_rc" -le 143 ] && return 124
	return "$_rc"
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
_mcp_send() { printf '%s\n' "$1"; }

_mcp_error() { # ID CODE MESSAGE
	_mcp_send "{\"jsonrpc\":\"2.0\",\"id\":$1,\"error\":{\"code\":$2,\"message\":$(json_quote "$3")}}"
}

_mcp_initialize() { # ID
	_want=$(_mcp_jf -e @.params.protocolVersion)
	_proto=${MCP_PROTOCOLS%% *}
	for _p in $MCP_PROTOCOLS; do [ "$_p" = "$_want" ] && _proto=$_want; done
	_instr="Read-only tools for inspecting an OpenWrt router; start with system_info and audit. Tools run with the firmware image's busybox first in PATH when /rom has one ($MCP_TRUSTED). Output over $MCP_MAX_OUTPUT bytes is cut. Secrets are masked unless the launcher was started with --no-redact (now: MCP_REDACT=$MCP_REDACT). The exec tool runs any shell command as root: prefer the dedicated tools."
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
	}
}

_mcp_tools_call() { # ID
	_name=$(_mcp_jf -e @.params.name)
	case $_name in '' | *[!a-z0-9_]*) _mcp_error "$1" -32602 "Unknown tool: $_name"; return ;; esac
	case " $MCP_TOOLS " in *" $_name "*) ;; *) _mcp_error "$1" -32602 "Unknown tool: $_name"; return ;; esac
	_out=$MCP_TMP/out
	mcp_log "call $_name"
	(cd "$MCP_TMP/work" && "tool_$_name") </dev/null >"$_out" 2>&1
	_rc=$?
	_size=$(wc -c <"$_out")
	_err=false
	[ "$_rc" = 0 ] || _err=true
	{
		printf '{"jsonrpc":"2.0","id":%s,"result":{"content":[{"type":"text","text":' "$1"
		if [ "$_size" -eq 0 ]; then
			echo "(no output)"
		elif [ "$_size" -gt "$MCP_MAX_OUTPUT" ]; then
			head -c "$MCP_MAX_OUTPUT" "$_out"
			printf '\n[output cut at %s of %s bytes; narrow the request or page with offset/limit where the tool has them]\n' "$MCP_MAX_OUTPUT" "$_size"
		else
			cat "$_out"
		fi | json_str
		printf '}],"isError":%s}}\n' "$_err"
	}
	rm -f "$_out"
}

_mcp_handle() {
	if ! _type=$(jsonfilter -i "$MCP_REQ" -t @ 2>/dev/null) || [ -z "$_type" ]; then
		_mcp_error null -32700 "Parse error"; return
	fi
	if [ "$_type" != object ]; then
		_mcp_error null -32600 "Invalid Request: batches are not supported"; return
	fi
	_method=$(_mcp_jf -e @.method)
	case $(_mcp_jf -t @.id) in
	int | double) _id=$(_mcp_jf -e @.id) ;;
	string) _id=$(_mcp_jf -e @.id | json_str) ;;
	null) _id=null ;;
	'') _id= ;;
	*) _mcp_error null -32600 "Invalid Request: bad id"; return ;;
	esac
	mcp_log "<- ${_method:-?} id=${_id:-none}"
	if [ -z "$_id" ]; then return; fi # notification: no reply
	case $_method in
	initialize) _mcp_initialize "$_id" ;;
	ping) _mcp_send "{\"jsonrpc\":\"2.0\",\"id\":$_id,\"result\":{}}" ;;
	tools/list) _mcp_tools_list "$_id" ;;
	tools/call) _mcp_tools_call "$_id" ;;
	'') _mcp_error "$_id" -32600 "Invalid Request: no method" ;;
	*) _mcp_error "$_id" -32601 "Method not found: $_method" ;;
	esac
}

mcp_main() {
	while IFS= read -r _line || [ -n "$_line" ]; do
		_line=${_line%"$(printf '\r')"}
		[ -n "$_line" ] || continue
		printf '%s' "$_line" >"$MCP_REQ"
		_mcp_handle
		_line=
	done
}

# ---------------------------------------------------------------- server_info
mcp_register server_info <<'EOF'
{"name":"server_info","title":"Server info","description":"Version of this MCP server, the protocol, whether the firmware image's busybox is used (trusted tools), whether secrets are masked, the output limit and the list of tools. Cheap; call it first if unsure what the server can do.","inputSchema":{"type":"object","properties":{},"additionalProperties":false},"annotations":{"readOnlyHint":true,"openWorldHint":false}}
EOF
tool_server_info() {
	printf 'server        %s %s\n' "$MCP_SERVER_NAME" "$MCP_SERVER_VERSION"
	printf 'protocols     %s\n' "$MCP_PROTOCOLS"
	printf 'trusted tools %s\n' "$MCP_TRUSTED"
	printf 'redaction     %s\n' "$([ "$MCP_REDACT" = 1 ] && echo on || echo off)"
	printf 'max output    %s bytes\n' "$MCP_MAX_OUTPUT"
	printf 'call timeout  %s s\n' "$MCP_CALL_TIMEOUT"
	printf 'firmware root %s\n' "$MCP_ROM"
	printf 'overlay upper %s\n' "$MCP_UPPER"
	printf 'temp dir      %s\n' "$MCP_TMP"
	printf 'tools        %s\n' "$MCP_TOOLS"
}
