# exec: one shell command as root. The only tool that may change the router.

mcp_register exec <<'EOF'
{"name":"exec","title":"Run a shell command as root",
"description":"Runs one shell command with sh -c as root on the router and returns its stdout and stderr, then a last line [exit N] or [timeout after N s]. It can change or break the router, so every call should be approved by the user; prefer the dedicated read-only tools and use exec only for what they do not cover. Do not run netstat on a device suspected of the gl-helper infection (the implant replaced it, running it starts the malware); the network tools read /proc instead. The output is not redacted: secrets the command prints are shown as they are.",
"inputSchema":{"type":"object","properties":{
"command":{"type":"string","description":"Shell command line, run with sh -c. stdin is /dev/null. Background processes should redirect their output (cmd >/dev/null 2>&1 &)."},
"timeout":{"type":"integer","description":"Seconds before the command and every process it started are killed, 1 to 600. Default 30.","default":30,"minimum":1,"maximum":600},
"trusted_tools":{"type":"boolean","description":"true: the firmware image's busybox (/rom) comes first in PATH, so overlay replacements of applets are not run. false: the router's normal PATH. Default true.","default":true},
"cwd":{"type":"string","description":"Working directory. Default /.","default":"/"}},
"required":["command"],"additionalProperties":false},
"annotations":{"title":"Run a shell command as root","readOnlyHint":false,"destructiveHint":true,"idempotentHint":false,"openWorldHint":true}}
EOF
mcp_own_timeout exec
# _x_to is set by arg_int (eval), _rt_fired by run_timeout (server/00-core.sh)
# shellcheck disable=SC2154
tool_exec() {
	arg _x_cmd command ''
	[ -n "$_x_cmd" ] || { tool_error "command is empty"; return; }
	arg_int _x_to timeout 30 1 600 || return
	arg _x_cwd cwd /
	[ -n "$_x_cwd" ] || _x_cwd=/
	arg_bool trusted_tools true || PATH=$MCP_PATH_ORIG
	export PATH
	cd "$_x_cwd" 2>/dev/null || { tool_error "cwd $_x_cwd: no such directory"; return; }
	run_timeout "$_x_to" sh -c "$_x_cmd" 2>&1
	_x_rc=$?
	if [ "$_x_rc" = 124 ] && [ "$_rt_fired" = 1 ]; then
		printf '\n[timeout after %s s]\n' "$_x_to"
		return 1
	fi
	printf '\n[exit %s]\n' "$_x_rc"
	return 0
}
