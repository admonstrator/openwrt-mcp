# admin module: uci_change and service_control, configuration changes through uci and
# init scripts on any OpenWrt. Registered with mcp_register_admin only; the launcher
# ships this file only with --admin.
# Handler variables are assigned by arg/arg_int (through eval), _rt_fired by run_timeout:
# shellcheck disable=SC2154

# Packages whose change can cut the owner off or expose the router: every uci_change on
# them needs confirm. system needs it only for ttylogin (serial console login); any
# delete of a whole section needs it in every package.
_UC_RISKY_PKGS='network firewall wireless dropbear uhttpd nginx rpcd oui-httpd wan-access rtty glconfig tailscale zerotier'
# Init scripts that carry access or the network: stop, restart and disable need confirm.
_SV_RISKY='network firewall dropbear sshd uhttpd nginx rpcd ubus odhcpd dnsmasq gl-ngx-session wpad hostapd tailscale zerotier openvpn'
# Init scripts that only make sense at boot or shutdown: every action but status is refused.
_SV_REFUSED='boot done umount sysfixtime'

_uc_nl='
'
_uc_cr=$(printf '\r')

# _uc_in WORD LIST: exit status 0 when WORD is one of the space separated LIST
_uc_in() { case " $2 " in *" $1 "*) return 0 ;; esac; return 1; }

# _uc_name S: exit status 0 when S is a uci name (letters, digits, underscore)
_uc_name() { case $1 in '' | *[!A-Za-z0-9_]*) return 1 ;; esac; return 0; }

# _uc_section S: a section name, or @type[N] with an optional minus and up to 4 digits
_uc_section() {
	case $1 in
	@*)
		_us_t=${1#@}
		_us_t=${_us_t%%\[*}
		_us_i=${1#*\[}
		_us_i=${_us_i%\]}
		[ "$1" = "@${_us_t}[${_us_i}]" ] || return 1
		_uc_name "$_us_t" || return 1
		case ${_us_i#-} in '' | *[!0-9]* | ?????*) return 1 ;; esac
		return 0 ;;
	*) _uc_name "$1" ;;
	esac
}

# _uc_q VALUE: VALUE in single quotes as uci show prints it
_uc_q() {
	case $1 in
	*"'"*) printf "'%s'" "$(printf '%s\n' "$1" | sed "s/'/'\\\\''/g")" ;;
	*) printf "'%s'" "$1" ;;
	esac
}

# _uc_copy ARGS...: uci on the private copy of the package (config in copy/cfg, changes
# in copy/save, no override dir); never touches /etc/config or /tmp/.uci
_uc_copy() {
	if [ "$_uc_hasC" = 1 ]; then
		uci -C "$_uc_w/copy/ovr" -c "$_uc_w/copy/cfg" -t "$_uc_w/copy/save" "$@"
	else
		uci -c "$_uc_w/copy/cfg" -t "$_uc_w/copy/save" "$@"
	fi
}

# _uc_run RUNNER N: apply change N (files op.N, path.N, val.N) with RUNNER (uci or
# _uc_copy); every value is one argv word. stdout is the new section name for add.
_uc_run() {
	_ur_op=$(cat "op.$2")
	_ur_p=$(cat "path.$2")
	IFS= read -r _ur_v <"val.$2"
	case $_ur_op in
	set) "$1" set "$_uc_pkg.$_ur_p=$_ur_v" ;;
	delete) "$1" delete "$_uc_pkg.$_ur_p" ;;
	add_list) "$1" add_list "$_uc_pkg.$_ur_p=$_ur_v" ;;
	del_list) "$1" del_list "$_uc_pkg.$_ur_p=$_ur_v" ;;
	add) "$1" add "$_uc_pkg" "$_ur_v" ;;
	*) return 1 ;;
	esac
}

# _uc_ops RUNNER: apply every change; on the first failure print what uci said and return 1
_uc_ops() {
	_uo_i=1
	while [ "$_uo_i" -le "$_uc_n" ]; do
		if ! _uc_run "$1" "$_uo_i" >"res.$_uo_i" 2>"err.$_uo_i"; then
			printf 'change %s (%s): uci refused it: %s\n' "$_uo_i" "$(cat "op.$_uo_i")" \
				"$(tr '\n' ' ' <"err.$_uo_i" | sed 's/ *$//')"
			return 1
		fi
		_uo_i=$((_uo_i + 1))
	done
	return 0
}

# _uc_diff BEFORE AFTER MAX: lines removed and added (as a multiset), redacted
_uc_diff() {
	awk 'NR == FNR { n[$0]++; next } { if (n[$0] > 0) n[$0]--; else print }' "$2" "$1" | redact >diff.rm
	awk 'NR == FNR { n[$0]++; next } { if (n[$0] > 0) n[$0]--; else print }' "$1" "$2" | redact >diff.add
	if [ ! -s diff.rm ] && [ ! -s diff.add ]; then
		echo 'no line would change'
		return 0
	fi
	printf 'config %s: %s removed, %s added\n' "$_uc_pkg" \
		"$(wc -l <diff.rm | tr -d ' ')" "$(wc -l <diff.add | tr -d ' ')"
	{ sed 's/^/  - /' diff.rm; sed 's/^/  + /' diff.add; } | awk -v max="$3" '
		NR <= max { print }
		END { if (NR > max) printf "  ... %d more lines\n", NR - max }'
}

# _uc_procd: exit status 0 when procd answers on ubus (its "service" object)
_uc_procd() { lib_ubus service list '{"name":"-"}' >/dev/null; }

# ============================================================== uci_change
mcp_register_admin uci_change <<'EOF'
{"name":"uci_change","title":"Change uci configuration",
"description":"Changes the uci configuration of ONE package in /etc/config: applies a list of operations (set, delete, add_list, del_list, add), commits the package and asks procd to reload the services that depend on it (reload_config). Every operation is checked first on a private copy of the package; if one fails, nothing is changed. dry_run shows the lines that would change and touches nothing. The result lists the plan, what changed in /etc/config (redacted) and whether the change was applied. Refused while the package has uncommitted changes from someone else (uci changes). Risky, so only with confirm=true after the user agreed to exactly this call: any change to the packages network, firewall, wireless, dropbear, uhttpd, nginx, rpcd, oui-httpd, wan-access, rtty, glconfig, tailscale, zerotier (they can cut off access to the router or expose it), a change of system ttylogin, and every delete of a whole section. Read the package first with the uci tool. On GL.iNet firmware prefer glinet_api for GL-managed settings.",
"inputSchema":{"type":"object","properties":{
"package":{"type":"string","description":"uci package, the file name in /etc/config (letters, digits, _ and -). It must exist."},
"changes":{"type":"array","description":"Operations, applied in order. path is relative to the package: section or section.option; a section is a name or @type[N] (N may be negative: @rule[-1] is the last rule, also one added by an earlier add). Values are taken literally (no shell); newlines are refused. 1 to 100 operations.","minItems":1,"maxItems":100,
"items":{"type":"object","properties":{
"op":{"type":"string","enum":["set","delete","add_list","del_list","add"],"description":"set: path section.option=value (or section=type to create a named section); delete: path section.option or section (the whole section, risky); add_list / del_list: path section.option, one list element; add: a new anonymous section, value is its type, no path."},
"path":{"type":"string","description":"section or section.option, without the package name"},
"value":{"type":"string","description":"the value (set, add_list, del_list) or the section type (add)"}},
"required":["op"],"additionalProperties":false}},
"dry_run":{"type":"boolean","description":"true: only show what would change, on a copy of the package. Default false.","default":false},
"reload":{"type":"boolean","description":"true: after the commit, let procd reload the services whose configuration changed (reload_config). false: commit only. Default true.","default":true},
"confirm":{"type":"boolean","description":"Set true only after the user agreed to exactly this risky change. Default false.","default":false},
"timeout":{"type":"integer","description":"Seconds for the reload step, 1 to 300. Default 30.","default":30,"minimum":1,"maximum":300}},
"required":["package","changes"],"additionalProperties":false},
"annotations":{"title":"Change uci configuration","readOnlyHint":false,"destructiveHint":true,"idempotentHint":false,"openWorldHint":false}}
EOF
mcp_own_timeout uci_change
tool_uci_change() {
	_uc_w=$PWD
	arg _uc_pkg package ''
	case $_uc_pkg in
	'' | -* | *[!A-Za-z0-9_-]*) tool_error "package must be a name of letters, digits, _ and - (not starting with -), got '$_uc_pkg'"; return ;;
	esac
	have uci || { tool_error "uci: not available on this router"; return; }
	[ -f "/etc/config/$_uc_pkg" ] || { tool_error "package $_uc_pkg: /etc/config/$_uc_pkg does not exist (uci_change changes existing packages only)"; return; }
	arg_int _uc_to timeout 30 1 300 || return
	_uc_dry=0
	arg_bool dry_run false && _uc_dry=1
	_uc_reload=1
	arg_bool reload true || _uc_reload=0
	_uc_confirm=0
	arg_bool confirm false && _uc_confirm=1

	# ---- validate every change before anything runs
	arg _uc_all changes ''
	_uc_types=$(jsonfilter -s "$_uc_all" -t '@[*]' 2>/dev/null | sed 's/\\ / /g')
	_uc_n=0
	for _uc_t in $_uc_types; do _uc_n=$((_uc_n + 1)); done
	[ "$_uc_n" -ge 1 ] || { tool_error "changes must hold at least one operation"; return; }
	[ "$_uc_n" -le 100 ] || { tool_error "changes holds $_uc_n operations, at most 100 are allowed"; return; }
	: >risk
	_uc_i=0
	for _uc_t in $_uc_types; do
		_uc_i=$((_uc_i + 1))
		_uc_e="change $_uc_i"
		[ "$_uc_t" = object ] || { tool_error "$_uc_e must be an object, got $_uc_t"; return; }
		_uc_o=$(jsonfilter -s "$_uc_all" -e "@[$((_uc_i - 1))]")
		_uc_known=0
		for _uc_k in op path value; do
			[ "$(jsonfilter -s "$_uc_o" -t "@.$_uc_k" 2>/dev/null)" ] && _uc_known=$((_uc_known + 1))
		done
		_uc_members=$(jsonfilter -s "$_uc_o" -t '@.*' 2>/dev/null | sed 's/\\ / /g' | wc -w)
		[ "$_uc_members" -eq "$_uc_known" ] || { tool_error "$_uc_e: unknown member (an operation takes op, path and value only)"; return; }
		for _uc_k in op path value; do
			case $(jsonfilter -s "$_uc_o" -t "@.$_uc_k" 2>/dev/null) in
			'' | string) ;;
			*) tool_error "$_uc_e: $_uc_k must be a string (quote numbers: \"1\")"; return ;;
			esac
		done
		_uc_op=$(jsonfilter -s "$_uc_o" -e '@.op' 2>/dev/null)
		_uc_p=$(jsonfilter -s "$_uc_o" -e '@.path' 2>/dev/null)
		_uc_hasp=0
		[ "$(jsonfilter -s "$_uc_o" -t '@.path' 2>/dev/null)" = string ] && _uc_hasp=1
		_uc_hasv=0
		[ "$(jsonfilter -s "$_uc_o" -t '@.value' 2>/dev/null)" = string ] && _uc_hasv=1
		# the value exactly: jsonfilter adds one newline, $() would eat any number of them
		_uc_v=$(jsonfilter -s "$_uc_o" -e '@.value' 2>/dev/null; echo .)
		_uc_v=${_uc_v%.}
		_uc_v=${_uc_v%"$_uc_nl"}
		case $_uc_v in
		*"$_uc_nl"* | *"$_uc_cr"*) tool_error "$_uc_e: the value contains a line break; uci_change takes single-line values only"; return ;;
		esac
		case $_uc_op in
		set | delete | add_list | del_list)
			[ "$_uc_hasp" = 1 ] || { tool_error "$_uc_e ($_uc_op) needs a path"; return; }
			_uc_s=${_uc_p%%.*}
			_uc_opt=
			case $_uc_p in *.*) _uc_opt=${_uc_p#*.} ;; esac
			_uc_section "$_uc_s" || { tool_error "$_uc_e: section '$_uc_s' is not a uci section name (letters, digits, _) or @type[N]"; return; }
			case $_uc_p in
			*.*) _uc_name "$_uc_opt" || { tool_error "$_uc_e: option '$_uc_opt' is not a uci option name (letters, digits, _)"; return; } ;;
			esac
			case $_uc_op in
			add_list | del_list) [ -n "$_uc_opt" ] || { tool_error "$_uc_e ($_uc_op) needs a path section.option"; return; } ;;
			esac
			case $_uc_op in
			delete) [ "$_uc_hasv" = 0 ] || { tool_error "$_uc_e (delete) takes no value; use del_list to remove one list element"; return; } ;;
			*) [ "$_uc_hasv" = 1 ] || { tool_error "$_uc_e ($_uc_op) needs a value"; return; } ;;
			esac
			if [ "$_uc_op" = set ] && [ -z "$_uc_opt" ]; then
				_uc_name "$_uc_v" || { tool_error "$_uc_e: set on a section creates it with the value as its type, and '$_uc_v' is not a type name (letters, digits, _)"; return; }
			fi
			if [ "$_uc_op" = delete ] && [ -z "$_uc_opt" ]; then
				echo "change $_uc_i deletes the whole section $_uc_pkg.$_uc_s" >>risk
			fi
			if [ "$_uc_pkg" = system ] && [ "$_uc_opt" = ttylogin ]; then
				echo "change $_uc_i changes system ttylogin (login on the serial console)" >>risk
			fi
			;;
		add)
			[ "$_uc_hasp" = 0 ] || { tool_error "$_uc_e (add) takes no path, only the section type as value"; return; }
			[ "$_uc_hasv" = 1 ] || { tool_error "$_uc_e (add) needs the section type as value"; return; }
			_uc_name "$_uc_v" || { tool_error "$_uc_e (add): '$_uc_v' is not a section type name (letters, digits, _)"; return; }
			;;
		'') tool_error "$_uc_e needs an op (set, delete, add_list, del_list, add)"; return ;;
		*) tool_error "$_uc_e: unknown op '$_uc_op' (set, delete, add_list, del_list, add)"; return ;;
		esac
		printf '%s\n' "$_uc_op" >"op.$_uc_i"
		printf '%s\n' "$_uc_p" >"path.$_uc_i"
		printf '%s\n' "$_uc_v" >"val.$_uc_i"
		# the plan line: "N op " and, apart, a uci show style line that redact understands
		printf '%s %s\n' "$_uc_i" "$_uc_op" >>plan.k
		case $_uc_op in
		add) printf '%s (new %s section)\n' "$_uc_pkg" "$_uc_v" ;;
		delete) printf '%s.%s\n' "$_uc_pkg" "$_uc_p" ;;
		*) printf '%s.%s=%s\n' "$_uc_pkg" "$_uc_p" "$(_uc_q "$_uc_v")" ;;
		esac >>plan.v
	done
	if _uc_in "$_uc_pkg" "$_UC_RISKY_PKGS"; then
		echo "package $_uc_pkg: a change can cut off access to the router or expose it" >>risk
	fi

	_uc_plan() {
		section "Plan: $_uc_n operation(s) on /etc/config/$_uc_pkg"
		redact <plan.v | awk 'NR == FNR { k[FNR] = $0; next } { print k[FNR] " " $0 }' plan.k -
	}

	# ---- risky without confirm: refused, also before a dry run tells more
	if [ -s risk ] && [ "$_uc_confirm" = 0 ] && [ "$_uc_dry" = 0 ]; then
		tool_error "risky change, not applied: $(sed 's/$/;/' risk | tr '\n' ' ' | sed 's/; $//'). Show the user this plan, ask whether to apply exactly this change, and only then resend the same call with confirm: true (dry_run: true shows the lines that would change)."
		_uc_plan
		return 1
	fi

	# ---- uncommitted changes of someone else in this package
	uci -q changes "$_uc_pkg" >pending 2>/dev/null
	if [ -s pending ] && [ "$_uc_dry" = 0 ]; then
		tool_error "/etc/config/$_uc_pkg has uncommitted changes that are not from this call; committing would apply them too. Ask the user: they can be committed or reverted (uci commit $_uc_pkg / uci revert $_uc_pkg) before this change. Nothing was changed."
		section "Uncommitted changes in $_uc_pkg"
		redact <pending | awk 'NR <= 40 { print } END { if (NR > 40) printf "... %d more lines\n", NR - 40 }'
		_uc_plan
		return 1
	fi

	_uc_plan

	# ---- every operation on a private copy first
	mkdir -p copy/cfg copy/save copy/ovr
	rd "/etc/config/$_uc_pkg" >"copy/cfg/$_uc_pkg" || { tool_error "cannot read /etc/config/$_uc_pkg"; return; }
	_uc_hasC=0
	uci 2>&1 | grep -q '^[[:space:]]*-C ' && _uc_hasC=1
	_uc_copy -q show "$_uc_pkg" >copy.before 2>/dev/null
	if ! _uc_ops _uc_copy >copy.err; then
		tool_error "invalid operation, nothing was changed: $(cat copy.err)"
		return 1
	fi
	_uc_copy -q show "$_uc_pkg" >copy.after 2>/dev/null

	if [ "$_uc_dry" = 1 ]; then
		section "Dry run: lines that would change (nothing was written)"
		_uc_diff copy.before copy.after 200
		if [ -s pending ]; then
			section "Uncommitted changes in $_uc_pkg"
			echo "A real run is refused until these are committed or reverted:"
			redact <pending | awk 'NR <= 40 { print } END { if (NR > 40) printf "... %d more lines\n", NR - 40 }'
		fi
		if [ -s risk ]; then
			section "Risk"
			sed 's/^/- /' risk
			echo "A real run needs confirm: true, after the user agreed to exactly this change."
		fi
		[ -f /etc/glversion ] && { section "Note"; _uc_glnote; }
		return 0
	fi

	# ---- the real run
	lib_cfg_snapshot snap
	if ! _uc_ops uci >real.err; then
		uci -q revert "$_uc_pkg" >/dev/null 2>&1
		tool_error "$(cat real.err); the operations were reverted, nothing was committed"
		return 1
	fi
	if ! uci commit "$_uc_pkg" >commit.err 2>&1; then
		uci -q revert "$_uc_pkg" >/dev/null 2>&1
		tool_error "uci commit $_uc_pkg failed: $(tr '\n' ' ' <commit.err); reverted"
		return 1
	fi
	section "Applied"
	echo "committed /etc/config/$_uc_pkg ($_uc_n operation(s))"
	_uc_i=1
	while [ "$_uc_i" -le "$_uc_n" ]; do
		[ "$(cat "op.$_uc_i")" = add ] && printf 'change %s (add): new section %s\n' "$_uc_i" "$(head -n 1 "res.$_uc_i")"
		_uc_i=$((_uc_i + 1))
	done

	section "Reload"
	if [ "$_uc_reload" = 0 ]; then
		echo "not reloaded (reload: false): the change is committed but the running services still use the old configuration"
	else
		_uc_rc=
		have reload_config && _uc_rc=$(command -v reload_config)
		if ! _uc_procd; then
			echo "reload_config  ${_uc_rc:-not available on this firmware}"
			echo "procd/ubus     not running or not answering (no ubus socket, or procd's service object is missing)"
			echo "result         NOT APPLIED: the change is committed to /etc/config/$_uc_pkg, but no service was reloaded. Apply it with service_control (action reload or restart) once procd runs, or reboot."
		elif [ -n "$_uc_rc" ] && [ -f /var/run/config.md5 ]; then
			run_timeout "$_uc_to" reload_config >reload.out 2>&1
			_uc_x=$?
			echo "reload_config  $_uc_rc"
			if [ "$_uc_x" = 124 ] && [ "$_rt_fired" = 1 ]; then
				echo "result         reload_config was stopped after $_uc_to s; the change is committed, check the services"
			else
				echo "result         ran (exit $_uc_x): procd reloads every service whose configuration changed since the last reload_config, in the background (usually within a few seconds)"
			fi
			[ -s reload.out ] && redact <reload.out | head -n 20 | sed 's/^/  /'
		else
			echo "reload_config  ${_uc_rc:-not available on this firmware}${_uc_rc:+ (no /var/run/config.md5 to compare against)}"
			if lib_ubus service event "{\"type\":\"config.change\",\"data\":{\"package\":\"$_uc_pkg\"}}" >/dev/null; then
				echo "result         sent procd the config.change event for $_uc_pkg: it reloads the services that watch this package, in the background"
			else
				echo "result         NOT APPLIED: the config.change event could not be sent; the change is committed to /etc/config/$_uc_pkg. Use service_control (action reload)."
			fi
		fi
	fi

	section "Changes in /etc/config"
	lib_cfg_changes snap 200
	[ -f /etc/glversion ] && { section "Note"; _uc_glnote; }
	return 0
}

_uc_glnote() {
	echo "GL.iNet firmware: glinet_api changes settings the way the GL web UI does and keeps it in sync. GL services may overwrite direct uci edits of GL-managed packages, or not apply them."
}

# ============================================================== service_control
mcp_register_admin service_control <<'EOF'
{"name":"service_control","title":"Control an init script",
"description":"Runs an init script in /etc/init.d: status (enabled at boot? running instances in procd?, read only), or start, stop, restart, reload, enable, disable (runs /etc/init.d/NAME ACTION and returns its output and exit status, then the status). Risky, so only with confirm=true after the user agreed: stop, restart and disable of services that carry access or the network (network, firewall, dropbear, sshd, uhttpd, nginx, rpcd, ubus, odhcpd, dnsmasq, gl-ngx-session, wpad, hostapd, tailscale, zerotier, openvpn). boot, done, umount and sysfixtime run only at boot or shutdown: every action but status is refused for them. Use the services tool to list init scripts.",
"inputSchema":{"type":"object","properties":{
"service":{"type":"string","description":"Name of a script in /etc/init.d (letters, digits, _ . -), no path."},
"action":{"type":"string","enum":["status","start","stop","restart","reload","enable","disable"],"description":"status only reads; the others run the init script with that action."},
"confirm":{"type":"boolean","description":"Set true only after the user agreed to exactly this risky action. Default false.","default":false},
"timeout":{"type":"integer","description":"Seconds before the init script and every process it started in the foreground are killed, 1 to 300. Default 30.","default":30,"minimum":1,"maximum":300}},
"required":["service","action"],"additionalProperties":false},
"annotations":{"title":"Control an init script","readOnlyHint":false,"destructiveHint":true,"idempotentHint":false,"openWorldHint":false}}
EOF
mcp_own_timeout service_control

# _sv_status NAME: enabled (rc.d start link) and running (procd instances)
_sv_status() {
	_ss_on=
	for _ss_f in /etc/rc.d/S[0-9][0-9]"$1"; do
		[ -e "$_ss_f" ] || [ -L "$_ss_f" ] || continue
		_ss_on="${_ss_on:+$_ss_on }$_ss_f"
	done
	printf 'enabled  %s\n' "${_ss_on:+yes ($_ss_on)}${_ss_on:-no (no /etc/rc.d/S??$1 link)}"
	if lib_ubus service list "{\"name\":\"$1\"}" >svc.json; then
		_ss_n=$(grep -c '"running": true' svc.json)
		_ss_all=$(grep -c '"instances"' svc.json)
		if [ "$_ss_n" -gt 0 ]; then
			printf 'running  yes (%s running instance(s) in procd)\n' "$_ss_n"
		elif [ "$_ss_all" -gt 0 ]; then
			echo "running  no (procd knows the service, but no instance is running)"
		else
			echo "running  no (procd has no instance: stopped, or not a procd service)"
		fi
	else
		echo "running  unknown (ubus or procd not available)"
	fi
}

tool_service_control() {
	arg _sv_name service ''
	case $_sv_name in
	'' | .* | -* | *[!A-Za-z0-9_.-]*) tool_error "service must be the name of a script in /etc/init.d (letters, digits, _ . -, not starting with . or -), got '$_sv_name'"; return ;;
	esac
	[ -f "/etc/init.d/$_sv_name" ] || { tool_error "no init script /etc/init.d/$_sv_name (the services tool lists them)"; return; }
	arg _sv_act action ''
	case $_sv_act in
	status | start | stop | restart | reload | enable | disable) ;;
	*) tool_error "action must be one of status, start, stop, restart, reload, enable, disable, got '$_sv_act'"; return ;;
	esac
	arg_int _sv_to timeout 30 1 300 || return
	_sv_confirm=0
	arg_bool confirm false && _sv_confirm=1

	if [ "$_sv_act" = status ]; then
		section "Status of $_sv_name"
		_sv_status "$_sv_name"
		return 0
	fi
	if _uc_in "$_sv_name" "$_SV_REFUSED"; then
		tool_error "refused: /etc/init.d/$_sv_name runs only at boot or shutdown (boot, done, umount, sysfixtime); running it by hand or changing its boot link can break the router"
		return
	fi
	case $_sv_act in
	stop | restart | disable)
		if _uc_in "$_sv_name" "$_SV_RISKY" && [ "$_sv_confirm" = 0 ]; then
			tool_error "risky action, not run: $_sv_act of $_sv_name can cut off access to the router or its network. Ask the user whether to run exactly this, and only then resend the same call with confirm: true."
			return
		fi
		;;
	esac

	section "/etc/init.d/$_sv_name $_sv_act"
	# the script runs from /, without the call's tag: daemons it starts outside procd
	# belong to the router, not to this call
	# shellcheck disable=SC2016  # the inner script expands its own arguments
	run_timeout "$_sv_to" sh -c 'unset MCP_CALL_TAG; cd / || exit 1; exec "$0" "$1"' \
		"/etc/init.d/$_sv_name" "$_sv_act" >out 2>&1
	_sv_rc=$?
	redact <out | awk 'NR <= 200 { print } END { if (NR > 200) printf "... %d more lines\n", NR - 200 }'
	if [ "$_sv_rc" = 124 ] && [ "$_rt_fired" = 1 ]; then
		printf '[timeout after %s s]\n' "$_sv_to"
		section "Status of $_sv_name"
		_sv_status "$_sv_name"
		return 1
	fi
	printf '[exit %s]\n' "$_sv_rc"
	section "Status of $_sv_name"
	_sv_status "$_sv_name"
	return 0
}
