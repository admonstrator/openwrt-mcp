#!/bin/sh
# Builds server/61-admin-glinet-catalog.sh, the method catalog of the glinet_api tool,
# from the GL.iNet web API documentation (github.com/admonstrator/glinet-api):
#
#   scripts/glinet-methods.sh /path/to/glinet-api [OUTPUT]
#
# OUTPUT defaults to server/61-admin-glinet-catalog.sh next to this script; "-" writes
# to stdout. Needs only POSIX sh and awk (macOS and Linux). The same input gives the
# same output, byte for byte.
#
# It reads src/data/api/<category>/<object>.yaml (format: src/data/README.md there) and
# keeps, per method: the summary, the parameters (name, type, required, enum, a cut
# description) and a class that glinet_api acts on:
#
#   q  query    reads only; runs without confirm, no config report
#   a  active   changes settings or does something (restarts a service, goes to the
#               internet, scans); runs without confirm, config changes are reported
#   r  risky    runs only with confirm: true; config changes are reported
#
# The class comes from, in this order:
#   1. the rules table below (exact object.method), which also gives the reason shown
#      to the model;
#   2. "destructive: true" in the documentation                      -> r
#   3. the method name: remove_* clear_* uninstall*                  -> r (it deletes)
#   4. the method name: get_* check_* load_*                         -> q
#   5. everything else                                               -> a
# A rule that names a method the documentation does not have is an error: the table
# must be looked at again when the documentation changes.

set -eu
LC_ALL=C
export LC_ALL

usage() { echo "usage: $0 /path/to/glinet-api [OUTPUT|-]" >&2; exit 2; }
[ $# -ge 1 ] && [ $# -le 2 ] || usage
src=${1%/}
api=$src/src/data/api
[ -d "$api" ] || { echo "$0: $api: no such directory" >&2; exit 1; }
out=${2:-$(dirname "$0")/../server/61-admin-glinet-catalog.sh}

# the commit the catalog was made from, read from the files (no git needed)
commit=unknown
if [ -f "$src/.git/HEAD" ]; then
	read -r head <"$src/.git/HEAD" || :
	case $head in
	'ref: '*)
		ref=${head#ref: }
		if [ -f "$src/.git/$ref" ]; then
			read -r commit <"$src/.git/$ref" || :
		elif [ -f "$src/.git/packed-refs" ]; then
			commit=$(awk -v r="$ref" '$2 == r { print $1; exit }' "$src/.git/packed-refs")
		fi
		;;
	*) commit=$head ;;
	esac
	commit=$(printf '%s' "$commit" | cut -c1-12)
	[ -n "$commit" ] || commit=unknown
fi

rules() {
	cat <<'RULES'
# class object.method reason
#
# --- named like a query, but not one (-> a) ---
a tailscale.get_auth_url restarts Tailscale
a ddns.get_status contacts the GL.iNet DDNS service
a upgrade.check_firmware_online contacts the GL.iNet firmware servers
a upgrade.check_cellular_online contacts the GL.iNet firmware servers
a upgrade.check_firmware_local works on the uploaded firmware file
a upgrade.check_cellular_local unpacks the uploaded modem firmware package
a parental-control.check_blacklist_online downloads a block list from the internet
a vpn-client.check_domain_online downloads a domain list from the internet
a ui.get_remote_langs contacts the GL.iNet servers
a network.get_available_address_list asks public services for the router's public IP
a ovpn-client.get_recommend_config downloads configs from the VPN provider
a ovpn-client.get_third_config logs in to the VPN provider and downloads its list
a ovpn-client.check_config unpacks the uploaded files
a wg-client.check_config unpacks the uploaded files
a wg_client.get_provider_server_list contacts the VPN provider
a wg_client.get_provider_user_info contacts the VPN provider
a edgerouter.get_status probes the WAN side for a DHCP server
a mptun.get_token may request a new token from the GL.iNet cloud
#
# --- deletes something small that is easy to set again (-> a) ---
a qos.remove_speed_limit_rule removes one speed limit
#
# --- remote management and who owns the router (-> r) ---
r cloud.set_config turns GoodCloud remote management and its remote SSH/web access on or off
r cloud.bind_device binds the router to a GoodCloud account, which can then manage it remotely
r cloud.rebind binds the router to a possibly different GoodCloud account
r cloud.unbind removes the router from its GoodCloud account and stops remote access
r cloud.bind_info writes GoodCloud account data into the configuration
r rtty.set_config allows remote SSH or web access through the rtty broker
r rtty.run opens an outgoing remote terminal connection to a broker
r acl.add_user gives a web interface account access rights
r acl.add_acl extends the access rights of a web interface group
#
# --- opens the router or the network to the WAN (-> r) ---
r firewall.set_wan_access opens or closes ping, HTTPS and SSH access to the router from the WAN
r firewall.set_dmz exposes one LAN host to all incoming WAN traffic
r firewall.add_rule opens (or blocks) a port of the router itself towards the WAN
r firewall.set_rule changes a WAN rule for a port of the router itself
r firewall.add_port_forward forwards a WAN port to a device in the LAN
r firewall.set_port_forward changes or enables a WAN port forward
r nas-web.set_proto_config turns file sharing (Samba, WebDAV) and its WAN access on or off
r nas-web.conf_nas_wan_access opens or closes file sharing towards the WAN
r wg-server.start starts the WireGuard server and opens its WAN port
r wg-server.set_config changes the WireGuard server's key, port or subnet: existing clients may no longer connect
r wg-server.stop stops the WireGuard server: everyone connected through it is cut off
r wg-server.add_peer creates a VPN client that can reach the network from outside
r ovpn-server.set_config changes the OpenVPN server: it may start listening on the WAN, existing clients may no longer connect
r ovpn-server.generate_certificate replaces the OpenVPN server's CA, certificate and key: existing clients no longer connect
r ovpn-server.add_user creates a VPN login that can reach the network from outside
r tailscale.set_config turns Tailscale on or off and decides what the tailnet may reach (LAN, WAN, exit node); restarts it
r zerotier.set_config joins a ZeroTier network and decides what it may reach; restarts it
r s2s.set_config links the LAN to a remote site through WireGuard
r vpn-client.set_tap_s2s bridges the LAN to a remote site (OpenVPN TAP)
#
# --- can cut the user's own way to the router or the router's uplink (-> r) ---
r wifi.set_config changes or turns off a Wi-Fi network: devices on it are disconnected and need the new settings
r wifi.set_mlo_config changes or turns off a Wi-Fi network (MLO): devices on it are disconnected and need the new settings
r timer.set_wifi schedules Wi-Fi to switch off
r black_white_list.set_single_mac blocks or unblocks a device by MAC address, possibly the user's own
r cable.set_config changes the WAN protocol or address: the internet uplink can go down
r cable.set_port_config changes which port is WAN or LAN: a device on that port can lose the router
r edgerouter.set_config changes the router's address and role in the network (drop-in mode)
r repeater.disconnect drops the Wi-Fi uplink
r repeater.enter_bare_mode switches the repeater to bare mode
r modem.disconnect drops the cellular uplink
r tethering.disconnect drops the USB tethering uplink
r tailscale.logout logs the router out of Tailscale: remote access through the tailnet ends
r vpn-client.set_options changes VPN client options including the kill switch, which blocks traffic when the VPN is down
r vpn-client.set_default_tunnel decides whether traffic outside the VPN policies passes or is blocked
r vpn-client.set_global_mode switches between global and policy VPN mode for all clients
r lpm.set_config sets sleep and shutdown timers: the router can switch itself off
#
# --- software, credentials, things that cost money or reach third parties (-> r) ---
r plugins.install_package installs software on the router
r plugins.set_config replaces the package feeds software is installed from
r luci.install_luci installs LuCI, a second web interface
r upgrade.reset_cellular_upgrade_status aborts a running modem firmware download or flash
r nas-web.set_user_pwd changes the password of a file sharing account
r screen.set_config changes display settings including the lock screen passcode
r modem.set_sim_pin_code enters a SIM PIN: wrong attempts lock the SIM
r modem.send_sms sends an SMS: it can cost money and reaches a third party
r sms-forward.set_phone_number forwards incoming SMS (also login codes) to other phone numbers
r sms-forward.set_email forwards incoming SMS (also login codes) by e-mail
r wg_client.create_provider_account creates an account with a VPN provider
RULES
}

tmp=${TMPDIR:-/tmp}/glinet-methods.$$
trap 'rm -f "$tmp" "$tmp.body"' EXIT INT TERM

{
	rules | sed -n '/^[aqr] /s/^/R /p'
	for f in "$api"/*/*.yaml; do
		echo "F $f"
		# ASCII only: awk cuts by bytes on some systems, and the text goes to a model
		sed -e 's/^/Y /' -e 's/—/-/g' -e 's/–/-/g' -e 's/→/->/g' -e 's/←/<-/g' -e 's/…/.../g' \
			-e 's/↔/<->/g' -e 's/°C/deg C/g' -e 's/≥/>=/g' -e 's/≤/<=/g' -e 's/×/x/g' \
			-e "s/‘/'/g" -e "s/’/'/g" -e 's/“/"/g' -e 's/”/"/g' "$f"
	done
} | awk '
function fail(msg) { printf "glinet-methods: %s\n", msg > "/dev/stderr"; bad = 1; exit 1 }
# a YAML scalar as written after "key: " -> its text
function scalar(s,   q) {
	sub(/^[ \t]+/, "", s); sub(/[ \t]+$/, "", s)
	q = substr(s, 1, 1)
	if (q == "\"" && s ~ /"$/ && length(s) > 1) { s = substr(s, 2, length(s) - 2); gsub(/\\"/, "\"", s); gsub(/\\\\/, "\\", s) }
	else if (q == sq && substr(s, length(s)) == sq && length(s) > 1) { s = substr(s, 2, length(s) - 2); gsub(sq sq, sq, s) }
	gsub(/\t/, " ", s)
	return s
}
function clean(s) { gsub(/[ \t]+/, " ", s); sub(/^ /, "", s); sub(/ $/, "", s); return s }
function cut(s, n) { s = clean(s); if (length(s) > n) s = substr(s, 1, n - 3) "..."; return s }
function indent(s) { match(s, /^ */); return RLENGTH }
function flush_param() {
	if (pname == "") return
	if (ptype == "") fail(obj "." meth ": parameter " pname " has no type")
	if (preq == "true") preq = "y"; else if (preq == "false") preq = "n"
	body = body sprintf("P\t%s\t%s\t%s\t%s\t%s\n", pname, clean(ptype), clean(preq), clean(penum), cut(pdesc, 160))
	pname = ""; ptype = ""; preq = ""; penum = ""; pdesc = ""
}
function flush_method(   k, c, why) {
	if (meth == "") return
	flush_param()
	if (msum == "") fail(obj "." meth ": no summary")
	k = obj "." meth
	if (k in seen) fail(k ": documented twice")
	seen[k] = 1
	if (k in rclass) { c = rclass[k]; why = rwhy[k]; used[k] = 1 }
	else if (mdest) { c = "r"; why = "documented as destructive" }
	else if (meth ~ /^(remove_|clear_|uninstall)/) { c = "r"; why = "deletes what it names" }
	else if (meth ~ /^(get|check|load)_/) { c = "q"; why = "" }
	else { c = "a"; why = "" }
	n[c]++
	printf "M\t%s\t%s\t%s\t%s\t%s\n%s", obj, meth, c, why, clean(msum), body
	meth = ""; msum = ""; mdest = 0; body = ""; sect = ""
}
BEGIN { sq = sprintf("%c", 39) }
$1 == "R" {
	k = $3; rclass[k] = $2
	why = $0; sub(/^R [aqr] [^ ]+ ?/, "", why); rwhy[k] = why
	if (why == "") fail("rule for " k " has no reason")
	next
}
$1 == "F" { flush_method(); obj = ""; cat = ""; osum = ""; inmethods = 0; file = $2; next }
{
	line = substr($0, 3)
	if (line ~ /^[ \t]*$/) next
	ind = indent(line)
	# continuation of a block or multi-line scalar
	if (target != "" && ind > tind) {
		t = line; sub(/^ +/, "", t)
		if (target == "pdesc") pdesc = pdesc " " t
		next
	}
	target = ""
	if (!inmethods) {
		if (line ~ /^object:/) { obj = scalar(substr(line, 8)); next }
		if (line ~ /^category:/) { cat = scalar(substr(line, 10)); next }
		if (line ~ /^summary:/) { osum = scalar(substr(line, 9)); next }
		if (line ~ /^methods:/) {
			if (obj !~ /^[a-z0-9_-]+$/ || osum == "") fail(file ": no object name or summary")
			printf "O\t%s\t%s\t%s\n", obj, cat, clean(osum)
			nobj++; inmethods = 1
		}
		next
	}
	if (line ~ /^  - name:/) {
		flush_method()
		meth = scalar(substr(line, 10))
		if (meth !~ /^[a-z0-9_]+$/) fail(file ": method name " meth)
		next
	}
	if (ind == 4) {
		flush_param()
		key = line; sub(/^ +/, "", key); val = key; sub(/:.*/, "", key); sub(/^[^:]*: ?/, "", val)
		sect = key
		if (key == "summary") msum = scalar(val)
		else if (key == "destructive") mdest = (scalar(val) == "true")
		if (key != "params") { tind = 4; target = "skip" }
		next
	}
	if (sect != "params") next
	if (line ~ /^      - name:/) { flush_param(); pname = scalar(substr(line, 14)); next }
	if (ind == 8 && pname != "") {
		key = line; sub(/^ +/, "", key); val = key; sub(/:.*/, "", key); sub(/^[^:]*: ?/, "", val)
		if (key == "type") ptype = scalar(val)
		else if (key == "required") preq = scalar(val)
		else if (key == "enum") { penum = scalar(val); sub(/^\[ */, "", penum); sub(/ *\]$/, "", penum); gsub(/ *, */, "|", penum) }
		else if (key == "description") {
			if (val ~ /^[|>][-+]?[ \t]*$/) pdesc = ""; else pdesc = scalar(val)
			target = "pdesc"; tind = 8
		}
	}
}
END {
	if (bad) exit 1
	flush_method()
	for (k in rclass) if (!(k in used)) fail("rule names " k ", which the documentation does not have")
	printf "T\t%d\t%d\t%d\t%d\n", nobj, n["q"], n["a"], n["r"]
}' >"$tmp.body"

total=$(awk -F '\t' '$1 == "T" { printf "%d objects, %d methods: %d query, %d active, %d risky", $2, $3 + $4 + $5, $3, $4, $5 }' "$tmp.body")
[ -n "$total" ] || { echo "$0: nothing parsed" >&2; exit 1; }
if grep -n '[^ -~	]' "$tmp.body" >&2; then echo "$0: non-ASCII text left (lines above): add a replacement" >&2; exit 1; fi
if grep -q '^GLINET_CATALOG_END$' "$tmp.body"; then echo "$0: the data contains the heredoc marker" >&2; exit 1; fi

{
	cat <<EOF
# admin module data: the method catalog of glinet_api (server/60-admin-glinet.sh).
# GENERATED by scripts/glinet-methods.sh from github.com/admonstrator/glinet-api
# (commit $commit); do not edit, change the rules in that script and run it again.
# $total.
#
# Tab separated, one record per line:
#   O  object  category  summary
#   M  object  method  class  reason  summary      class: q query, a active, r risky
#   P  name  type  required  enum  description     parameters of the M line above;
#                                                  required: y, n or a condition
_ga_catalog() {
	cat <<'GLINET_CATALOG_END'
EOF
	grep -v '^T	' "$tmp.body"
	echo 'GLINET_CATALOG_END'
	echo '}'
} >"$tmp"

if [ "$out" = - ]; then
	cat "$tmp"
else
	cp "$tmp" "$out"
	echo "$out: $total (glinet-api $commit)" >&2
fi
