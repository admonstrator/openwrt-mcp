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
		if (pid != "-") { f = "/proc/" pid "/comm"; if ((getline comm < f) <= 0) comm = "-"; close(f) }
		print proto, state, la, hex(l[2]), ra, hex(r[2]), inode, pid, comm
	}'
}
