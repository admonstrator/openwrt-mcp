# Tools

Every tool the server offers, what it reads, its arguments and its limits.
Sections are numbered by module; each module's owner writes only its own section.

## 1 Core

`server_info`: version, protocol versions, trusted tools, redaction, limits, tool list.

## 2 Core and exec

(server/00-core.sh, server/90-exec.sh, bin/openwrt-mcp)

### Protocol

JSON-RPC 2.0, one message per line on stdin and stdout (MCP stdio transport). Methods:
`initialize`, `ping`, `tools/list`, `tools/call`; capability `tools` only.

- `initialize` answers with the client's `protocolVersion` when the server knows it
  (2025-11-25, 2025-06-18, 2025-03-26, 2024-11-05), otherwise with the newest.
- Errors: `-32700` the line is not JSON (id null); `-32600` a batch (array), a non-object,
  an id that is not a string or an integer of at most 15 digits (also `null`, fractions,
  exponents and bigger integers, which could not be echoed exactly; id null), no or
  non-string `method`,
  `jsonrpc` not `"2.0"`; `-32601` unknown method; `-32602` `params` not an object,
  `tools/call` without a string `name`, unknown tool.
- Notifications (no `id`) never get a reply, whatever the method; `notifications/cancelled`
  is accepted and ignored: requests are handled one at a time, the call timeout bounds
  each of them.
- Blank lines and a trailing CR are skipped. A 1 MB request line works (the shell reads
  it byte by byte: about a second under emulation, a few on a slow router).
- Requests are answered in order. On EOF the server answers what it has already read,
  then exits 0.
- Stdout carries only protocol messages: they go to fd 3 inside `mcp_main`; fd 1 points
  at stderr, and tool handlers get neither (their output goes to the result).

### Tool calls

- **Arguments** are checked against the tool's `inputSchema` before the handler runs:
  unknown names (when `additionalProperties` is false), JSON types (`string`, `integer`,
  `number`, `boolean`, `array`, `object`) and `required`. `null` counts as absent. A
  mismatch is a normal tool result with `isError: true` that names the argument and
  lists what the tool takes. `arg_int` ranges are checked by the handler, same way.
- **Work directory**: every handler starts in `$MCP_TMP/work`, which is emptied before
  every call; scratch files never carry over to the next call.
- **Output cap**: a handler writes into a FIFO; a reader (`cat` under a file size limit,
  so what it has read is on disk even when it is killed) keeps `MCP_MAX_OUTPUT` (default
  60000) bytes plus at most one 512-byte block. More than the cap and the call's process
  tree is killed and the text ends with `[output cut at N bytes and the tool was
  stopped; narrow the request or page with offset/limit where the tool has them]`.
  `isError` stays false. `/tmp` never holds more than the cap per call, whatever the
  tool prints.
- **Text cap**: the cap also holds for the text as sent: escaped, a control character
  takes 6 bytes (`\u0001`), an invalid byte 3 (U+FFFD), a newline, quote, backslash or
  tab 2. The text stops where its escaped form reaches `MCP_MAX_OUTPUT` bytes (on a
  whole character, at most 9 bytes over) and ends with `[output cut at N bytes of text
  (control characters and invalid bytes take more room escaped); ...]`, so a result line
  is never much longer than the cap.
- **Call timeout**: `MCP_CALL_TIMEOUT` (default 120 s) per call; for `exec` the limit is
  at least its `timeout` + 5 s. On timeout the call's process tree and every process
  that carries the call's `MCP_CALL_TAG` environment variable (children that daemonized
  and left the tree) are killed; the text ends with `[timeout: the call was stopped after
  N s ...]` and `isError` is true. The server keeps serving.
- **Background holders**: a process the call started in the background that keeps the
  output open does not block the reply: 2 s after the handler ends the reader stops; the
  text has everything printed until then and ends with `[a background process started
  by this call still holds its output open 2 s after the call ended; it keeps running,
  and what it prints from now on is not shown ...]`.
- **Text encoding**: every result is valid UTF-8 and the JSON line is valid JSON,
  whatever the tool printed. Invalid UTF-8 becomes U+FFFD (one per maximal invalid
  subpart, like Python's `errors="replace"`), NUL bytes are dropped, control characters
  and DEL are `\uXXXX` escapes (`\t`, `\r`, `\n` as such), one trailing newline is
  dropped. A multibyte character cut by the output cap is dropped, not replaced. Empty
  output reads `(no output)`. Without `hexdump` on the router the fallback turns every
  non-ASCII byte into `?`.
- `isError` is true when the handler returns non-zero (or `tool_error`), on invalid
  arguments and on timeout.

### Helpers (changed behaviour, same signatures)

- `run_timeout SECS CMD...`: the limit kills the whole process tree of CMD (stopped
  first with SIGSTOP until the set stops growing, then SIGKILL; found through
  `/proc/*/stat`, no `setsid` or `timeout` needed). Returns 124 only when the limit hit
  and something was killed (`_rt_fired=1`), otherwise CMD's own status. CMD's stdin is
  /dev/null. The watchdog never holds the caller's stdout, so `$(run_timeout ...)` and
  `run_timeout ... | awk` return when CMD ends. Whether the watchdog fired or was
  cancelled is decided by a lock directory in `$MCP_TMP` (`mkdir`, first one wins), not by
  signal timing; a cancelled watchdog is frozen and killed together with its `sleep`.
- `json_quote STRING` keeps a trailing newline of STRING (before, it was dropped);
  `json_str` still drops one trailing newline of its input.
- `rd` resolves the whole path (`readlink -f`): a link anywhere in it, also a directory
  link such as `/tmp/x -> /proc` in `/tmp/x/kmsg`, must not lead into `/proc`, `/sys` or
  `/dev` unless the path itself starts there (`rd /proc/cpuinfo` works), and the
  resolved file must be a regular file. `/proc/kmsg` and `trace_pipe` files (regular
  files that block) are always refused. Without `readlink -f` only the last component is
  checked, as before.
- `redact` masks, line by line:
  - names that contain `password`, `passwd`, `passphrase`, `secret`, `token`,
    `credential`, `psk`, `privatekey`, `presharedkey` or `pwd`, or have a word part
    `pass`, `pin`, `pin<N>`, `pincode`, `community`, `keys`, `r0kh`, `r1kh` or one ending
    in `key` (`key`, `key1`, `apikey`, `private_key`); `public_key`, `pubkey`, `keyid`,
    `key_mgmt`, `*PasswordAuth` stay readable. These names count in uci show
    (`pkg.section.option=value`), config files (`option`/`list`, e.g. acme's
    `list credentials 'CF_Token=...'`), `name=value` lines (hostapd, wpa_supplicant,
    shell, `export`; not when the value starts with `$` or a backtick) and pretty-printed
    JSON members (ubus);
  - shadow lines with any hash, also behind `!`/`*` (locked) and 13-character DES
    hashes (`name:<redacted hash, $6>:...`); a bare `!` or `*` is kept;
  - PEM private key blocks (also a whole block on one line, as in JSON text), WireGuard `PrivateKey =`/`PresharedKey =`, hostapd
    `r0kh=`/`r1kh=` (the last field, the key) and per-station PSK files
    (`[keyid=..] [vlanid=..] MAC PSK`);
  - command lines: `--name=value` and `--name value` for the secret names above, and on
    lines that run something from a bin directory also pppd style `password value`
    (`password`, `passwd`, `pass`, `secret`, `psk`, `key`, `pwd`, `token`). Single-letter
    options such as `-p` are left alone (`-p 22` is a port for dropbear and ssh).
  It decides on the line format only, not on file names: a bare base64 line (a
  WireGuard `privatekey` file) is not recognised; tools that show whole files decide by
  the file name.

### Environment knobs

| Variable | Default | Meaning |
| --- | --- | --- |
| `MCP_ROM` | `/rom` | firmware image root; when its `bin/busybox` runs, its applets go first in PATH (and its `usr/bin/jsonfilter`, when that works). The applet names come from the image's links to busybox in `bin`, `sbin`, `usr/bin`, `usr/sbin` (OpenWrt's busybox has no `--list`; it is used where it works). `server_info` shows `yes (/rom/bin/busybox, N applets)`, or `no (...)` when none were found |
| `MCP_UPPER` | `/overlay/upper` | overlay upper directory |
| `MCP_REDACT` | `1` | `0` turns masking of secrets off (launcher `--no-redact`) |
| `MCP_MAX_OUTPUT` | `60000` | bytes per result (launcher `--max-output`) |
| `MCP_CALL_TIMEOUT` | `120` | seconds per call (launcher `--call-timeout`) |
| `MCP_SELF_DELETE` | `0` | `1`: the script removes itself from /tmp at start (launcher sets it) |
| `MCP_DEBUG` | `0` | `1`: log requests to stderr |
| `MCP_ADMIN` | `0` | `1`: admin mode, the write tools of section 5 are registered (launcher `--admin`); any other value is `0` |

Invalid numbers fall back to the default. A module marks a tool with `mcp_own_timeout NAME` when its own integer `timeout` argument should raise the call limit to timeout + 5 s (`exec` and the write tools). Set by the server for every process of a call:
`MCP_CALL_TAG` (internal, for the timeout).

### `exec`

Runs one command with `sh -c` as root and returns stdout and stderr merged, then a last
line `[exit N]`, or `[timeout after N s]` (then `isError` is true and every process the
command started is killed). A non-zero exit status is not an error result. The output
is not redacted. Annotations: `readOnlyHint` false, `destructiveHint` true,
`openWorldHint` true; the description asks for user approval of every call, points to
the read-only tools, and warns not to run `netstat` on a device suspected of the
gl-helper infection.

| Argument | Type | Default | Meaning |
| --- | --- | --- | --- |
| `command` | string, required | | shell command line; stdin is /dev/null |
| `timeout` | integer 1–600 | 30 | seconds, then the process tree is killed |
| `trusted_tools` | boolean | true | true: the firmware busybox (`MCP_ROM`) first in PATH; false: the router's own PATH |
| `cwd` | string | `/` | working directory; a missing one is an error |

Background processes should redirect their output (`cmd >/dev/null 2>&1 &`); one that
keeps the output open gets the 2 s note above and keeps running.

### Launcher `bin/openwrt-mcp`

```
openwrt-mcp [options] [user@]HOST
  -p PORT              SSH port
  -i KEY               SSH identity file (a relative path is made absolute)
  -o OPTION            extra ssh -o option, repeatable; wins over the defaults
  --no-redact          MCP_REDACT=0
  --max-output N       MCP_MAX_OUTPUT=N
  --call-timeout N     MCP_CALL_TIMEOUT=N
  --admin              MCP_ADMIN=1, and the script includes server/NN-admin-*.sh
  --build FILE         write the joined server script to FILE and exit
  --print-config NAME  print "claude mcp add NAME -- <launcher> <options> HOST" and an
                       .mcp.json entry, and exit
```

- Bash, macOS and Linux; needs `ssh` (OpenSSH client) and `sha256sum` or `shasum`.
- One SSH login per start: the first connection is a ControlMaster (`ControlPersist=60`)
  on a socket in a private `mktemp -d` directory under `$TMPDIR` (or /tmp when that path
  is too long); it copies the server and the run goes over the same connection. On exit
  (EOF, SIGTERM, SIGHUP, SIGINT) the session is stopped, the master told to exit and the
  directory removed. If the launcher is killed hard, the master ends 60 s after the
  session.
- The copy goes to `/tmp/openwrt-mcp.<time>.<pid>.<random>.sh` with `umask 077; set -C`.
  The router runs `sha256sum` on it and starts it only when the hash matches; otherwise
  it deletes it and the launcher exits 1. The server starts with `MCP_SELF_DELETE=1` and
  removes the file at once. Router side needs only `sh`, `cat`, `sha256sum` (and `rm`).
- `BatchMode=yes`, `ConnectTimeout=15`, `ServerAliveInterval=30`, `LogLevel=ERROR`.
  When the login fails the launcher prints ssh's message and what to do: unknown or
  changed host key (log in once by hand), rejected key (install the public key, use
  `-i`), unreachable host. Exit status 1; usage errors 2.

## 3 System and network inventory

(server/10-system.sh, server/20-network.sh, server/05-lib.sh)

All tools are read-only and take their data from `/proc`, `/sys`, files and the optional
programs `ubus`, `uci`, `logread`, `dmesg`, `ip`, `iwinfo`, `wg`, `nft`, `iptables-save`,
`opkg`/`apk`. A missing source is reported as "not available" with the reason. Flags that
compare against the firmware image ("not in firmware image") are only set when `MCP_ROM`
looks like a firmware root (`lib_rom_ok`: has `etc/`, `bin/`, `usr/` or `lib/`); containers,
ext4 and initramfs images get a note instead of a flag on every file.

| Tool | Arguments (default) | Reads |
| --- | --- | --- |
| `system_info` | none | `/tmp/sysinfo/*`, `/etc/board.json`, `ubus call system board`, `/etc/openwrt_release`, `/etc/openwrt_version`, `/etc/glversion`, `/etc/version.type`, `uname`, `/proc/{cmdline,cpuinfo,uptime,loadavg,meminfo,mounts}`, `df`, `/etc/TZ`, uci `system` |
| `processes` | `filter` (""), `pid` (0 = list), `include_kernel_threads` (false), `max_results` (500) | `/proc/PID/{stat,status,cmdline,exe,maps}` via `lib_procs`; with `pid` also `fd`, `cwd`, `root`, `environ`, sockets |
| `services` | `filter` ("") | `/etc/init.d/*`, `/etc/rc.d`, `ubus call service list`, else the process list |
| `packages` | `filter` (""), `user_installed_only` (false), `audit` (false), `max_results` (1000) | `/usr/lib/opkg/status` or `/lib/apk/db/installed`, `/etc/apk/world`, the same files in `MCP_ROM`, `apk audit` |
| `logs` | `source` (syslog, kernel, file), `lines` (200, max 5000), `pattern` (ERE, ""), `file` ("") | `logread` (fallback `/tmp/log/messages`), `dmesg`, files under `/tmp/log` and `/var/log` |
| `kernel_modules` | none | `/proc/modules`, `/lib/modules/$(uname -r)`, `/proc/sys/kernel/tainted`, `/etc/modules.d`, `/etc/modules-boot.d` |
| `uci` | `package` (""), `changes` (false) | `uci show`, `uci changes`, else `/etc/config/*` |
| `network` | `section` (all, interfaces, routes, neighbors, dns, dhcp, wifi, vpn) | `ip addr/route/rule/neigh`, `/sys/class/net`, `ubus call network.interface dump`, resolv.conf files, uci `dhcp`, `/var/etc/dnsmasq.conf*`, hosts files, `/tmp/dhcp.leases`, `ubus call dhcp ipv6leases`, `iwinfo`, uci `wireless`, `wg show all`, VPN configs and processes |
| `connections` | `state` (listen, established, all), `include_unix` (false), `resolve_interfaces` (true), `conntrack` (false), `max_results` (500) | `lib_sockets` (`/proc/net/{tcp,udp,raw}*`), `/proc/net/unix`, `ip addr`, `/proc/sys/net/netfilter/nf_conntrack_{count,max}`, `/proc/net/nf_conntrack` |
| `firewall` | `raw` (false) | uci `firewall`, `/etc/firewall.user`, uci include paths, `/etc/nftables.d`, `/usr/share/nftables.d`, uci `upnpd`, miniupnpd leases, `nft list ruleset`, `iptables-save`, `ip6tables-save` |

Details and limits:

- `processes` lists one line per process with pid, ppid, user, state, RSS (kB), start time
  (local, `btime + starttime/100`), name, exe target and command line (cut at 300
  characters; `pid` shows all arguments). The server's own process tree is left out.
  Kernel threads are counted, listed only with `include_kernel_threads`. Flags:
  `exe-deleted`, `exe-memfd`, `exe-in-tmp` (`/tmp`, `/var`, `/dev`), `exe-overlay-only`
  (exe exists in the overlay upper dir and not in the image), `mapped-deleted:PATH`,
  `exec-mapping-in-tmp:PATH`, `exec-memfd-mapping:PATH`, `name-mismatch` (comm matches
  neither the exe nor the first three arguments), `fake-kthread-name` (a user process
  whose argv[0] is `[...]`). A legend explains only the flags that occur. The `pid` view
  masks environment variables whose name contains PASS, SECRET, TOKEN, KEY, PSK, AUTH,
  CRED, PRIVATE, COOKIE or SESSION and passes the rest through `redact`.
  Under qemu user emulation (the test containers) `/proc/PID/exe` is the emulator, so a
  deleted program shows as `mapped-deleted` rather than `exe-deleted`.
- `services`: running state comes from procd (`ubus call service list`); without ubus a
  service counts as running when a process runs a daemon path that the init script passes
  to `procd_set_param command` (variables such as `$PROG` resolved), or has its name.
  Flags: init script not in the image, rc.d entries that are not symlinks, point to a
  missing script or elsewhere, and procd services without an init script.
- `packages`: origin is `image`, `user` or `upgraded` when the image's package database
  is in `MCP_ROM`. Without it, opkg uses the most common `Installed-Time` as the image time
  (later than 10 minutes after it counts as user-installed, a heuristic); apk cannot tell
  and marks packages named in `/etc/apk/world` as REQ. Changed config files: opkg's
  `Conffiles` hashes are recomputed directly (`opkg list-changed-conffiles` would write a
  lock file); a conffile that is not a regular file or links into /proc, /sys or /dev is
  reported as `unreadable` and never opened. apk uses `apk audit --no-cache` (without
  `--no-cache` apk creates `/tmp/cache/apk`). `audit=true` runs `apk audit --system` (package files
  whose content changed); opkg has no file hashes and says so.
  Order: changed config files first, then the package list with the packages that did
  not come with the image on top, so a list cut by `max_results` or the output limit
  loses only image packages.
- `logs` passes every line through `redact`. `file` must resolve to a file under
  `/tmp/log` or `/var/log`.
- `kernel_modules` prints the taint and a "Flagged" section first, then the module
  list and the boot lists. `/proc/modules` lists only loadable modules, so a loaded
  module without a `.ko` under `/lib/modules/<release>` is flagged (loaded from elsewhere
  or deleted after loading); when that directory does not exist at all (containers) the
  check is skipped with a note. It also flags a loaded module whose `.ko` under `/lib/modules/<release>` is
  not in the image, and `/etc/modules.d` entries not in the image. Taint bits are decoded;
  `O` (out-of-tree) is normal on OpenWrt.
- `uci` never sets or commits. `package` may be `pkg` or `pkg.section[.option]`.
- `network` with the default `section=all` is a compact overview (about 12 KB on a router
  with 35 devices): one line per device with state, type, parent, bridge master and
  addresses; the netifd table; the main routing table (IPv6 without link-local routes)
  plus route counts per other table and the number of policy rules; neighbour counts per
  device; resolvers, dnsmasq upstreams and overrides (first 25); DHCPv4 leases (first 30);
  radios and SSIDs from uci (no keys); WireGuard interfaces with peer count and latest
  handshake, VPN processes and config paths. Each part names the section with the full
  details. `section=interfaces` prints `ip -d addr` when the `ip` supports `-d`
  (ip-full), else busybox `ip addr` with a note; `routes` prints
  `ip -4/-6 route show table all` and the rules. The netifd table falls back to uci `network` when ubus is not
  reachable. WireGuard: `wg show all` (keys shown as "(hidden)" by wg, then `redact`) and
  uci peers (proto wireguard, and GL.iNet's wgclient/wgserver) without private or
  preshared keys. dnsmasq config files are listed once by their real path (`/var` is a
  link to `/tmp`).
- `connections`: a listener is "all IPv4 addresses" (`0.0.0.0`), "all addresses" (`::`,
  dual stack unless v6only), "loopback only", "interface IF" (address found in `ip addr`)
  or "address on no interface". PID `-` means a kernel socket or an owner that is gone.
  Reachability ignores the firewall. Conntrack top lists are capped at 25 entries each.
- `firewall` prints what is exposed first (zones, forwardings, WAN-input accepts, port
  forwards, includes), then all rules, UPnP, custom rule files and the active ruleset.
  WAN zones are zones named `*wan*`, masquerading, or holding network
  `wan`. `iptables-save`/`ip6tables-save` run only when `/proc/net/ip_tables_names`
  (`ip6_tables_names`) lists tables: legacy iptables would otherwise load the table
  modules. "Rules accepting input from a WAN zone" are enabled or disabled `rule` sections
  with a WAN `src`, no `dest` and target ACCEPT. The ruleset is capped at 300 lines per
  command unless `raw=true`.

Helpers in `server/05-lib.sh` (for other modules): `lib_sockets` (unchanged format),
`lib_procs` (TSV: pid ppid uid state rss_kb start kthread comm exe cmdline),
`lib_fd_inodes` ("inode pid"); control characters in comm and cmdline are replaced
(`?` in comm, space in cmdline), so a name with a newline cannot split a record, `lib_uci_dump PKG` (TSV `S sec type` / `O sec opt value`,
not redacted), `lib_ubus OBJ METHOD` (only when the ubus socket exists, 10 s limit;
redirect its output to a file), `lib_rom_ok`, `lib_upper` (MCP_UPPER when it exists;
with the default MCP_UPPER also the upperdir of an overlay root mount, then
`/userdata/overlay/upper`; prints nothing and fails when there is none).

Command lines (process list and `pid` view, procd instances, daemon lines in `network`)
pass through `redact`; the `pid` view also masks the argument after `password`,
`secret`, `psk`, `key`, `token` style arguments and the value of `--password=...`
style arguments itself.

## 4 Files, forensics and audit

(server/30-files.sh, server/40-forensics.sh, server/45-glinet.sh, server/50-audit.sh)

All nine tools are read-only. They compare with the firmware image at `MCP_ROM` by
content (size first, SHA-256 when the sizes match), never by "is the path in the
overlay", so a bind mount over an image file shows up too. The image counts as usable
when it holds a system tree (`etc`, `bin`, `usr` or `lib`); without one every tool says
that it could not compare. The image column reads `same`, `CHANGED`, `meta` (same
content, other mode or owner), `new` (not in the image), `-` (not compared).

### read_file

Reads one file with paging. Arguments: `path` (required), `view` (`auto`, `text`, `hex`,
`strings`; auto shows text, or the first 256 bytes of a binary file as hex), `offset` and
`limit` (lines for text and strings: default 200, at most 2000; bytes for hex: default
512, at most 8192), `min_length` (strings, default 6), `line_numbers` (default true).
The header gives type, mode, owner, mtime, size and the image comparison.

- Refused: directories, FIFOs, sockets, device nodes, dangling links, links into `/proc`,
  `/sys` or `/dev`, and the kernel files that block (`/proc/kmsg`, `/proc/kcore`,
  `/proc/PID/mem`, `trace_pipe`, ...). Other `/proc` and `/sys` files are read once with
  a 5 s limit and at most 1 MB; `/proc/PID/exe` reads a running program even when its
  file was deleted.
- Redaction (while on): text passes through the core's `redact` and a second filter for
  `name=value`, `name: value`, JSON pairs, ppp `*-secrets` files and `password=` inside
  command lines. The raw views of a text file show the redacted text; the raw views of
  files that hold key material by name (`dropbear_*_host_key`, `*.key`, `*.pem`,
  `id_*`, `shadow`, ...) are refused. A private key block collapses to one line, so line
  numbers after it differ from the file.
- GL.iNet's device private key, `/proc/gl-hw-info/device_key` (any path ending in
  `/gl-hw-info/device_key`, by the name given and by what it resolves to), is refused in
  every view while redaction is on, text included: it need not be PEM, so the secret
  filter cannot be trusted with it. `file_hash` still hashes it.

### list_dir

Lists a directory: type, mode, owner, bytes, mtime, image column, path, link target.
Arguments: `path` (default `/`), `depth` (default 1, at most 6), `max_entries` (default
300, at most 2000), `compare_image` (default true). Sorted by path. Mount points are
listed but not entered; below `/proc`, `/sys` and `/dev` the depth is 1. At most 5000
entries are read per call.

### find_files

Searches by `name` (shell pattern; with a slash it matches the whole path), `type`
(`file`, `dir`, `symlink`, `char`, `block`, `fifo`, `socket`), `perm` (`suid`, `sgid`,
`world_writable`, `executable`), `modified_within_minutes`, `modified_before_minutes`,
`newer_than` (a reference file), `min_size`, `max_size` (bytes), `max_depth`. `path`
defaults to `/` plus `/tmp` when that is its own filesystem. Output like `list_dir`,
`order` `mtime` (newest first, default) or `path`, `max_results` default 200 (at most
2000), `compare_image` default true. Only the server's own temp directory is left out. It stays on the filesystem of each root, never
walks `/proc` or `/sys`, stops after 20000 matches or 40 s and says so.

### file_hash

A file that cannot be read gets "could not read" and never a hash. `paths` (1 to 50 absolute paths), `algorithm` (`sha256` default, `md5`; the images have no
`sha1sum`). Per file: hash, size, mode, mtime, owning package, and the comparison with
the same path in the image (same, DIFFERENT with the image's hash, different type, not
in the image). Refuses what `read_file` refuses; one refused path does not stop the rest.

### overlay_diff

Everything the overlay's upper directory adds, changes or deletes against the image.
The upper directory is `MCP_UPPER` when it exists; with the default value the `upperdir`
of the root mount and `/userdata/overlay/upper` (some GL.iNet models) are tried.
Arguments: `path` (subtree, default `/`), `status` (`all`, `added`, `changed`, `deleted`,
`unchanged`), `max_priority` (1 to 5), `offset`, `max_results` (default 200, at most
1000). Per entry: priority, status, type, mode, owner, bytes, mtime, path, and in
brackets the reason, what the image has instead, and the owning package with its
relation to the image (`image`, `upgraded old>new`, `added`, `removed`).

| Priority | Meaning |
| --- | --- |
| 1 | An image program or image init/hotplug script replaced after first boot, a setuid/setgid bit added, `/etc/ld.so.preload` |
| 2 | Programs and autostart entries that neither the image nor a package provides, authorized keys, deleted image programs |
| 3 | Files replaced by a package upgrade, changed data or configuration files of the image in program directories, account files, mode or owner changes, unowned data files, feeds |
| 4 | Files of packages installed after flashing, what the firmware wrote at first boot, links to image programs, services enabled or disabled, other configuration |
| 5 | Expected state: `/etc/config`, host keys, the package database, first-boot scripts that removed themselves, identical copies |

A program, as opposed to a data file next to programs, is a file with an execute bit, a
link, a code file by name (`.so`, `.ko`, `.lua`, `.uc`, `.sh`, `.js`, ...), anything below
`/lib/functions`, `/lib/netifd`, `/lib/preinit`, `/lib/upgrade`, `/usr/libexec`,
`/www/cgi-bin`, or an autostart location. Link targets are compared as resolved paths:
`busybox` in `/bin` and `/bin/busybox` are the same.

First boot: OpenWrt has no clock at its first boot; sysfixtime sets it to the newest file
below `/etc` of the image, and it runs from there until NTP answers. What the firmware's
own first-boot scripts write is therefore dated within minutes after that file. An entry
whose mtime and ctime both lie in the hour after the newest file of `$MCP_ROM/etc` counts
as written at first boot (priority 4, marked in the output). `touch` cannot set a ctime,
so back-dating the mtime does not move a file into the window; setting the system clock
back would, and the output says so. No window is used when the device's own clock still
stands inside it. `MCP_FIRSTBOOT_CTIME=0` judges by mtime alone; it exists for the tests,
which cannot create a file with an old ctime.

Limits: package ownership comes from the writable package database (opkg `.list` files
or apk's `installed`), so it lowers a priority but proves nothing, and the output says
so. Opaque directories are not detected (busybox cannot read `trusted.overlay.opaque`).
Directories that also exist in the image are not listed. At most 20000 entries per scan.

### persistence

Every place code starts from by itself or survives an upgrade, each entry marked against
the image. Arguments: `locations` (any of `cron`, `rc_local`, `init`, `inittab`,
`hotplug`, `uci_defaults`, `firewall`, `dnsmasq`, `profile`, `preload`, `modules`,
`sysupgrade`, `rpcd`, `luci`, `feeds`, `hosts`, `ssh_keys`; default all), `only_changed`
(default false), `max_lines` (active lines per file, default 40).

- Shown in full (active lines, comments skipped, redacted): cron, `rc.local` and
  `ld.so.preload` always; every other file only when it differs from the image.
- Named only: entries identical to the image (grouped per directory), and files that a
  package installed after flashing brought along.
- Also read: uci firewall includes and the dnsmasq `dhcpscript` (their files join the
  list wherever they live), uci dhcp options that hook or redirect, whether cron is
  enabled.
- cron also shows what actually runs: the crontab directory of every running `crond`
  (its `-c DIR`, also `-cDIR` and in clusters such as `-fc DIR`; busybox' default
  `/var/spool/cron/crontabs` without one, which OpenWrt links to `/etc/crontabs`).
  Command lines come from `MCP_PROC` (default `/proc`). A directory that resolves to
  `/etc/crontabs` is only named; a missing one is said; for any other (GL.iNet:
  `crond -f -c /tmp/gl_crontabs -l 7`) every file in it and in its `crontabs.d`
  subdirectory (not crond's `cron.update` marker) is listed with its active lines,
  redacted, before the files of `/etc/crontabs` and `/etc/cron.d`. Files on the RAM disk
  are marked `[RAM disk]`: something rebuilds them at every boot; the generator is not
  known, but the init scripts and `rc.local` that name the directory are listed as
  candidates. Without a running crond the section says that nothing runs.

### users_auth

No arguments. Accounts with uid, shell, password state (`EMPTY`, none, locked, or the
hash algorithm), date of the last password change and flags (`UID0`, `login-shell`,
`hash-in-passwd`, `not-in-image`); authorized keys of every account with type, bits,
OpenSSH SHA256 fingerprint, comment, options and whether the image has the key;
dropbear instances (enabled, port, interface, password login, root login) and active
`sshd_config` lines; listening SSH and web sockets; uhttpd listen addresses and
`no_ubusauth`; rpcd logins with the kind of password (never the value); on GL.iNet
firmware the firmware version and the login-related options of `oui-httpd` and
`glconfig`. It prints no secret, with or without redaction.

### audit

Arguments: `categories` (any of `exposure`, `auth`, `integrity`, `persistence`,
`updates`, `wifi`; default all), `min_severity` (`info`, `low`, `medium`, `high`;
default `info`). Output: a header (release, image, overlay, trusted tools, counts), the
findings by severity, then "Checked, nothing found" (check ids) and "Could not check"
(check id and reason). Each finding has a stable id, a confidence statement, evidence
lines (at most 25), why it matters and what to do.

| Check | Severity | Evidence |
| --- | --- | --- |
| `exposure.wan_input_accept` | high (medium when no WAN interface has an address) | WAN zone with `input=ACCEPT`, its devices, and the sockets it reaches |
| `exposure.wan_open_port` | medium | listening socket plus the uci rule that accepts its port from the WAN zone |
| `exposure.port_forward` | low | uci redirects from the WAN zone |
| `exposure.firewall_not_loaded` | low | no `fw4` table (nft) or no `zone_*` chains (iptables-save) |
| `exposure.gl_remote_terminal` | medium | GL.iNet: a running `rtty` process (command line redacted, its `-t` token masked), or GoodCloud enabled while rtty SSH or web access is on |
| `exposure.gl_cloud_bound` | low | GL.iNet: GoodCloud enabled and bound to an account (username, email, bind time, server) |
| `auth.root_no_password` | high | empty password field of root |
| `auth.extra_uid0` | high | accounts with uid 0 besides root |
| `auth.ssh_password_from_wan` | high | SSH instance with password login whose port the WAN side reaches |
| `auth.ubus_without_login` | high | uhttpd `no_ubusauth=1` |
| `auth.empty_password` | medium | other login accounts with an empty password |
| `auth.account_added` | low | login accounts that are not in the image |
| `auth.authorized_keys` | low | every authorized key with its fingerprint |
| `auth.gl_no_auth_methods` | high | GL.iNet: `object.method` pairs of the `no-auth-methods` sections of `/etc/config/oui-httpd` that the image's copy does not have (callable through the web API without login) |
| `auth.gl_admin_accounts` | medium | GL.iNet: accounts besides root in table `account` of `/etc/oui/oui.db` (read from a copy with `sqlite3 -readonly`; "Could not check" without sqlite3 or the database) |
| `auth.gl_console_login` | low | GL.iNet: `oui-httpd.main.console_disabled` off while the image has it on (login on the serial console) |
| `integrity.image_file_replaced` | high | overlay holds another version of an image program, written after first boot, no package upgrade explains it |
| `integrity.image_data_changed` | low | a data or configuration file of the image in a program directory differs, changed after first boot |
| `integrity.first_boot_changes` | info | files in program directories that the firmware wrote at first boot |
| `integrity.setuid_added` | high | setuid or setgid bit on an image program |
| `integrity.process_memfd` | high | process whose program is a memfd (exists only in memory) |
| `integrity.process_deleted_tmp_binary` | high | process whose program was deleted from `/tmp`, `/var`, `/dev/shm` |
| `integrity.ld_preload` | high with `LD_PRELOAD` in a process or on glibc, else medium | `/etc/ld.so.preload` lines, process environments; a preloaded library that equals its image copy (procd's `/lib/libsetlbf.so`) is not reported |
| `integrity.unowned_program` | medium | program in a system directory that neither the image nor a package provides |
| `integrity.tmp_executable` | medium with an ELF file, else low | executable ELF files and scripts with at least one command in `/tmp` and `/dev/shm`; executable data files are not listed |
| `integrity.process_tmp_binary` | medium | process running from the RAM disk |
| `integrity.process_deleted_binary` | medium | process whose program file is gone (elsewhere) |
| `integrity.process_not_from_image` | medium | process running a program that neither the image nor an added package provides |
| `integrity.kernel_module_not_in_image` | medium | loaded module without a `.ko` in the image |
| `integrity.mount_over_system_path` | medium | a mount on `/bin`, `/sbin`, `/lib`, `/usr`, `/www` or below, other than a read-only squashfs or erofs |
| `integrity.image_mount` | info | read-only squashfs or erofs mounted below those directories (firmware data partitions such as `/lib/firmware`) |
| `integrity.image_file_deleted` | low | whiteouts for image programs (not when the package was removed, not `/etc/rc.d` links of disabled services) |
| `integrity.package_upgrades` | info | image files replaced by a package upgrade, counted per package |
| `persistence.image_script_changed` | high | image init, hotplug, inittab, rpcd or LuCI script that differs from the image, changed after first boot |
| `persistence.autostart_added` | medium | autostart file that neither the image nor a package provides (not dnsmasq files, not `.nft` files, not first-boot files) |
| `persistence.autostart_link` | medium | an autostart file (cron, `rc.local`, init, hooks, profile) that is a link resolving into `/tmp`, `/var`, `/run` or `/dev/shm` |
| `persistence.module_autoload` | medium | new or changed files in `/etc/modules.d` and `/etc/modules-boot.d` that no package owns, with the modules they load |
| `persistence.dnsmasq_hook` | medium | `dhcp-script`, `dhcp-luascript` or `conf-script` in a dnsmasq file that differs from the image, or uci `dhcpscript`, naming a program that is not an unchanged image file |
| `persistence.firewall_rules_added` | low | `.nft` rule files that neither the image nor a package provides |
| `persistence.first_boot_changes` | info | startup scripts that the firmware wrote at first boot |
| `persistence.user_autostart` | low; medium when a line downloads, pipes into a shell or uses the RAM disk | active lines of cron files (not crond's `cron.update`), `rc.local`, changed profile and firewall scripts |
| `persistence.feeds_changed` | low | package feeds or keys that differ from the image |
| `persistence.live_crontab` | medium when a line runs a program from the RAM disk, names one that does not exist, downloads, pipes into a shell or gives a network tool (`nc`, `ncat`, `socat`, `telnet`, also through busybox) a program to run; else low | active lines of the crontabs the running crond reads outside `/etc/crontabs` (GL.iNet: `/tmp/gl_crontabs`) that are not fully judged firmware jobs: a program that is not an unchanged image file (not in the image, changed, a shell expansion), or a command that runs another program through a shell, `eval`, `exec`, `nice`, `nohup`, `timeout`, `env`, `xargs`, `setsid`, `start-stop-daemon`, `flock`, `busybox APPLET`, `su`, `chroot`, `find -exec` and the like, or command substitution; each with the reason |
| `persistence.live_crontab_firmware` | info | the other lines of those crontabs: every command is simple and runs an unchanged image file, a plain shell builtin or a function of an image file the line sources (GL.iNet's own jobs) |
| `persistence.package_autostart` | info | autostart files of packages installed after flashing |
| `updates.branch_eol` | medium (low on GL.iNet firmware) | `DISTRIB_RELEASE` on a branch in the built-in end-of-life list (17.01 to 23.05, as of 2026-11) |
| `updates.firmware_age` | low | release file of the image older than 365 days |
| `wifi.wep` | high | enabled interface with WEP |
| `wifi.open_network` | medium | enabled access point without encryption |
| `wifi.wpa1` | medium for WPA1 only, low for mixed or TKIP | `psk`, `wpa`, `psk-mixed`, `wpa-mixed`, TKIP-only |
| `wifi.wps` | medium for PIN, low for push button | `wps_label`, `wps_pin`, `wps_pushbutton` |
| `wifi.open_uplink` | low | client interface on an unencrypted network |

How far the exposure check reasons: it reads the zones, rules and redirects from
`/etc/config/firewall`. A zone faces the internet when it holds the network `wan` or
`wan6` (or is named so) or when one of its devices carries the default route;
masquerading alone does not make a WAN zone, so VPN and Tailscale zones with
`input=ACCEPT` are not reported. The devices of a zone come from netifd (`l3_device`),
uci and the zone's `device` option. A socket from `/proc` counts as reachable from a zone
when it is bound to all addresses or to an address on one of the zone's devices. The
loaded nft or iptables ruleset is not evaluated rule by rule, so custom includes can open
or close more; the finding's confidence line says so. The stock rules for the DHCP
clients (udp 68, 546) are not reported.

The process checks leave out the server itself and everything its tool calls started
(`MCP_CALL_TAG` of this server in the environment), and treat a program below `$MCP_ROM`
as part of the image. Content checks read autostart files through links (never links
into `/proc`, `/sys`, `/dev`).

Limits that are said, not hidden: the overlay scan stops after 20000 entries and each
persistence location after 500; when either happens, `audit` lists it under "Could not
check", and `overlay_diff` and `persistence` print a note. When no zone can be identified
as the WAN side, the exposure checks are listed as not checked; when the default route
leaves through the zone of the network `lan` (access point or client mode), that zone is
not treated as WAN and the audit says that exposure to the upstream network was not
assessed.

Each thing is reported by one check: autostart locations belong to the persistence
checks, so the integrity checks skip them, and a socket the zone policy already opens is
not repeated for a rule. A line of a live crontab that also stands in a file of
`/etc/crontabs` is left to `persistence.user_autostart`. The live-crontab check judges a
line by the programs it runs: the first word of every command (after `.` or `source`
the file read, after `sh`, `lua` and other interpreters the script), bare names looked
up in `/usr/sbin`, `/usr/bin`, `/sbin`, `/bin`; a name that a sourced file defines as a
function counts as that file. Only a line whose every command is simple and judged that
way is a firmware job (info). A command whose first word runs something else (a shell or
interpreter, `eval`, `exec`, `command`, `trap`, `nice`, `nohup`, `timeout`, `env`,
`xargs`, `setsid`, `start-stop-daemon`, `flock`, `busybox APPLET`, `su`, `sudo`,
`chroot`, `time`, `ionice`, `taskset`, `watch`, `nsenter`, `unshare`, `ssh`, `find` with
`-exec`), command substitution (`$(...)`, backticks), and a network tool with a program
to run make it a `persistence.live_crontab` finding with the reason; the program run
that way is not judged. Other arguments are not judged either (`awk` calling
`system()`, for one, is not seen).

The GL.iNet checks need `/etc/glversion`; on other firmware they are listed under "Could
not check". They read uci, files and `/proc` (decision 2.5), compare `oui-httpd` with the
image's copy, and leave out the server's own processes.

`MCP_PROC` (default `/proc`) is where the process checks read exe links, environments
and the module list, and where `persistence`, `glinet` and the GL.iNet and live-crontab
checks find crond, rtty and gl-cloud by their `comm` and read `gl-hw-info`. It exists for the tests, because in an emulated container every
`/proc/PID/exe` points at the emulator; sockets always come from the real `/proc`.

### glinet

No arguments. On GL.iNet firmware (4.x, recognised by `/etc/glversion`) it shows what the
vendor firmware has switched on that reaches the router from outside, reports to outside
or controls access to it. Elsewhere it prints one line: not GL.iNet firmware, no
`/etc/glversion`.

Everything comes from uci (`lib_uci_dump`), files and `/proc`; the GL web API is never
called (decision 2.5: some get methods have side effects). `/proc/gl-hw-info` is read
below `MCP_PROC`; its `device_key`, `device_cert` and `device_sn` are never read. Options
are printed as `uci show` lines through `redact`; tokens (`gl-cloud` token) are only
reported as present. A package that is missing gives one line `<thing> (<package>): not
installed`. Sections, most important first, so that the output cap cuts only the tail:

1. Remote management: GoodCloud (`gl-cloud`: enable, server, binding with username,
   email, bindtime, bindtype, token present or not) and whether a `gl-cloud` process
   runs; the remote terminal `rtty` (`general.ssh_en`, `web_en`, the process with its
   command line, `-t` token masked) and a warning when GoodCloud and rtty access are both
   on; AstroWarp (`mptun.global`); GL DDNS (`gl_ddns`) and the device DDNS name from
   `gl-hw-info/device_ddns`.
2. Admin access: the options of `oui-httpd.main`, each with the image's value where it
   differs (from `$MCP_ROM/etc/config/oui-httpd`), `console_disabled` explained; the
   methods callable without login (`no-auth-methods` sections), each marked `[image]`,
   `[ADDED]` or `[-]` (no image), ADDED first, at most 60 per object and 40 lines;
   the `listen` lines of `/etc/nginx/conf.d/gl.conf`; web admin accounts from table
   `account` of `/etc/oui/oui.db` (copied below `MCP_TMP`, opened with `sqlite3
   -readonly`; "sqlite3: not available" otherwise); the `wan-access` whitelist; the
   firewall rules and redirects GL writes for WAN access to the router and DMZ
   (`ping_wan`, `https_wan`, `ssh_wan` and IPv6 twins, `GL-*`, DMZ) with src, port,
   target and enabled, at most 40.
3. VPN servers and mesh VPNs: WireGuard server (`wireguard_server.main_server`, peer
   count and names, interface `wgserver`), OpenVPN server (`ovpnserver`, and the number of
   lines in `/etc/openvpn/cert/user_passwd.txt`, never its content), Tailscale, ZeroTier,
   Tor, site-to-site WireGuard (`gl_s2s`).
4. Sharing: NAS (`nas`, WebDAV and service ports), Samba shares (name, path, guest ok,
   read only; at most 30), GL's WAN rules for sharing (`sambasharewan`, `glnas_ser`,
   `webdav_wan`), DLNA (`minidlna`).
5. Firmware and updates: version and type (`/etc/glversion`, `/etc/version.type`), model,
   country code, flash size, the `upgrade` settings (`gray_url` is the beta channel);
   plugin feeds are left to `persistence locations=["feeds"]`.

## 5 Admin mode: write tools

(server/60-admin-glinet.sh with its generated catalog server/61-admin-glinet-catalog.sh
from scripts/glinet-methods.sh, server/65-admin-uci.sh; core support in
server/00-core.sh, server/05-lib.sh, bin/openwrt-mcp)

Only with launcher `--admin` (`MCP_ADMIN=1`): the script then includes the modules
`server/NN-admin-*.sh`, and their tools are registered with `mcp_register_admin`.
Without it the server is the read-only one of sections 1 to 4, and a call to a write
tool is "Unknown tool". Register the admin server as its own MCP server (for example
`router-admin`), so the read-only one keeps its permissions. In admin mode
`initialize` says so in its instructions (read first, one change at a time, `confirm`
only after the user agreed), `serverInfo.title` is `OpenWrt (admin)` and `server_info`
prints `mode admin (write tools on)`.

Write tools report what they changed in `/etc/config`: `lib_cfg_snapshot DIR` records
`uci show` of every package before the change, `lib_cfg_changes DIR [MAX]` prints per
changed package `config PKG: N removed, M added` and the lines (`- ` before, `+ ` after,
at most MAX, default 60), redacted, or `no change in /etc/config`. Lines are compared as
a multiset: a renumbered anonymous section shows up as removed plus added.

### glinet_api

(server/60-admin-glinet.sh; catalog in server/61-admin-glinet-catalog.sh, generated by
scripts/glinet-methods.sh)

Calls one method of the GL.iNet web API on the router itself, or lists what can be
called. GL.iNet firmware 4.x only: without `/etc/glversion` and
`/usr/lib/oui-httpd/rpc` every call is an error that says so and points to `uci_change`
and `service_control`.

The call is `ubus call gl-session call '{"module":OBJECT,"func":METHOD,"params":{...}}'`:
`gl-ngx-session` passes it to the web API on 127.0.0.1, which needs no session for a
local caller. The firmware's validators and service reloads apply as for the web
interface, and the firmware writes every call whose method name contains none of `get`,
`load`, `check` to the system log. The
`ubus` program is the firmware image's (`/rom/bin/ubus`) when the image has one, else the
one in `PATH`; there is no environment variable that points the tool elsewhere.

| Argument | Type | Default | Meaning |
| --- | --- | --- | --- |
| `object` | string | | API object (module), e.g. `wifi`. Letters, digits, `-`, `_`. |
| `method` | string | | Method, e.g. `get_config`. With it the call is made; without it the tool only lists. |
| `params` | object | `{}` | The method's parameters, passed on unchanged. |
| `confirm` | boolean | false | Needed to run a method of class CONFIRM. |
| `search` | string | | Listing only: keyword filter (ASCII, case ignored). |
| `timeout` | integer | 30 | Seconds to wait for the answer, 1 to 600; the call limit is at least this plus 5 s. |

**Listing** (no `method`; nothing is called):

- no arguments: the firmware version, whether `gl-session` answers, `== API objects on
  this router (N)` with one line per object in `/usr/lib/oui-httpd/rpc` (file names
  without `.so`/`.lua`): `OBJECT  (N query, N active, N confirm)  summary`, or `OBJECT
  (not in the catalog: methods unknown)`; then `== In the catalog, not on this router
  (N)` as one comma-separated line. When the directory cannot be listed, all catalog
  objects are shown under `== API objects in the catalog (N)`.
- `object`: `== OBJECT (category: summary), on this router` and per method
  `OBJECT.METHOD  [query|active|CONFIRM]  summary`, then indented `confirm needed: why`
  or `note: why` and one line per parameter: `name (type, required|optional|required
  if ...; one of a|b): description`. Nested fields are written `rules[].ip`.
- `search` (with or without `object`): the methods whose object, name, summary, reason
  or parameter names contain the text; without `object` one line per method, with
  `(not on this router)` where that applies.

**The catalog** holds 52 objects and 368 methods from the API documentation
(github.com/admonstrator/glinet-api, GL-E5800, firmware 4.8.5): per method the summary,
a class, the reason for the class and the parameters (name, type, required, enum, the
description cut at 160 characters), ASCII only, about 105 kB of the admin script. It is
generated, never edited: `scripts/glinet-methods.sh /path/to/glinet-api` (POSIX sh and
awk) rewrites `server/61-admin-glinet-catalog.sh`; the same documentation gives the same
bytes, and the file names the documentation commit. The class of a method is, in this
order:

1. the rules table in the script (exact `object.method`, with the reason shown to the
   model);
2. `destructive: true` in the documentation: CONFIRM;
3. a name starting with `remove_`, `clear_` or `uninstall`: CONFIRM (it deletes);
4. a name starting with `get_`, `check_` or `load_`: query;
5. everything else: active.

The rules table makes active what is named like a query but is none (18 methods:
`tailscale.get_auth_url` restarts Tailscale, `ddns.get_status`,
`upgrade.check_firmware_online`, `ui.get_remote_langs` and others go to the internet,
`*.check_config` unpack uploads), and makes CONFIRM what the documentation does not mark
destructive but that can change who controls the router or whether the user still
reaches it: GoodCloud (`cloud.set_config`, `bind_device`, `rebind`, `unbind`,
`bind_info`), rtty, web accounts (`acl.add_user`, `add_acl`); openings towards the WAN
(`firewall.set_wan_access`, `set_dmz`, `add_rule`, `set_rule`, `add_port_forward`,
`set_port_forward`, NAS sharing, starting or re-keying a VPN server, new VPN peers and
logins, `tailscale.set_config`, `zerotier.set_config`, site-to-site); the user's own way
in and the uplink (`wifi.set_config`, `wifi.set_mlo_config`, `timer.set_wifi`,
`black_white_list.set_single_mac`, `cable.set_config`, `cable.set_port_config`,
`edgerouter.set_config`, disconnecting repeater, modem or tethering, `tailscale.logout`,
`wg-server.stop`, the VPN client's kill switch, default tunnel and global mode,
`lpm.set_config`); software and feeds (`plugins.install_package`, `plugins.set_config`,
`luci.install_luci`); credentials, money and third parties (`nas-web.set_user_pwd`,
`screen.set_config`, `modem.set_sim_pin_code`, `modem.send_sms`, SMS forwarding,
`wg_client.create_provider_account`). In all: 140 query, 129 active, 99 CONFIRM. A rule
that names a method the documentation no longer has stops the generator.

**A call** (`object` and `method`) goes through these checks; the first that fails ends
it with `isError` and nothing sent to the API:

1. `object` is not in `/usr/lib/oui-httpd/rpc` (when that can be listed):
   `OBJECT.METHOD: not called. This router has no API object ...`.
2. Class CONFIRM without `confirm: true`: `OBJECT.METHOD: NOT CALLED, it needs
   confirmation. Nothing was changed.`, then `What it does:`, `Why confirmation:`, what
   to ask the user and to send the same call again with `"confirm": true`, and the
   method's parameters. A method the catalog does not have is treated as CONFIRM
   unless its name starts with `get_`, `check_` or `load_`; then it runs as active, with
   a `note:` line. (`reset_target` contains "get" and still needs confirm: the name
   must start with the word.)
3. An active or CONFIRM method with documented required top-level parameters, called
   with empty `params`: `NOT CALLED, params is empty but the method has required
   parameters`, then the parameters. This also answers "what does this method take".
4. `ubus` missing or no `gl-session` object: `not called. ... the web API cannot be
   reached: ...`.
5. A request of more than 100000 bytes.

The result starts with one status line:

- `OBJECT.METHOD: ok`; plus `but the answer carries err_msg: ...` when the result holds
  one (some methods report errors inside the result).
- `OBJECT.METHOD: GL API ERROR CODE: MESSAGE` (`isError`). For `-32602`: the validator
  rejected the params, nothing was changed, followed by the documented parameters; for
  `-32601`: the firmware has no such method; other codes of a changing method: it may
  have applied part of the change.
- `OBJECT.METHOD: NO ANSWER after N s (timeout)` (`isError`): `ubus` and its children
  are stopped, the router may still be working on the call.
- `OBJECT.METHOD: the ubus call failed (exit N): ...` (`isError`).

Then, for every call that is not a query, `== Config changes (/etc/config, right after
the call; ...)` with the output of `lib_cfg_changes` (also after an error or a
timeout), and last `== Answer`: the reply as `ubus` printed it, masked. Status and
changes come first, so the output cap cuts only the answer.

**Secrets**: with redaction on, the values of answer members named like secrets are
replaced by `"<redacted>"` whatever their JSON type (also a whole object or array):
names containing `password`, `passwd`, `pwd`, `passphrase`, `passcode`, `secret`,
`credential`, `private_key`, `preshared_key`; names ending in `key`, `psk`, `pass`,
`token`, `sid` as a word; `pin`, `puk`, `pin_code`, `puk_code`. Not masked: `public_key`
and booleans (`presharedkey_enable`). Inside longer strings (a WireGuard or OpenVPN client config)
`PrivateKey = ` and `PresharedKey = ` values and PEM private key blocks (`<redacted
private key>`) are masked, and so are the members with such names in JSON text that
sits inside a string (`\"password\":\"...\"`). The core `redact` runs after that. A client config with its
keys can therefore only be fetched with `--no-redact` or in the web interface. The
params of a call are never printed back.

Limits: the catalog describes one model and firmware; fields and methods of other
versions differ, and the router's answer decides. The config report sees `/etc/config`
only (not `/etc/oui/oui.db`, key files, the modem) and only what is written by the time
the call returns; a method that applies its change in the background shows up on the
next read. Calls are handled one at a time, as every request of this server; nothing
stops the web interface from changing things at the same moment. A call that drops the
SSH connection (LAN address, SSH port, reboot) ends the server before the result
arrives.

### uci_change and service_control

(server/65-admin-uci.sh; any OpenWrt, admin mode only.) Annotations of both:
`readOnlyHint` false, `destructiveHint` true, `openWorldHint` false; both bring their own
`timeout` (`mcp_own_timeout`), so the call limit is at least `timeout` + 5 s.

#### `uci_change`

Applies a list of uci operations to one package in `/etc/config`, commits it and lets
procd reload what depends on it.

| Argument | Type | Default | Meaning |
| --- | --- | --- | --- |
| `package` | string, required | | file name in `/etc/config`: letters, digits, `_`, `-`, not starting with `-`; the file must exist |
| `changes` | array, required | | 1 to 100 operations `{"op", "path", "value"}`, applied in order |
| `dry_run` | boolean | false | only show what would change; nothing is written |
| `reload` | boolean | true | after the commit, let procd reload the services whose configuration changed |
| `confirm` | boolean | false | needed for risky changes (below), set only after the user agreed |
| `timeout` | integer 1–300 | 30 | seconds for the reload step (`reload_config`) |

Operations (`path` is relative to the package; a section is a name of letters, digits
and `_`, or `@type[N]` with N up to 4 digits, negative counts from the end, so
`@rule[-1]` is a rule an earlier `add` created):

| `op` | `path` | `value` | uci command |
| --- | --- | --- | --- |
| `set` | `section.option` | the value | `uci set pkg.section.option=value` |
| `set` | `section` | section type | creates a named section (`uci set pkg.section=type`) |
| `delete` | `section.option` or `section` | none | `uci delete`; a whole section is risky |
| `add_list` | `section.option` | one element | `uci add_list` |
| `del_list` | `section.option` | one element | `uci del_list` (an element that is not there is no error, as in uci) |
| `add` | none | section type | `uci add pkg type`; the result names the new section (`cfgXXXXXX`) |

Order of work:

1. **Validation** of every operation (op, path syntax, `value` present exactly where
   needed and a JSON string, no members other than `op`, `path`, `value`). Values are
   passed to uci as one argv word each, never through the shell: spaces, quotes, `;`,
   `$()`, backticks arrive literally. A value with a line break (`\n`, `\r`) is refused:
   uci would store it, but `uci show`, `reload_config` and every line-based reader
   (including this server's) would misread it.
2. **Risk check.** Without `confirm: true` a real run is refused with an error that names
   the risk, shows the plan and asks to get the user's agreement and resend with
   `confirm: true`. Risky: every change to the packages `network`, `firewall`,
   `wireless`, `dropbear`, `uhttpd`, `nginx`, `rpcd`, `oui-httpd`, `wan-access`, `rtty`,
   `glconfig`, `tailscale`, `zerotier` (they can cut off access to the router or expose
   it); a change of `system` option `ttylogin` (login on the serial console); every
   `delete` of a whole section, in any package. A dry run needs no confirm and lists the
   risk under `== Risk`.
3. **Uncommitted changes** of someone else in the package (`uci changes PKG` not empty):
   a real run is refused and lists them (redacted), because the commit would apply them
   too. A dry run works and lists them as a warning.
4. **Private copy.** The package file is copied below the call's work directory and every
   operation runs there first (`uci -c COPY -t SAVE`, on 25.12 also `-C` with an empty
   override directory). If uci refuses one (missing section, bad index), the result is
   `invalid operation, nothing was changed: change N (op): uci refused it: ...` and
   nothing in `/etc/config` or `/tmp/.uci` was touched.
5. **Dry run** stops here: `== Dry run: lines that would change (nothing was written)`
   with `config PKG: N removed, M added` and the `uci show` lines (`  - ` before,
   `  + ` after, redacted, at most 200).
6. **Real run**: `lib_cfg_snapshot`, the operations with uci (if one fails now, `uci
   revert PKG` and an error: nothing committed), `uci commit PKG`, then the reload:
   - procd not answering on ubus (no socket, as in containers): `NOT APPLIED: the change
     is committed ... but no service was reloaded`;
   - `reload_config` present and `/var/run/config.md5` there (written at boot): it runs
     under `timeout`; procd reloads every service whose configuration changed since the
     last `reload_config`, in the background;
   - otherwise (no `reload_config`, or no md5 file to compare against) the server sends
     procd the `config.change` event for the package itself (`ubus call service event`),
     which is what `reload_config` does per changed package.
   `reload: false` commits only and says so.

Output: `== Plan: N operation(s) on /etc/config/PKG` (one line per operation, `N op
pkg.path='value'`, redacted), then for a real run `== Applied` (`committed ...`, new
section names), `== Reload` (`reload_config`, `procd/ubus`, `result` lines) and `== Changes
in /etc/config` (`lib_cfg_changes`, at most 200 lines per package). On GL.iNet firmware
(`/etc/glversion`) a last `== Note` says that `glinet_api` keeps the GL web UI in sync and
that GL services may overwrite or ignore direct uci edits of GL-managed packages.

Limits: no rollback timer (unlike LuCI's apply/confirm): a change that cuts the SSH
connection stays committed, which is why such packages need `confirm`. Only existing
packages; `rename` and `reorder` are not offered.

#### `service_control`

| Argument | Type | Default | Meaning |
| --- | --- | --- | --- |
| `service` | string, required | | script name in `/etc/init.d` (letters, digits, `_ . -`, not starting with `.` or `-`, no path); it must be a regular file |
| `action` | string, required | | `status`, `start`, `stop`, `restart`, `reload`, `enable`, `disable` |
| `confirm` | boolean | false | needed for risky actions |
| `timeout` | integer 1–300 | 30 | seconds, then the init script and everything it started in the foreground are killed |

- `status` reads only: `enabled  yes (/etc/rc.d/S..NAME)` or `no`, and `running` from
  procd (`ubus call service list`): number of running instances, `no`, or `unknown
  (ubus or procd not available)`.
- Other actions run `/etc/init.d/NAME ACTION` from `/` with stdin `/dev/null` and print
  its output (redacted, at most 200 lines), `[exit N]` (a non-zero exit is not an error
  result) or `[timeout after N s]` (error result), then `== Status of NAME`. The script
  runs without the call's `MCP_CALL_TAG`, so daemons it starts outside procd are not
  killed with the call and are not hidden from `audit`.
- Risky (need `confirm: true`): `stop`, `restart`, `disable` of `network`, `firewall`,
  `dropbear`, `sshd`, `uhttpd`, `nginx`, `rpcd`, `ubus`, `odhcpd`, `dnsmasq`,
  `gl-ngx-session`, `wpad`, `hostapd`, `tailscale`, `zerotier`, `openvpn`.
- Refused for every action but `status`: `boot`, `done`, `umount`, `sysfixtime` (they
  run only at boot or shutdown; `umount` unmounts the filesystems, disabling `boot`
  breaks the next boot). `sysntpd` is an ordinary daemon and allowed.

