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
  - PEM private key blocks, WireGuard `PrivateKey =`/`PresharedKey =`, hostapd
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

Invalid numbers fall back to the default. Set by the server for every process of a call:
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

(server/30-files.sh, server/40-forensics.sh, server/50-audit.sh)

All eight tools are read-only. They compare with the firmware image at `MCP_ROM` by
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
| `auth.root_no_password` | high | empty password field of root |
| `auth.extra_uid0` | high | accounts with uid 0 besides root |
| `auth.ssh_password_from_wan` | high | SSH instance with password login whose port the WAN side reaches |
| `auth.ubus_without_login` | high | uhttpd `no_ubusauth=1` |
| `auth.empty_password` | medium | other login accounts with an empty password |
| `auth.account_added` | low | login accounts that are not in the image |
| `auth.authorized_keys` | low | every authorized key with its fingerprint |
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
not repeated for a rule.

`MCP_PROC` (default `/proc`) is where the process checks read exe links, environments
and the module list. It exists for the tests, because in an emulated container every
`/proc/PID/exe` points at the emulator; sockets always come from the real `/proc`.
