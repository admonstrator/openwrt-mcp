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
  an id that is not a string or a number (also `null`; id null), no or non-string `method`,
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
- **Output cap**: a handler writes into a FIFO; a reader keeps at most `MCP_MAX_OUTPUT`
  (default 60000) bytes. One byte more and the call's process tree is killed and the
  text ends with `[output cut at N bytes and the tool was stopped; narrow the request or
  page with offset/limit where the tool has them]`. `isError` stays false. `/tmp` never
  holds more than the cap per call, whatever the tool prints.
- **Call timeout**: `MCP_CALL_TIMEOUT` (default 120 s) per call; for `exec` the limit is
  at least its `timeout` + 5 s. On timeout the call's process tree and every process
  that carries the call's `MCP_CALL_TAG` environment variable (children that daemonized
  and left the tree) are killed; the text ends with `[timeout: the call was stopped after
  N s ...]` and `isError` is true. The server keeps serving.
- **Background holders**: a process the call started in the background that keeps the
  output open does not block the reply: 2 s after the handler ends the reader stops and
  the text ends with a note saying so. The process itself keeps running.
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
  (`_rt_fired=1`), otherwise CMD's own status. CMD's stdin is /dev/null.
- `json_quote STRING` keeps a trailing newline of STRING (before, it was dropped);
  `json_str` still drops one trailing newline of its input.
- `rd` also refuses `/proc/kmsg` and `trace_pipe` files (regular files that block).
- `redact` also masks hostapd/wpa_supplicant lines (`wpa_passphrase=`, `wpa_psk=`,
  `sae_password=`, `psk=`, `password=`, `private_key_passwd=`) and pretty-printed JSON
  members such as `"key": "..."` (ubus output).

### Environment knobs

| Variable | Default | Meaning |
| --- | --- | --- |
| `MCP_ROM` | `/rom` | firmware image root; when its `bin/busybox` runs, every applet of it (and its `usr/bin/jsonfilter`, when that works) goes first in PATH: `server_info` shows it as trusted tools |
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
looks like a firmware root (`lib_rom_ok`: has `etc/` and `bin/` or `usr/`); containers,
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
  lock file); apk uses `apk audit`. `audit=true` runs `apk audit --system` (package files
  whose content changed); opkg has no file hashes and says so.
- `logs` passes every line through `redact`. `file` must resolve to a file under
  `/tmp/log` or `/var/log`.
- `kernel_modules` flags a loaded module whose `.ko` under `/lib/modules/<release>` is
  not in the image, and `/etc/modules.d` entries not in the image. Taint bits are decoded;
  `O` (out-of-tree) is normal on OpenWrt.
- `uci` never sets or commits. `package` may be `pkg` or `pkg.section[.option]`.
- `network` prints `ip -d addr` when the `ip` supports `-d` (ip-full), else busybox
  `ip addr` with a note. The netifd table falls back to uci `network` when ubus is not
  reachable. WireGuard: `wg show all` (keys shown as "(hidden)" by wg, then `redact`) and
  uci peers without private or preshared keys.
- `connections`: a listener is "all IPv4 addresses" (`0.0.0.0`), "all addresses" (`::`,
  dual stack unless v6only), "loopback only", "interface IF" (address found in `ip addr`)
  or "address on no interface". PID `-` means a kernel socket or an owner that is gone.
  Reachability ignores the firewall. Conntrack top lists are capped at 25 entries each.
- `firewall`: WAN zones are zones named `*wan*`, masquerading, or holding network
  `wan`. "Rules accepting input from a WAN zone" are enabled or disabled `rule` sections
  with a WAN `src`, no `dest` and target ACCEPT. The ruleset is capped at 300 lines per
  command unless `raw=true`.

Helpers in `server/05-lib.sh` (for other modules): `lib_sockets` (unchanged format),
`lib_procs` (TSV: pid ppid uid state rss_kb start kthread comm exe cmdline),
`lib_fd_inodes` ("inode pid"), `lib_uci_dump PKG` (TSV `S sec type` / `O sec opt value`,
not redacted), `lib_ubus OBJ METHOD` (only when the ubus socket exists, 10 s limit;
redirect its output to a file), `lib_rom_ok`, `lib_upper`.

## 4 Files, forensics and audit

(server/30-files.sh, server/40-forensics.sh, server/50-audit.sh)
