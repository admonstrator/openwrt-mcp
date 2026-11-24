# Tools

Every tool the server offers, what it reads, its arguments and its limits.
Sections are numbered by module; each module's owner writes only its own section.

## 1 Core

`server_info`: version, protocol versions, trusted tools, redaction, limits, tool list.

## 2 Core and exec

(server/00-core.sh, server/90-exec.sh, bin/openwrt-mcp)

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
