# Tools

Every tool the server offers, what it reads, its arguments and its limits.
Sections are numbered by module; each module's owner writes only its own section.

## 1 Core

`server_info`: version, protocol versions, trusted tools, redaction, limits, tool list.

## 2 Core and exec

(server/00-core.sh, server/90-exec.sh, bin/openwrt-mcp)

## 3 System and network inventory

(server/10-system.sh, server/20-network.sh, server/05-lib.sh)

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
2000), `compare_image` default true. It stays on the filesystem of each root, never
walks `/proc` or `/sys`, stops after 20000 matches or 40 s and says so.

### file_hash

`paths` (1 to 50 absolute paths), `algorithm` (`sha256` default, `md5`; the images have no
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
| 1 | An image program or image init/hotplug script replaced, a setuid/setgid bit added, `/etc/ld.so.preload` |
| 2 | Programs and autostart entries that neither the image nor a package provides, authorized keys, deleted image programs |
| 3 | Files replaced by a package upgrade, account files, mode or owner changes, unowned data files, feeds |
| 4 | Files of packages installed after flashing, services enabled or disabled, other configuration |
| 5 | Expected state: `/etc/config`, host keys, the package database, first-boot scripts that removed themselves, identical copies |

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
| `exposure.wan_input_accept` | high (medium when no WAN interface has an address) | WAN zone with `input=ACCEPT`, and the sockets listening on all addresses |
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
| `integrity.image_file_replaced` | high | overlay holds another version of an image program, no package upgrade explains it |
| `integrity.setuid_added` | high | setuid or setgid bit on an image program |
| `integrity.process_deleted_tmp_binary` | high | process whose program was deleted from `/tmp`, `/var`, `/dev/shm` |
| `integrity.ld_preload` | high with `LD_PRELOAD` in a process or on glibc, else medium | `/etc/ld.so.preload` lines, process environments |
| `integrity.unowned_program` | medium | program in a system directory that neither the image nor a package provides |
| `integrity.tmp_executable` | medium | executable files in `/tmp` and `/dev/shm` |
| `integrity.process_tmp_binary` | medium | process running from the RAM disk |
| `integrity.process_deleted_binary` | medium | process whose program file is gone (elsewhere) |
| `integrity.process_not_from_image` | medium | process running a program that neither the image nor an added package provides |
| `integrity.kernel_module_not_in_image` | medium | loaded module without a `.ko` in the image |
| `integrity.mount_over_system_path` | medium | a mount on `/bin`, `/sbin`, `/lib`, `/usr`, `/www` or below |
| `integrity.image_file_deleted` | low | whiteouts for image programs (not when the package was removed) |
| `integrity.package_upgrades` | info | image files replaced by a package upgrade, counted per package |
| `persistence.image_script_changed` | high | image init, hotplug, inittab, rpcd or LuCI script that differs from the image |
| `persistence.autostart_added` | medium | autostart file that neither the image nor a package provides |
| `persistence.user_autostart` | low; medium when a line downloads, pipes into a shell or uses the RAM disk | active lines of cron files, `rc.local`, changed profile, firewall and dnsmasq files |
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
`/etc/config/firewall` and matches them against the listening sockets from `/proc`
(wildcard addresses and addresses of the WAN devices). It does not evaluate the loaded
nft or iptables ruleset rule by rule, so custom includes can open or close more; the
finding's confidence line says so. The stock rules for the DHCP clients (udp 68, 546)
are not reported.

Each thing is reported by one check: autostart locations belong to the persistence
checks, so the integrity checks skip them, and a socket the zone policy already opens is
not repeated for a rule.

`MCP_PROC` (default `/proc`) is where the process checks read exe links, environments
and the module list. It exists for the tests, because in an emulated container every
`/proc/PID/exe` points at the emulator; sockets always come from the real `/proc`.
