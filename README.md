# openwrt-mcp

An MCP server for OpenWrt routers, so that Claude (or any other MCP client) can take a
router apart: inventory, network exposure, integrity against the firmware image,
persistence, accounts, and an audit with findings.

It is one POSIX sh script. Nothing is installed: on every start the launcher copies the
script over SSH to `/tmp` on the router (RAM) and runs it there. MCP goes over the SSH
session. No port is opened and nothing is written to flash.

> [!WARNING]
> The `exec` tool runs any command as root on the router. Your MCP client asks you before
> every tool call unless you allow it permanently; for `exec`, don't.

## Requirements

- On the router: OpenWrt 21.02 or later (GL.iNet firmware 4.x included). It only needs
  busybox and `jsonfilter`, which every OpenWrt has. `ubus`, `uci`, `nft`,
  `iptables-save`, `opkg`/`apk`, `iwinfo` and `wg` are used when they are there.
- On your computer: bash and OpenSSH (macOS or Linux).
- SSH login as root **with a key**. The MCP client starts the launcher without a
  terminal, so it cannot ask for a password or confirm a new host key. Log in once by
  hand (`ssh root@192.168.1.1`) first.

## Setup

```sh
git clone <this repository> ~/openwrt-mcp
~/openwrt-mcp/bin/openwrt-mcp --print-config router root@192.168.1.1
```

This prints the line for Claude Code and an `.mcp.json` entry, for example:

```sh
claude mcp add router -- ~/openwrt-mcp/bin/openwrt-mcp root@192.168.1.1
```

Then ask Claude something like *"Audit the router and tell me what to look at first."*

Launcher options: `-p PORT`, `-i KEY`, `-o SSH_OPTION`, `--no-redact`,
`--max-output BYTES` (default 60000), `--call-timeout SECONDS` (default 120),
`--admin` (write tools, see below), `--build FILE` (write the single-file server, for
example to run it by hand).

## Tools

| Tool | What it shows |
| --- | --- |
| `server_info` | Version, trusted tools, redaction, limits |
| `system_info` | Model, firmware, kernel, uptime, memory, storage, mounts |
| `processes` | Processes from `/proc`, with flags for deleted or RAM-disk binaries; one process in depth |
| `services` | Init scripts, enabled and running state, scripts not in the image |
| `packages` | Installed packages, user-installed ones, changed config files, `apk audit` |
| `logs` | `logread`, kernel log, log files |
| `kernel_modules` | Loaded modules, modules not in the image, taint |
| `uci` | `uci show`, masked |
| `network` | Interfaces, routes, rules, neighbors, DNS, DHCP, Wi-Fi, VPNs |
| `connections` | Listening sockets and connections with their processes, from `/proc` |
| `firewall` | Zones, forwards, WAN input rules, port forwards, includes, UPnP, the loaded ruleset |
| `read_file` | A file as text, hex or strings, with paging |
| `list_dir` | A directory with mode, owner, size, mtime, link targets, compared with the image |
| `find_files` | Files by name, type, age, permissions (setuid, world-writable) or size |
| `file_hash` | SHA-256 or MD5, compared with the image |
| `overlay_diff` | Everything the overlay adds, changes or deletes against the image, suspicious first |
| `persistence` | Every place code can start from by itself, with what differs from the image |
| `users_auth` | Accounts, SSH keys with fingerprints, SSH and web login settings |
| `audit` | Findings with severity, evidence, confidence and what to do |
| `glinet` | GL.iNet firmware: GoodCloud and remote terminal, admin access, VPN servers, sharing, updates |
| `exec` | Any shell command as root (asks every time) |

[docs/tools.md](docs/tools.md) describes every tool, its arguments and the audit's checks.

## Admin mode: configuring the router

With `--admin` the server also offers tools that change the router. Register it as a
second server next to the read-only one, so each keeps its own permissions:

```sh
~/openwrt-mcp/bin/openwrt-mcp --admin --print-config router-admin root@192.168.1.1
```

| Tool | What it does |
| --- | --- |
| `glinet_api` | Lists and calls the GL.iNet web API on the router (`ubus call gl-session call`), with a method catalog from [glinet-api](https://github.com/admonstrator/glinet-api) |
| `uci_change` | uci operations on one package, with dry run, commit and reload |
| `service_control` | Status, start, stop, restart, reload, enable, disable of an init script |

Every write call reports what changed in `/etc/config`. Calls that can cut off your
access, expose the router or reset, flash or reboot it run only with `confirm: true`,
which Claude is told to set only after you agreed to that exact call. There is no
automatic rollback: a change that cuts the SSH connection stays. Without `--admin` the
write modules are not even part of the script. Do not use admin mode on a router you
suspect to be compromised.

## Safety

- **Read-only by default.** Except `exec`, no tool of the default server changes the
  router: no writes outside its own temp directory, no `uci commit`, no service
  restarts, no network traffic. Only `--admin` adds write tools.
- **Trusted tools.** If the firmware image (`/rom`) has a busybox, every tool call runs
  with it first in `PATH`, so a replaced applet in the overlay cannot lie. Sockets are
  read from `/proc`, never with `netstat` (on GL.iNet devices infected with the
  "gl-helper" malware, running the replaced `netstat` starts the malware).
- **Secrets are masked** by default: Wi-Fi keys, password hashes, private keys, tokens.
  `--no-redact` turns that off. `exec` output is never masked.
- **Limits.** At most 60000 bytes per result; tools with long output have paging or
  `max_results`. Every call has a time limit, and its whole process tree is stopped
  when the limit is hit.
- **Cleanup.** The script deletes itself from `/tmp` when it starts. Its temp
  directory goes away when the session ends, also when SSH drops.

## Limits

- The audit reasons from `/etc/config/firewall` and the socket table. It does not
  evaluate the loaded nftables or iptables ruleset rule by rule, so it says how sure it
  is about each exposure finding.
- File times can be forged, and the package database is writable. The audit treats
  both as hints and says so.
- busybox cannot read extended attributes, so opaque overlay directories are not
  detected.
- The busybox from `/rom` still loads its libraries from the live system.
- The tools do not prove a router clean. After a real compromise, reflash it without
  keeping settings.

## Tests

The tests run the server in OpenWrt rootfs containers (21.02.7, 23.05.5, 24.10.4,
25.12.0) and talk MCP to it:

```sh
OPENWRT_IMAGE=openwrt/rootfs:x86-64-24.10.4 python3 -m unittest discover -s tests
```

GitHub Actions runs shellcheck and the suite on all four images.

## License

MIT, see [LICENSE](LICENSE).
