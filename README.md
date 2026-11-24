<div align="center">

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="./images/logo-dark.png">
  <img src="./images/logo.png" alt="OpenWrt MCP, also for GL.iNet routers" width="480">
</picture>

<h1>openwrt-mcp</h1>

An MCP server that lets Claude inspect, audit and configure OpenWrt and GL.iNet routers.

[![Tests](https://img.shields.io/github/actions/workflow/status/admonstrator/openwrt-mcp/tests.yml?branch=main&style=for-the-badge&logo=githubactions&label=Tests)](https://github.com/admonstrator/openwrt-mcp/actions/workflows/tests.yml) [![License](https://img.shields.io/github/license/admonstrator/openwrt-mcp?style=for-the-badge&color=0ea5e9)](LICENSE) [![OpenWrt](https://img.shields.io/badge/OpenWrt-21.02%20to%2025.12-10b981?style=for-the-badge&logo=openwrt)](#requirements)

English · [Deutsch](README.de.md)

[What it does](#what-it-does) · [Setup](#giving-claude-access-to-the-router) · [Tools](#tools) · [Admin mode](#admin-mode-configuring-the-router) · [Safety](#safety) · [Limits](#limits)

</div>

---

An MCP server for OpenWrt routers. It gives Claude (or any other MCP client) tools to
take a router apart: inventory, network exposure, integrity against the firmware image,
persistence, accounts, and an audit with findings. In admin mode Claude can also
configure the router: Wi-Fi, LAN and DHCP, firewall, VPN and, on GL.iNet firmware,
everything the GL.iNet web interface can do.

## What it does

You ask Claude a question about your router, such as "is anything reachable from the
internet?" or "what changed since I flashed it?". Claude calls the tools of this server,
the server reads the answer on the router, and Claude tells you what it found and what
to look at first.

The server is one POSIX sh script. Nothing is installed: on every start the launcher
copies the script over SSH to `/tmp` on the router (RAM) and runs it there. MCP goes
over the SSH session. No port is opened and nothing is written to flash.

By default the server only reads. It compares what it finds with the firmware image in
`/rom`, so it can tell which files, services and programs came with the firmware and
which were added or changed later.

With `--admin` the server also changes the router. You say "change the Wi-Fi password",
"give the printer a fixed IP" or "forward port 443 to the NAS", and Claude reads the
current setting, tells you what it is about to change, and makes the change. See
[Admin mode](#admin-mode-configuring-the-router).

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

## Giving Claude access to the router

There are two parts. The MCP server gives Claude the tools. The skills tell Claude how
to use them: `openwrt-router-audit` for checking a router, `openwrt-router-admin` for
configuring it. The tools work without the skills; the results are better with them.

### 1. SSH login with a key

If you still log in with a password, put your public key on the router. OpenWrt's SSH
server (dropbear) reads root's keys from `/etc/dropbear/authorized_keys`, which is why
`ssh-copy-id` does not work here:

```sh
ssh root@192.168.1.1 "tee -a /etc/dropbear/authorized_keys" < ~/.ssh/id_ed25519.pub
```

Then log in once by hand and accept the host key:

```sh
ssh root@192.168.1.1
```

### 2. Register the MCP server

```sh
git clone https://github.com/admonstrator/openwrt-mcp.git ~/openwrt-mcp
~/openwrt-mcp/bin/openwrt-mcp --print-config router root@192.168.1.1
```

This prints the line for Claude Code and an `.mcp.json` entry with the right paths.

**Claude Code:** run the printed line. With `--scope user` the server is there in every
project, not only in the current one:

```sh
claude mcp add --scope user router -- ~/openwrt-mcp/bin/openwrt-mcp root@192.168.1.1
```

To let Claude configure the router as well, add the admin server as a second entry
(see [Admin mode](#admin-mode-configuring-the-router)):

```sh
claude mcp add --scope user router-admin -- ~/openwrt-mcp/bin/openwrt-mcp --admin root@192.168.1.1
```

`claude mcp list` shows whether the connections work.

**Claude Desktop (macOS):** put the printed `mcpServers` entry into
`~/Library/Application Support/Claude/claude_desktop_config.json` and restart the app.

claude.ai in the browser cannot use this server: the launcher has to run on a computer
that reaches the router over SSH.

Launcher options: `-p PORT`, `-i KEY`, `-o SSH_OPTION`, `--no-redact`,
`--max-output BYTES` (default 60000), `--call-timeout SECONDS` (default 120),
`--admin` (write tools, see below), `--build FILE` (write the single-file server, for
example to run it by hand).

### 3. Add the skills

The skills are in [.claude/skills](.claude/skills):

| Skill | For |
| --- | --- |
| `openwrt-router-audit` | Checking a router: the order of the tools, how to read the results, the report |
| `openwrt-router-admin` | Configuring a router: which write tool for what, GL.iNet methods for common tasks, what can cut off your access |

**Claude Code:** if you start `claude` inside the cloned repository, the skills are
loaded already. To have them in every project, copy them to your personal skills:

```sh
mkdir -p ~/.claude/skills
cp -R ~/openwrt-mcp/.claude/skills/openwrt-router-audit ~/openwrt-mcp/.claude/skills/openwrt-router-admin ~/.claude/skills/
```

**Claude Desktop:** zip each folder and upload the files in the settings where skills
are managed (the name of that page has changed between app versions):

```sh
cd ~/openwrt-mcp/.claude/skills
zip -r ~/openwrt-router-audit.zip openwrt-router-audit
zip -r ~/openwrt-router-admin.zip openwrt-router-admin
```

The audit skill points to `docs/tools.md` for details. Outside the repository Claude
does not have that file and works from the tool descriptions, which is enough for an
audit.

### 4. Ask

*"Audit the router and tell me what to look at first."* Or, with the admin server:
*"Turn on the guest Wi-Fi and call it Visitors."* Claude asks for permission
before each tool call. You can allow the read-only tools permanently; leave `exec` on
"ask every time".

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

On GL.iNet firmware 4.x, `glinet_api` reaches the same API the web interface uses. The
catalog has 52 API objects with 368 methods (written from a GL-E5800 with firmware
4.8.5; other models have fewer or different ones). What that covers:

| Area | What Claude can set |
| --- | --- |
| Wi-Fi | SSID, password, encryption, channel, transmit power, on and off, guest Wi-Fi, Wi-Fi 7 MLO, schedules |
| LAN and DHCP | Router address, DHCP range and lease time, static leases, guest network, client isolation |
| DNS | Upstream DNS, DNS over TLS/HTTPS, local host names, AdGuard Home |
| Firewall | Rules, port forwards, DMZ, access to the router from the WAN |
| Uplink | WAN port, repeater, cellular modem and SIM, USB tethering, multi-WAN, IPv6, router mode (router, access point, repeater, WDS) |
| VPN | WireGuard and OpenVPN as client and as server, which devices go through the tunnel, kill switch, Tailscale, ZeroTier, Tor |
| Clients | List of devices, names, blocking by MAC, speed limits, parental control |
| Remote access | GoodCloud, remote terminal, DDNS, ports of the web interface and SSH |
| System | Time zone, LED, display, schedules, packages, firmware update, reboot, factory reset |
| Sharing | Samba and WebDAV shares, DLNA |

On plain OpenWrt there is no GL.iNet API. `uci_change` and `service_control` cover what
is in `/etc/config`: `wireless`, `network`, `dhcp`, `firewall` and every other package.

Write calls report what changed in `/etc/config` (not other files such as
`/etc/hosts`). Calls classed as risky, because they can cut off your access, open the
router or the LAN, or reset, flash or reboot it, run only with `confirm: true`, which
Claude is told to set only after you agreed to that exact call. The classes come from
fixed lists, not from understanding each change: read what Claude proposes. There is no
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
