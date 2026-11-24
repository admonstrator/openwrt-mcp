# openwrt-mcp

English | [Deutsch](README.de.md)

An MCP server for OpenWrt routers. It gives Claude (or any other MCP client) tools to
take a router apart: inventory, network exposure, integrity against the firmware image,
persistence, accounts, and an audit with findings.

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
which were added or changed later. With `--admin` it can also change the configuration
(see [Admin mode](#admin-mode-configuring-the-router)).

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

There are two parts. The MCP server gives Claude the tools. The skill
`openwrt-router-audit` tells Claude in which order to use them and how to read the
results. The tools work without the skill; the audits are better with it.

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

`claude mcp list` shows whether the connection works.

**Claude Desktop (macOS):** put the printed `mcpServers` entry into
`~/Library/Application Support/Claude/claude_desktop_config.json` and restart the app.

claude.ai in the browser cannot use this server: the launcher has to run on a computer
that reaches the router over SSH.

Launcher options: `-p PORT`, `-i KEY`, `-o SSH_OPTION`, `--no-redact`,
`--max-output BYTES` (default 60000), `--call-timeout SECONDS` (default 120),
`--admin` (write tools, see below), `--build FILE` (write the single-file server, for
example to run it by hand).

### 3. Add the skill

The skill is in [.claude/skills/openwrt-router-audit](.claude/skills/openwrt-router-audit).

**Claude Code:** if you start `claude` inside the cloned repository, the skill is loaded
already. To have it in every project, copy it to your personal skills:

```sh
mkdir -p ~/.claude/skills
cp -R ~/openwrt-mcp/.claude/skills/openwrt-router-audit ~/.claude/skills/
```

**Claude Desktop:** zip the folder and upload the file in the settings where skills are
managed (the name of that page has changed between app versions):

```sh
cd ~/openwrt-mcp/.claude/skills && zip -r ~/openwrt-router-audit.zip openwrt-router-audit
```

The skill points to `docs/tools.md` for details. Outside the repository Claude does not
have that file and works from the tool descriptions, which is enough for an audit.

### 4. Ask

*"Audit the router and tell me what to look at first."* Claude asks for permission
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
