---
name: openwrt-router-admin
description: Configure and control an OpenWrt or GL.iNet router through the openwrt-mcp admin tools (glinet_api, uci_change, service_control) – Wi-Fi name, password, channel and guest network, LAN address and DHCP range, static leases, DNS and hosts, port forwards and firewall rules, VPN client and server, Tailscale, repeater and modem uplink, client blocking and speed limits, parental control, schedules, firmware updates, reboot. Use this whenever the user wants something on the router changed, switched on or off, set up or restarted, or asks what a setting currently is in order to change it, even when they do not name a tool, for example "change the Wi-Fi password", "give the printer a fixed IP", "open port 443 to the NAS", "turn the guest Wi-Fi off at night". German triggers too, such as WLAN ändern, Gastnetz, DHCP, feste IP, Portfreigabe, Router einstellen, konfigurieren, neu starten, VPN einrichten. Not for checking a router for compromise (that is openwrt-router-audit).
---

# Configuring an OpenWrt or GL.iNet router with openwrt-mcp

The admin server is openwrt-mcp started with `--admin`. It has every read-only tool of the
audit server plus three that change the router. Its tools appear under the name the user
registered, usually `mcp__router-admin__*`. `server_info` prints `mode admin (write tools
on)` when you are on the right server.

If the write tools are not there, do not reach for `exec` on the read-only server to change
things: it bypasses the confirm rules and the change report. Tell the user to register the
admin server next to the read-only one and stop:

```sh
bin/openwrt-mcp --admin --print-config router-admin root@HOST
```

If the user suspects the router is compromised, do not change it. Every change destroys
evidence, and whoever is on the router sees what you do. Use the read-only server and the
openwrt-router-audit skill first.

## Which tool

| Situation | Tool |
| --- | --- |
| GL.iNet firmware, and the setting exists in GL's web interface | `glinet_api` |
| Plain OpenWrt, or a setting GL's interface does not have | `uci_change` |
| Start, stop, restart, enable or disable a service | `service_control` |
| Look at the current state | the read-only tools (`uci`, `network`, `firewall`, `glinet`, `services`) and the query methods of `glinet_api` |

`system_info` tells you which firmware it is. On GL.iNet firmware prefer `glinet_api` over
`uci_change` for anything GL manages (Wi-Fi, LAN, DHCP, firewall, VPN, modem, repeater): the
call goes through the same validators as the web interface, GL's services reload the right
things, and the web interface stays in sync. A direct uci edit of a GL-managed package can
be ignored or overwritten by a GL service later.

## The order that works

1. **Read the current state.** A `get_` method or `uci` with the package. You need it to
   name the right interface or section, to tell the user what will change from what to
   what, and to have the old values if the change has to be undone by hand. There is no
   automatic rollback.
2. **Find the call.** For `glinet_api` do not guess method names or parameters; list them
   (next section). For `uci_change`, the section and option names come from what step 1
   showed.
3. **Tell the user the exact change** in plain words, with old and new value, and what it
   can break. For `uci_change`, run it with `dry_run: true` first and show the lines.
4. **Make one change.** If the tool refuses with "needs confirmation", that is the design,
   not an obstacle: show the user what the tool said, ask, and resend the same call with
   `confirm: true` only after they agreed to that call. An earlier "yes, go ahead" for
   something else does not cover it.
5. **Check the result.** Read the status line and the `Config changes` section the tool
   prints, then read the setting back. `ok` with `no change in /etc/config` usually means
   the method applies in the background or stores its state elsewhere; read again before
   you call it a failure or a success.
6. **Report** what changed (old to new), what the user now has to do themselves
   (reconnect to the new SSID, use the new address), and anything that did not apply.

## Finding a GL.iNet method

`glinet_api` without `method` only lists, nothing is called:

- no arguments: the API objects this router has, with counts per class;
- `object: "wifi"`: every method of that object with class, summary and parameters;
- `search: "guest"`: methods whose name, summary or parameters contain the word.

Classes: `query` reads, `active` changes something that is not in use yet or only cosmetic,
`CONFIRM` can cut the user off, open the router, change credentials, flash or reboot. The
class comes from a fixed list, not from an understanding of your particular call, so think
about the effect yourself as well.

The catalog was written from one model and firmware (GL-E5800, 4.8.5). On other devices
fields differ. So take the shape of `params` from the matching `get_` answer of this router
rather than from the catalog alone: a `set_config` usually takes the fields its `get_config`
returns. If the API answers `-32602`, the validator rejected the params and nothing
changed; compare with the `get_` answer and try again. `-32601` means this firmware has no
such method.

[references/tasks.md](references/tasks.md) maps common tasks to methods and to the uci
options on plain OpenWrt. Read it when the task is in there.

## What cuts off access, and how to avoid it

The server runs over SSH to the router. A change that drops that connection ends the
server before the result arrives, and the change stays.

- **Wi-Fi the user is connected through.** Changing SSID, password, encryption or channel
  disconnects them. Ask how they are connected. Tell them the new SSID and password before
  the call, because the tool never prints params back and masks keys in answers.
- **LAN address, netmask, router mode** (`lan.set_config`, `netmode.set_mode`, uci
  `network.lan`). The router moves to another address; the session ends. Tell the user the
  new address and that the MCP server entry has to be changed to it.
- **SSH and web ports, firewall input rules, WAN access** (`local-access.set_config`, uci
  `dropbear`, `firewall`). Check that the new rule still lets the user in before sending it.
- **`service_control` on `network`, `firewall`, `dropbear`, `dnsmasq`.** A restart applies
  whatever is committed, including changes someone else made and did not apply yet. Read
  `uci` for uncommitted or surprising settings first.
- **Uplink changes** (repeater, modem, cable, multi-WAN, VPN client with kill switch). The
  LAN side stays reachable, the internet may not be.
- **Reboot, firmware upgrade, factory reset.** Only on an explicit request for exactly
  that. For an upgrade, say whether settings are kept (`keep_config`).

Change one thing, check it, then the next. Two access-related changes in a row leave no way
to tell which one broke it.

## Secrets

Answers are masked: Wi-Fi keys, passwords, tokens and private keys show as `<redacted>`.
That is why a VPN client config with its keys cannot be fetched through the tool unless the
server runs with `--no-redact`; point the user to the web interface for that instead of
asking them to turn masking off. A password the user gives you goes into `params` and
nowhere else: do not repeat it in the report beyond what they need to log in again.

## Plain OpenWrt: `uci_change` in practice

One call changes one package. All operations run on a private copy first; if uci refuses
one, nothing is written. Then commit and a reload of the services that watch that package.

```json
{"package": "wireless", "dry_run": true, "changes": [
  {"op": "set", "path": "@wifi-iface[0].ssid", "value": "Home"},
  {"op": "set", "path": "@wifi-iface[0].key", "value": "…"}]}
```

- Take the section from `uci` output (`wireless.default_radio0` or `@wifi-iface[0]`), not
  from memory; names differ between devices.
- A new anonymous section: `{"op": "add", "value": "host"}`, then address it as
  `@host[-1]` in the same call.
- `network`, `wireless`, `dhcp`, `firewall`, `dropbear` and the VPN and sharing packages
  need `confirm`, as does deleting a whole section. A dry run does not.
- The call is refused when the package has uncommitted changes from someone else. Show
  them to the user; do not commit or revert them on your own.
- `NOT APPLIED` in the result means committed but no service reloaded (no procd). Say so.

## Report format

Write in the user's language, short:

```
## Changed
<setting>: <old> -> <new>   (tool and method or package)

## What you need to do
Reconnect to …, new address …, anything the change requires on other devices.

## Not done / needs your decision
Calls that were refused, need confirmation, or failed, with the tool's message.
```

Distinguish between what the tool reported and what you read back afterwards.
