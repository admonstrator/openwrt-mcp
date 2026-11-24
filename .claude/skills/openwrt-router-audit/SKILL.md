---
name: openwrt-router-audit
description: Investigate an OpenWrt or GL.iNet router through the openwrt-mcp tools (audit, overlay_diff, persistence, processes, connections, firewall, users_auth, file tools) and report what to look at first. Use this whenever the user wants a router audited, checked for compromise, malware (gl-helper and the like), backdoors, open ports, unexpected changes since flashing, unknown processes or SSH keys, or asks "is my router clean / safe / hacked", "what is exposed to the WAN", "what changed on the router", even when they do not name the tools or the server. Also use it when following up on a single audit finding. German triggers too, such as Router prüfen, untersuchen, auditieren, kompromittiert, Schadsoftware, offene Ports.
---

# Investigating an OpenWrt router with openwrt-mcp

The openwrt-mcp server runs a read-only POSIX sh script on the router over SSH. Its tools
appear under the name the user registered, for example `mcp__router__audit`. Everything
except `exec` is read-only, masks secrets by default and compares against the firmware
image in `/rom`. The tool reference is `docs/tools.md` in this repository (sections 3 and 4
describe every tool and every audit check); read the part you need instead of guessing
what an output line means.

If no openwrt-mcp tools are connected, do not try to SSH in yourself. Tell the user how to
register the server (`bin/openwrt-mcp --print-config router root@HOST`, key login as
root, host key accepted once by hand) and stop.

## The order that works

1. **`server_info`** – check `trusted tools`. `yes (/rom/bin/busybox, N applets)` means
   every call ran with the image's busybox, so a replaced applet in the overlay cannot
   lie. `no (...)` lowers the trust in every later result; say so in the report.
   Also note whether redaction is on.
2. **`system_info`** – model, firmware (GL.iNet version if any), OpenWrt release, uptime.
   Uptime matters: a RAM-only implant disappears on reboot, and a recent reboot means
   `/tmp` evidence may be gone.
3. **`audit`** with no arguments. It gives findings by severity, then "Checked, nothing
   found" and "Could not check". Read all three parts: "Could not check" is as important
   as a finding, because it tells you where the audit is blind (no WAN zone identified,
   no usable `/rom`, scan limits hit).
4. **Follow up** every high and medium finding with the dedicated tools (table below, and
   [references/followups.md](references/followups.md) per check id). Low and info
   findings get a follow-up only when they connect to something higher, for example a
   new authorized key plus an unowned program started from cron.
5. **Cross-check the big three** even when the audit is quiet, because these are where a
   real compromise on OpenWrt lives:
   - `persistence` with `only_changed: true` – every place code starts from by itself.
   - `overlay_diff` with `max_priority: 2` – replaced image programs, setuid bits,
     programs no package provides, authorized keys.
   - `connections` (state `listen`) next to `firewall` – what listens, who owns it, and
     whether the WAN side reaches it.
6. **Report** (format below).

| Question | Tool and arguments |
| --- | --- |
| What is this process? | `processes` with `pid`: exe, maps, fds, cwd, environment, sockets |
| What does this file contain? | `read_file` (`view: strings` for binaries, `hex` for headers) |
| Is this the image's file? | `file_hash` (compares with `/rom`), `list_dir` (image column) |
| What was added or changed in a tree? | `overlay_diff` with `path`, `status` |
| Recently written files | `find_files` with `modified_within_minutes`, or `newer_than` a reference file |
| setuid / world-writable files | `find_files` with `perm` |
| Which package owns it, was it installed later? | `packages` with `filter`, `user_installed_only` |
| What starts it at boot? | `persistence`, `services` with `filter` |
| What did it log? | `logs` with `pattern` (ERE) |
| SSH keys, accounts, web login | `users_auth` |
| What reaches it from the internet? | `firewall`, then `connections` |

## Reading the results correctly

These points come from how the tools are built. Getting them wrong produces confident
false alarms or false all-clears.

- **First-boot changes are not an intrusion.** OpenWrt has no clock at first boot;
  sysfixtime sets it to the newest file in the image's `/etc`. What the firmware writes
  then lands in the hour after that time, and the tools mark it as first boot (INFO,
  priority 4). Do not escalate those.
- **The package database is writable.** "Owned by package X" lowers a priority but proves
  nothing; an attacker can add a `.list` entry. Treat ownership as a hint and say so.
- **File times can be forged** with `touch`; ctime cannot be set that way, but setting the
  system clock back can. Timelines are hints.
- **The exposure checks reason from `/etc/config/firewall` and `/proc`**, not from the
  loaded nftables/iptables ruleset rule by rule. Custom includes can open or close more.
  Carry the finding's confidence line into the report instead of rounding it up.
- **GL.iNet firmware ships a lot on its own** (oui-httpd, gl-* services, extra init
  scripts). Compare with `/rom` via the tools rather than judging by name.
- **Masquerading alone does not make a WAN zone.** VPN and Tailscale zones with
  `input=ACCEPT` are not reported as WAN exposure, on purpose.
- **Under emulation** (test containers) `/proc/PID/exe` is the emulator. On a real router
  `exe-deleted`, `exe-memfd` and `exe-in-tmp` flags are strong signals.
- **Clean output does not prove a clean router.** The image's busybox still loads
  libraries from the live system, opaque overlay directories are not detected, and a
  kernel-level implant can hide from `/proc`. Say this once in the report, not as a
  disclaimer on every line.

## Never, and why

- **Never run `netstat`** (not through `exec`, not by suggesting it). On GL.iNet devices
  with the gl-helper infection the replaced `netstat` starts the malware. `connections`
  reads `/proc` and gives the same answer safely.
- **Use `exec` only when no read-only tool covers the question**, and before calling it,
  tell the user the exact command and why. The client asks for approval every time; that
  approval should be an informed one. Keep it read-only (no `uci commit`, no restarts, no
  `rm`, no writes outside `/tmp`), set a short `timeout`, and keep `trusted_tools: true`.
  `exec` output is not redacted, so avoid commands that print secrets.
- **Do not change the router to "fix" a finding.** The tools are read-only for a reason:
  on a compromised device every change destroys evidence and the attacker may still be
  there. Recommend the fix; let the user do it.
- **Do not ask for `--no-redact`** unless a secret's value is the actual question (for
  example comparing a key with a known one). Mention it as an option instead.
- **Do not paste secrets** from any output into the report.

## Large outputs

Every result is capped (60000 bytes by default) and ends with a note when cut. When that
happens, narrow the call instead of reading on blindly: `path`, `filter`, `status`,
`max_priority`, `locations`, `section`, or `offset`/`limit` where the tool has them. The
tools print the most useful parts first, so a cut list usually loses only the
unremarkable tail.

## Report format

Write in the user's language. Lead with what to do, not with how you got there.

```
## Verdict
One to three sentences: compromised / suspicious / nothing found that indicates a
compromise, and how sure (trusted tools yes/no, what could not be checked).

## Look at this first
1. <Finding in plain words> – severity, confidence
   Evidence: <the lines that show it: path, pid, port, hash, image comparison>
   Why it matters: <one sentence>
   What to do: <concrete step>
2. ...

## Also noticed (low / info)
Short list, one line each.

## Not checked or not certain
What the audit listed under "Could not check", limits that applied (cut output, no WAN
zone, no /rom), and the general limits that matter for this verdict.

## Next steps
Ordered. If there is evidence of compromise: disconnect WAN, save evidence if wanted,
reflash the firmware without keeping settings, then change every password and key the
router held (Wi-Fi, admin, VPN, API tokens). Keeping settings across a reflash can keep
the persistence.
```

Keep evidence exact (paths, pids, ports, hashes, fingerprints) so the user can verify it.
Distinguish between what a tool showed and what you conclude from it.
