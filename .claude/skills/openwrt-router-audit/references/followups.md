# Follow-ups per audit check

What to call after a finding, and what would make it benign or serious. Check ids and
severities are those of `docs/tools.md` section 4 ("audit"); if a check is missing here,
read that table.

## exposure

| Check | Follow-up | Benign when | Serious when |
| --- | --- | --- | --- |
| `exposure.wan_input_accept` | `firewall` (zones first), `connections` state `listen` | no WAN interface has an address (router behind another router; severity is then medium) | the zone's devices carry a public address and services listen on all addresses |
| `exposure.wan_open_port` | `connections` for the port's owner, `processes` with that `pid`, `firewall` rule | the user opened it on purpose (WireGuard, a known service) | the owning program is not from the image or a known package |
| `exposure.port_forward` | `firewall` port forwards, `network` section `dhcp` for the target host | the user knows the forward | target host or port unknown to the user, or UPnP leases nobody expects |
| `exposure.firewall_not_loaded` | `firewall` with `raw: true`, `services` filter `firewall` | firewall disabled on a pure access point by design | WAN-facing router without fw4/zone chains |

## auth

| Check | Follow-up | Notes |
| --- | --- | --- |
| `auth.root_no_password` | `users_auth` | On a fresh OpenWrt this is the default; still high if SSH or LuCI is reachable. |
| `auth.extra_uid0` | `users_auth`, `overlay_diff` path `/etc` | A second uid-0 account is a classic backdoor. |
| `auth.ssh_password_from_wan` | `users_auth`, `firewall`, `connections` port 22 | Ask whether the user knowingly exposed SSH. |
| `auth.ubus_without_login` | `uci` package `uhttpd` | `no_ubusauth=1` lets anyone call ubus over HTTP. |
| `auth.authorized_keys` / `auth.account_added` | `users_auth` (fingerprints, comments), `overlay_diff` path `/etc/dropbear` or `/root/.ssh` with mtime | Ask the user to confirm every fingerprint. An unknown key is reason enough to treat the device as compromised. |

## integrity

| Check | Follow-up | Notes |
| --- | --- | --- |
| `integrity.image_file_replaced` | `file_hash` on the path (image hash next to it), `read_file` `view: strings`, `packages` filter on the owning package | Not explained by a package upgrade and written after first boot: treat as compromise. |
| `integrity.setuid_added` | `find_files` `perm: suid`, `list_dir` on the directory | Almost never legitimate on OpenWrt. |
| `integrity.process_memfd`, `integrity.process_deleted_tmp_binary` | `processes` with `pid` (maps, fds, sockets, environment), `read_file` path `/proc/PID/exe` `view: strings`, `connections` | Strongest live signals. Note the pid and its sockets before anything restarts. |
| `integrity.ld_preload` | `read_file` `/etc/ld.so.preload`, `processes` with `pid` for the environment | procd's `/lib/libsetlbf.so` identical to the image is already filtered out. |
| `integrity.unowned_program`, `integrity.process_not_from_image` | `file_hash`, `read_file` `strings`, `persistence` (what starts it), `packages` | Often a manually copied tool (tailscale, cloudflared). Ask the user before calling it malicious; check what starts it and what it connects to. |
| `integrity.tmp_executable`, `integrity.process_tmp_binary` | `list_dir` `/tmp` depth 2, `read_file` `strings`, `processes` with `pid` | ELF files in `/tmp` that run are typical for dropper-style malware (Mirai family, gl-helper loaders). |
| `integrity.kernel_module_not_in_image` | `kernel_modules`, `persistence` locations `modules` | Out-of-tree (`O`) taint alone is normal on OpenWrt. |
| `integrity.mount_over_system_path` | `system_info` (mounts) | A writable mount over `/bin`, `/usr` etc. can hide replaced programs from the overlay scan. |
| `integrity.first_boot_changes`, `integrity.package_upgrades` | none needed | Informational. |

## persistence

| Check | Follow-up | Notes |
| --- | --- | --- |
| `persistence.image_script_changed` | `read_file` on the script, `file_hash`, `overlay_diff` path of its directory | Compare with the image copy line by line: read the same path under `/rom`. |
| `persistence.autostart_added` | `read_file`, `packages` filter, `services` filter | Ask the user whether they created it. |
| `persistence.autostart_link` | `list_dir` on the link, `read_file` on the target | Autostart pointing into the RAM disk is a strong signal. |
| `persistence.user_autostart` | `persistence` locations `cron`,`rc_local` | Medium when a line downloads (`wget`, `curl`, `uclient-fetch`), pipes into a shell or runs from `/tmp`. |
| `persistence.dnsmasq_hook` | `persistence` location `dnsmasq`, `uci` package `dhcp`, `read_file` on the named program | A DHCP script runs as root on every lease. |
| `persistence.module_autoload` | `kernel_modules`, `read_file` on the file in `/etc/modules.d` | |
| `persistence.firewall_rules_added` | `firewall` `raw: true`, `read_file` on the `.nft` file | Rules can open ports or redirect DNS. |
| `persistence.feeds_changed` | `persistence` location `feeds` | A changed feed or key lets future `opkg`/`apk` installs pull attacker packages. |

## updates and wifi

| Check | What to tell the user |
| --- | --- |
| `updates.branch_eol` | The OpenWrt branch gets no security fixes any more; on GL.iNet firmware check the vendor's newest release instead (severity is low there). |
| `updates.firmware_age` | Image older than a year; check for a newer release. |
| `wifi.wep`, `wifi.open_network`, `wifi.wpa1`, `wifi.wps`, `wifi.open_uplink` | Configuration advice; show the affected interface from `network` section `wifi`. Not a sign of compromise. |
