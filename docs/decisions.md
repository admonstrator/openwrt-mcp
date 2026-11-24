# Decisions

## Phase 1: the first version

| Nr. | Frage | Entscheidung |
| --- | --- | --- |
| 1.1 | Wie kommt der Server auf den Router? | POSIX-sh-Skript, das der Starter bei jedem Start nach `/tmp` (RAM) kopiert und über SSH startet; MCP über stdio. Kein Paket, kein offener Port, nichts im Flash. |
| 1.2 | Was darf Claude? | Feste, nur lesende Werkzeuge plus ein Werkzeug `exec` für beliebige Befehle, das der MCP-Client bei jedem Aufruf freigeben lässt. |
| 1.3 | Wo liegt der Code? | Eigenes Repository `openwrt-mcp`. |
| 1.4 | Wogegen wird getestet? | OpenWrt-rootfs-Container 21.02.7, 23.05.5, 24.10.4, 25.12.0 (lokal und in der CI), am Ende eine Rauchprobe gegen einen echten Router. |
| 1.5 | Welche Werkzeuge auf dem Router? | Pflicht sind nur busybox und `jsonfilter` (auf jedem OpenWrt ab 21.02). `ubus`, `uci`, `nft`, `iptables`, `opkg`/`apk`, `iwinfo`, `wg` werden benutzt, wenn sie da sind. |
| 1.6 | Wem trauen die Werkzeuge? | Hat `/rom` eine busybox, steht sie für jeden Aufruf vorn im PATH, auch für `exec`. Netzverbindungen kommen aus `/proc`, nie aus `netstat` oder `ss`. |
| 1.7 | Geheimnisse | Standardmäßig maskiert (WLAN-Schlüssel, Passwort-Hashes, private Schlüssel); `--no-redact` am Starter schaltet das ab. `exec` maskiert nicht. |
| 1.8 | Wie viel Ausgabe? | Höchstens 60000 Bytes je Ergebnis, einstellbar mit `--max-output`; Werkzeuge mit viel Ausgabe haben `offset`/`limit` oder `max_results`. |
| 1.9 | Protokoll | MCP 2025-11-25 bis 2024-11-05, nur die Fähigkeit `tools`. |
| 1.10 | Woher kommen die vertrauenswürdigen Applets? | Aus den Symlinks auf `bin/busybox` in `/rom/{bin,sbin,usr/bin,usr/sbin}`. Die busybox von OpenWrt kennt `--list` nicht (am GL-BE14000 geprüft: 0 Zeilen); `--list` bleibt nur als Rückfall. `server_info` nennt die Zahl der Applets. |
| 1.11 | Was die Firmware selbst schreibt | Änderungen im Overlay, deren mtime und ctime im Fenster „neueste Datei unter `/rom/etc` bis eine Stunde danach“ liegen, hat die Firmware beim ersten Start geschrieben (sysfixtime stellt die Uhr auf die neueste Image-Datei). Sie sind INFO, nicht HIGH. |
| 1.12 | Welche Zone ist WAN? | Die Zone mit dem Netz `wan`/`wan6` oder mit dem Gerät der Default-Route; eine Zone mit dem Netz `lan` nie. Ohne erkannte WAN-Zone stehen die Expositions-Checks unter „Could not check“. |
| 1.13 | Eigene Prozesse des Servers | Bleiben in den Prozess-Checks des Audits außen vor (`MCP_CALL_TAG`); ein Programm unter `/rom` gilt als aus dem Image. |
| 1.14 | Tests gegen einen echten Router | `OPENWRT_MCP_TARGET` lässt nur die containerfreien Tests laufen; das Harness überspringt jede Anfrage, die `exec` nennt. |

## Rauchprobe Phase 1

Am 2026-11-24 an einem GL.iNet GL-BE14000 (Firmware 4.11.0 beta5, OpenWrt 25.12-SNAPSHOT, aarch64), nur lesende Werkzeuge, kein `exec`: alle 19 Lesewerkzeuge ohne Fehler, je 0,1 bis 6,3 s, Start 0,4 s; 123 Applets aus `/rom`; WLAN-Schlüssel und Hash maskiert; danach nichts in `/tmp` des Routers. Das Audit meldet 2 high, 1 medium, 3 low, 3 info, zu Änderungen nach dem ersten Start (Tailscale-Programme, `samba4`-Init-Skript, `cloudflared.new`, SSH-Schlüssel, nftables-Datei) und als INFO zu dem, was die Firmware beim ersten Start schrieb.
