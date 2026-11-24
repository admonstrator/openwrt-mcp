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
