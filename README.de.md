# openwrt-mcp

[English](README.md) | Deutsch

Ein MCP-Server für OpenWrt-Router. Er gibt Claude (oder jedem anderen MCP-Client)
Werkzeuge, mit denen sich ein Router untersuchen lässt: Bestandsaufnahme, was aus dem
Netz erreichbar ist, Abgleich mit dem Firmware-Image, Persistenz, Benutzerkonten und ein
Audit mit Befunden. Im Admin-Modus kann Claude den Router auch konfigurieren: WLAN, LAN
und DHCP, Firewall, VPN und auf GL.iNet-Firmware alles, was die Weboberfläche von
GL.iNet kann.

## Was der Server tut

Du stellst Claude eine Frage zu deinem Router, etwa „Ist irgendetwas aus dem Internet
erreichbar?“ oder „Was hat sich seit dem Flashen geändert?“. Claude ruft die Werkzeuge
dieses Servers auf, der Server liest die Antwort auf dem Router aus, und Claude sagt
dir, was es gefunden hat und was du dir zuerst ansehen solltest.

Der Server ist ein einzelnes POSIX-sh-Skript. Installiert wird nichts: Bei jedem Start
kopiert der Launcher das Skript per SSH nach `/tmp` auf den Router (RAM) und führt es
dort aus. MCP läuft über die SSH-Sitzung. Es wird kein Port geöffnet und nichts in den
Flash geschrieben.

In der Voreinstellung liest der Server nur. Was er findet, vergleicht er mit dem
Firmware-Image in `/rom`. So erkennt er, welche Dateien, Dienste und Programme mit der
Firmware kamen und welche später dazugekommen sind oder geändert wurden.

Mit `--admin` verändert der Server den Router auch. Du sagst „Ändere das
WLAN-Passwort“, „Gib dem Drucker eine feste IP“ oder „Leite Port 443 an das NAS
weiter“. Claude liest die aktuelle Einstellung, sagt dir, was es ändern will, und
ändert es dann. Siehe [Admin-Modus](#admin-modus-den-router-konfigurieren).

> [!WARNING]
> Das Werkzeug `exec` führt beliebige Befehle als root auf dem Router aus. Dein
> MCP-Client fragt vor jedem Werkzeugaufruf nach, solange du ihn nicht dauerhaft
> erlaubst. Bei `exec` solltest du das nicht tun.

## Voraussetzungen

- Auf dem Router: OpenWrt 21.02 oder neuer (GL.iNet-Firmware 4.x eingeschlossen).
  Gebraucht werden nur busybox und `jsonfilter`, die jedes OpenWrt mitbringt. `ubus`,
  `uci`, `nft`, `iptables-save`, `opkg`/`apk`, `iwinfo` und `wg` werden benutzt, wenn
  sie vorhanden sind.
- Auf deinem Rechner: bash und OpenSSH (macOS oder Linux).
- SSH-Login als root **mit Schlüssel**. Der MCP-Client startet den Launcher ohne
  Terminal. Er kann deshalb weder nach einem Passwort fragen noch einen neuen Host-Key
  bestätigen. Melde dich vorher einmal von Hand an (`ssh root@192.168.1.1`).

## Claude Zugriff auf den Router geben

Es sind zwei Teile. Der MCP-Server gibt Claude die Werkzeuge. Die Skills sagen Claude,
wie es sie benutzt: `openwrt-router-audit` für das Prüfen eines Routers,
`openwrt-router-admin` für das Konfigurieren. Die Werkzeuge funktionieren auch ohne die
Skills, die Ergebnisse werden mit ihnen besser.

### 1. SSH-Login mit Schlüssel

Wenn du dich noch mit Passwort anmeldest, lege deinen öffentlichen Schlüssel auf dem
Router ab. Der SSH-Server von OpenWrt (dropbear) liest die Schlüssel für root aus
`/etc/dropbear/authorized_keys`, deshalb funktioniert `ssh-copy-id` hier nicht:

```sh
ssh root@192.168.1.1 "tee -a /etc/dropbear/authorized_keys" < ~/.ssh/id_ed25519.pub
```

Danach einmal von Hand anmelden und den Host-Key bestätigen:

```sh
ssh root@192.168.1.1
```

### 2. Den MCP-Server eintragen

```sh
git clone https://github.com/admonstrator/openwrt-mcp.git ~/openwrt-mcp
~/openwrt-mcp/bin/openwrt-mcp --print-config router root@192.168.1.1
```

Das gibt die Zeile für Claude Code und einen `.mcp.json`-Eintrag mit den richtigen
Pfaden aus.

**Claude Code:** Führe die ausgegebene Zeile aus. Mit `--scope user` steht der Server in
jedem Projekt zur Verfügung, nicht nur im aktuellen:

```sh
claude mcp add --scope user router -- ~/openwrt-mcp/bin/openwrt-mcp root@192.168.1.1
```

Soll Claude den Router auch konfigurieren, trage den Admin-Server als zweiten Eintrag
ein (siehe [Admin-Modus](#admin-modus-den-router-konfigurieren)):

```sh
claude mcp add --scope user router-admin -- ~/openwrt-mcp/bin/openwrt-mcp --admin root@192.168.1.1
```

`claude mcp list` zeigt, ob die Verbindungen stehen.

**Claude Desktop (macOS):** Trage den ausgegebenen `mcpServers`-Eintrag in
`~/Library/Application Support/Claude/claude_desktop_config.json` ein und starte die App
neu.

claude.ai im Browser kann diesen Server nicht benutzen: Der Launcher muss auf einem
Rechner laufen, der den Router per SSH erreicht.

Optionen des Launchers: `-p PORT`, `-i KEY`, `-o SSH_OPTION`, `--no-redact`,
`--max-output BYTES` (Standard 60000), `--call-timeout SECONDS` (Standard 120),
`--admin` (Schreibwerkzeuge, siehe unten), `--build FILE` (schreibt den Server als
einzelne Datei, zum Beispiel um ihn von Hand zu starten).

### 3. Die Skills hinzufügen

Die Skills liegen in [.claude/skills](.claude/skills):

| Skill | Wofür |
| --- | --- |
| `openwrt-router-audit` | Einen Router prüfen: Reihenfolge der Werkzeuge, wie die Ergebnisse zu lesen sind, der Bericht |
| `openwrt-router-admin` | Einen Router konfigurieren: welches Schreibwerkzeug wofür, GL.iNet-Methoden für häufige Aufgaben, was dich aussperren kann |

**Claude Code:** Wenn du `claude` im geklonten Repository startest, sind die Skills
schon geladen. Sollen sie in jedem Projekt da sein, kopiere sie zu deinen persönlichen
Skills:

```sh
mkdir -p ~/.claude/skills
cp -R ~/openwrt-mcp/.claude/skills/openwrt-router-audit ~/openwrt-mcp/.claude/skills/openwrt-router-admin ~/.claude/skills/
```

**Claude Desktop:** Packe jeden Ordner als ZIP und lade die Dateien in den
Einstellungen dort hoch, wo Skills verwaltet werden (die Seite hieß je nach App-Version
unterschiedlich):

```sh
cd ~/openwrt-mcp/.claude/skills
zip -r ~/openwrt-router-audit.zip openwrt-router-audit
zip -r ~/openwrt-router-admin.zip openwrt-router-admin
```

Für Einzelheiten verweist der Audit-Skill auf `docs/tools.md`. Außerhalb des
Repositorys hat Claude diese Datei nicht und arbeitet mit den Beschreibungen der
Werkzeuge. Für ein Audit reicht das.

### 4. Fragen

*„Prüf den Router und sag mir, was ich mir zuerst ansehen soll.“* Oder mit dem
Admin-Server: *„Schalte das Gast-WLAN ein und nenne es Besuch.“* Claude fragt vor jedem
Werkzeugaufruf um Erlaubnis. Die lesenden Werkzeuge kannst du dauerhaft erlauben, `exec`
bleibt besser auf „jedes Mal fragen“.

## Werkzeuge

| Werkzeug | Was es zeigt |
| --- | --- |
| `server_info` | Version, vertrauenswürdige Programme, Maskierung, Grenzen |
| `system_info` | Modell, Firmware, Kernel, Laufzeit, Speicher, Datenträger, Mounts |
| `processes` | Prozesse aus `/proc`, mit Markierung für gelöschte Programmdateien und solche auf der RAM-Disk; ein einzelner Prozess im Detail |
| `services` | Init-Skripte, ob aktiviert und ob sie laufen, Skripte, die nicht im Image sind |
| `packages` | Installierte Pakete, selbst installierte, geänderte Konfigurationsdateien, `apk audit` |
| `logs` | `logread`, Kernel-Log, Logdateien |
| `kernel_modules` | Geladene Module, Module, die nicht im Image sind, Taint |
| `uci` | `uci show`, maskiert |
| `network` | Schnittstellen, Routen, Regeln, Nachbarn, DNS, DHCP, WLAN, VPNs |
| `connections` | Lauschende Sockets und Verbindungen mit ihren Prozessen, aus `/proc` |
| `firewall` | Zonen, Weiterleitungen, Eingangsregeln am WAN, Portweiterleitungen, Includes, UPnP, das geladene Regelwerk |
| `read_file` | Eine Datei als Text, Hex oder Strings, seitenweise |
| `list_dir` | Ein Verzeichnis mit Rechten, Besitzer, Größe, mtime und Linkzielen, verglichen mit dem Image |
| `find_files` | Dateien nach Name, Typ, Alter, Rechten (setuid, für alle schreibbar) oder Größe |
| `file_hash` | SHA-256 oder MD5, verglichen mit dem Image |
| `overlay_diff` | Alles, was das Overlay gegenüber dem Image hinzufügt, ändert oder löscht, Verdächtiges zuerst |
| `persistence` | Jede Stelle, von der aus Code von selbst startet, und was dort vom Image abweicht |
| `users_auth` | Konten, SSH-Schlüssel mit Fingerabdruck, Einstellungen für SSH- und Web-Login |
| `audit` | Befunde mit Schweregrad, Belegen, Sicherheit der Aussage und dem, was zu tun ist |
| `glinet` | GL.iNet-Firmware: GoodCloud und Remote-Terminal, Admin-Zugang, VPN-Server, Freigaben, Updates |
| `exec` | Beliebiger Shell-Befehl als root (fragt jedes Mal) |

[docs/tools.md](docs/tools.md) beschreibt jedes Werkzeug, seine Argumente und die
Prüfungen des Audits (auf Englisch).

## Admin-Modus: den Router konfigurieren

Mit `--admin` bietet der Server zusätzlich Werkzeuge an, die den Router verändern. Trage
ihn als zweiten Server neben dem lesenden ein, damit jeder seine eigenen Berechtigungen
behält:

```sh
~/openwrt-mcp/bin/openwrt-mcp --admin --print-config router-admin root@192.168.1.1
```

| Werkzeug | Was es tut |
| --- | --- |
| `glinet_api` | Listet die Methoden der GL.iNet-Web-API auf dem Router auf und ruft sie auf (`ubus call gl-session call`), mit einem Methodenkatalog aus [glinet-api](https://github.com/admonstrator/glinet-api) |
| `uci_change` | uci-Operationen auf einem Paket, mit Probelauf, Commit und Reload |
| `service_control` | Status, start, stop, restart, reload, enable, disable eines Init-Skripts |

Auf GL.iNet-Firmware 4.x erreicht `glinet_api` dieselbe API, die auch die Weboberfläche
benutzt. Der Katalog kennt 52 API-Objekte mit 368 Methoden (aufgenommen an einem
GL-E5800 mit Firmware 4.8.5, andere Modelle haben weniger oder andere). Das deckt ab:

| Bereich | Was Claude einstellen kann |
| --- | --- |
| WLAN | SSID, Passwort, Verschlüsselung, Kanal, Sendeleistung, ein und aus, Gast-WLAN, Wi-Fi 7 MLO, Zeitpläne |
| LAN und DHCP | Adresse des Routers, DHCP-Bereich und Lease-Dauer, feste Zuordnungen, Gastnetz, Client-Isolation |
| DNS | Upstream-DNS, DNS über TLS/HTTPS, lokale Hostnamen, AdGuard Home |
| Firewall | Regeln, Portweiterleitungen, DMZ, Zugriff auf den Router vom WAN |
| Uplink | WAN-Port, Repeater, Mobilfunkmodem und SIM, USB-Tethering, Multi-WAN, IPv6, Betriebsart (Router, Access Point, Repeater, WDS) |
| VPN | WireGuard und OpenVPN als Client und als Server, welche Geräte durch den Tunnel gehen, Kill-Switch, Tailscale, ZeroTier, Tor |
| Clients | Geräteliste, Namen, Sperren nach MAC, Geschwindigkeitslimits, Kindersicherung |
| Fernzugriff | GoodCloud, Remote-Terminal, DDNS, Ports von Weboberfläche und SSH |
| System | Zeitzone, LED, Display, Zeitpläne, Pakete, Firmware-Update, Neustart, Werkseinstellungen |
| Freigaben | Samba- und WebDAV-Freigaben, DLNA |

Auf einem reinen OpenWrt gibt es die GL.iNet-API nicht. Dort decken `uci_change` und
`service_control` ab, was in `/etc/config` steht: `wireless`, `network`, `dhcp`,
`firewall` und jedes andere Paket.

Schreibende Aufrufe melden, was sich in `/etc/config` geändert hat (nicht in anderen
Dateien wie `/etc/hosts`). Als riskant gelten Aufrufe, die dich aussperren, den Router
oder das LAN öffnen oder den Router zurücksetzen, flashen oder neu starten können. Sie
laufen nur mit `confirm: true`, und Claude hat die Anweisung, das erst zu setzen,
nachdem du genau diesem Aufruf zugestimmt hast. Die Einstufung kommt aus festen Listen
und nicht daraus, dass jede Änderung verstanden wird: Lies, was Claude vorschlägt. Es
gibt kein automatisches Zurückrollen. Eine Änderung, die die SSH-Verbindung kappt,
bleibt bestehen. Ohne `--admin` sind die Schreibmodule nicht einmal Teil des Skripts.
Benutze den Admin-Modus nicht auf einem Router, den du für kompromittiert hältst.

## Sicherheit

- **Nur lesend in der Voreinstellung.** Außer `exec` verändert kein Werkzeug des
  Standardservers den Router: Er schreibt nichts außerhalb seines eigenen
  Temp-Verzeichnisses, macht kein `uci commit`, startet keine Dienste neu und erzeugt
  keinen Netzwerkverkehr. Schreibwerkzeuge kommen erst mit `--admin` dazu.
- **Vertrauenswürdige Programme.** Hat das Firmware-Image (`/rom`) ein busybox, läuft
  jeder Werkzeugaufruf mit diesem an erster Stelle im `PATH`. Ein im Overlay
  ausgetauschtes Applet kann so nicht lügen. Sockets werden aus `/proc` gelesen, nie mit
  `netstat` (auf GL.iNet-Geräten, die mit der Schadsoftware „gl-helper“ infiziert sind,
  startet das ausgetauschte `netstat` die Schadsoftware).
- **Geheimnisse sind maskiert**, wenn du nichts anderes einstellst: WLAN-Schlüssel,
  Passwort-Hashes, private Schlüssel, Tokens. `--no-redact` schaltet das ab. Die Ausgabe
  von `exec` wird nie maskiert.
- **Grenzen.** Höchstens 60000 Bytes pro Ergebnis. Werkzeuge mit langer Ausgabe geben
  sie seitenweise aus oder haben `max_results`. Jeder Aufruf hat ein Zeitlimit. Läuft es
  ab, wird der ganze Prozessbaum des Aufrufs beendet.
- **Aufräumen.** Das Skript löscht sich beim Start selbst aus `/tmp`. Sein
  Temp-Verzeichnis verschwindet, wenn die Sitzung endet, auch wenn die SSH-Verbindung
  abbricht.

## Grenzen

- Das Audit schließt aus `/etc/config/firewall` und der Socket-Tabelle. Das geladene
  nftables- oder iptables-Regelwerk wertet es nicht Regel für Regel aus. Deshalb sagt es
  bei jedem Befund zur Erreichbarkeit dazu, wie sicher es sich ist.
- Zeitstempel von Dateien lassen sich fälschen, und die Paketdatenbank ist schreibbar.
  Das Audit behandelt beides als Hinweis und sagt das auch.
- busybox kann keine erweiterten Attribute lesen. Opake Overlay-Verzeichnisse werden
  deshalb nicht erkannt.
- Das busybox aus `/rom` lädt seine Bibliotheken trotzdem aus dem laufenden System.
- Die Werkzeuge beweisen nicht, dass ein Router sauber ist. Nach einer echten
  Kompromittierung flashst du ihn neu, ohne die Einstellungen zu behalten.

## Tests

Die Tests starten den Server in Containern mit OpenWrt-Rootfs (21.02.7, 23.05.5,
24.10.4, 25.12.0) und sprechen MCP mit ihm:

```sh
OPENWRT_IMAGE=openwrt/rootfs:x86-64-24.10.4 python3 -m unittest discover -s tests
```

GitHub Actions lässt shellcheck und die Tests auf allen vier Images laufen.

## Lizenz

MIT, siehe [LICENSE](LICENSE).
