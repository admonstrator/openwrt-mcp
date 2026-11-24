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
