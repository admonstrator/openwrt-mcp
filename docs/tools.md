# Tools

Every tool the server offers, what it reads, its arguments and its limits.
Sections are numbered by module; each module's owner writes only its own section.

## 1 Core

`server_info`: version, protocol versions, trusted tools, redaction, limits, tool list.

## 2 Core and exec

(server/00-core.sh, server/90-exec.sh, bin/openwrt-mcp)

### Protocol

JSON-RPC 2.0, one message per line on stdin and stdout (MCP stdio transport). Methods:
`initialize`, `ping`, `tools/list`, `tools/call`; capability `tools` only.

- `initialize` answers with the client's `protocolVersion` when the server knows it
  (2025-11-25, 2025-06-18, 2025-03-26, 2024-11-05), otherwise with the newest.
- Errors: `-32700` the line is not JSON (id null); `-32600` a batch (array), a non-object,
  an id that is not a string or a number (also `null`; id null), no or non-string `method`,
  `jsonrpc` not `"2.0"`; `-32601` unknown method; `-32602` `params` not an object,
  `tools/call` without a string `name`, unknown tool.
- Notifications (no `id`) never get a reply, whatever the method; `notifications/cancelled`
  is accepted and ignored: requests are handled one at a time, the call timeout bounds
  each of them.
- Blank lines and a trailing CR are skipped. A 1 MB request line works (the shell reads
  it byte by byte: about a second under emulation, a few on a slow router).
- Requests are answered in order. On EOF the server answers what it has already read,
  then exits 0.
- Stdout carries only protocol messages: they go to fd 3 inside `mcp_main`; fd 1 points
  at stderr, and tool handlers get neither (their output goes to the result).

### Tool calls

- **Arguments** are checked against the tool's `inputSchema` before the handler runs:
  unknown names (when `additionalProperties` is false), JSON types (`string`, `integer`,
  `number`, `boolean`, `array`, `object`) and `required`. `null` counts as absent. A
  mismatch is a normal tool result with `isError: true` that names the argument and
  lists what the tool takes. `arg_int` ranges are checked by the handler, same way.
- **Output cap**: a handler writes into a FIFO; a reader keeps at most `MCP_MAX_OUTPUT`
  (default 60000) bytes. One byte more and the call's process tree is killed and the
  text ends with `[output cut at N bytes and the tool was stopped; narrow the request or
  page with offset/limit where the tool has them]`. `isError` stays false. `/tmp` never
  holds more than the cap per call, whatever the tool prints.
- **Call timeout**: `MCP_CALL_TIMEOUT` (default 120 s) per call; for `exec` the limit is
  at least its `timeout` + 5 s. On timeout the call's process tree and every process
  that carries the call's `MCP_CALL_TAG` environment variable (children that daemonized
  and left the tree) are killed; the text ends with `[timeout: the call was stopped after
  N s ...]` and `isError` is true. The server keeps serving.
- **Background holders**: a process the call started in the background that keeps the
  output open does not block the reply: 2 s after the handler ends the reader stops and
  the text ends with a note saying so. The process itself keeps running.
- **Text encoding**: every result is valid UTF-8 and the JSON line is valid JSON,
  whatever the tool printed. Invalid UTF-8 becomes U+FFFD (one per maximal invalid
  subpart, like Python's `errors="replace"`), NUL bytes are dropped, control characters
  and DEL are `\uXXXX` escapes (`\t`, `\r`, `\n` as such), one trailing newline is
  dropped. A multibyte character cut by the output cap is dropped, not replaced. Empty
  output reads `(no output)`. Without `hexdump` on the router the fallback turns every
  non-ASCII byte into `?`.
- `isError` is true when the handler returns non-zero (or `tool_error`), on invalid
  arguments and on timeout.

### Helpers (changed behaviour, same signatures)

- `run_timeout SECS CMD...`: the limit kills the whole process tree of CMD (stopped
  first with SIGSTOP until the set stops growing, then SIGKILL; found through
  `/proc/*/stat`, no `setsid` or `timeout` needed). Returns 124 only when the limit hit
  (`_rt_fired=1`), otherwise CMD's own status. CMD's stdin is /dev/null.
- `json_quote STRING` keeps a trailing newline of STRING (before, it was dropped);
  `json_str` still drops one trailing newline of its input.
- `rd` also refuses `/proc/kmsg` and `trace_pipe` files (regular files that block).
- `redact` also masks hostapd/wpa_supplicant lines (`wpa_passphrase=`, `wpa_psk=`,
  `sae_password=`, `psk=`, `password=`, `private_key_passwd=`) and pretty-printed JSON
  members such as `"key": "..."` (ubus output).

### Environment knobs

| Variable | Default | Meaning |
| --- | --- | --- |
| `MCP_ROM` | `/rom` | firmware image root; its `bin/busybox` goes first in PATH when it runs |
| `MCP_UPPER` | `/overlay/upper` | overlay upper directory |
| `MCP_REDACT` | `1` | `0` turns masking of secrets off (launcher `--no-redact`) |
| `MCP_MAX_OUTPUT` | `60000` | bytes per result (launcher `--max-output`) |
| `MCP_CALL_TIMEOUT` | `120` | seconds per call (launcher `--call-timeout`) |
| `MCP_SELF_DELETE` | `0` | `1`: the script removes itself from /tmp at start (launcher sets it) |
| `MCP_DEBUG` | `0` | `1`: log requests to stderr |

Invalid numbers fall back to the default. Set by the server for every process of a call:
`MCP_CALL_TAG` (internal, for the timeout).

### `exec`

Runs one command with `sh -c` as root and returns stdout and stderr merged, then a last
line `[exit N]`, or `[timeout after N s]` (then `isError` is true and every process the
command started is killed). A non-zero exit status is not an error result. The output
is not redacted. Annotations: `readOnlyHint` false, `destructiveHint` true,
`openWorldHint` true; the description asks for user approval of every call, points to
the read-only tools, and warns not to run `netstat` on a device suspected of the
gl-helper infection.

| Argument | Type | Default | Meaning |
| --- | --- | --- | --- |
| `command` | string, required | | shell command line; stdin is /dev/null |
| `timeout` | integer 1–600 | 30 | seconds, then the process tree is killed |
| `trusted_tools` | boolean | true | true: the firmware busybox (`MCP_ROM`) first in PATH; false: the router's own PATH |
| `cwd` | string | `/` | working directory; a missing one is an error |

Background processes should redirect their output (`cmd >/dev/null 2>&1 &`); one that
keeps the output open gets the 2 s note above and keeps running.

### Launcher `bin/openwrt-mcp`

```
openwrt-mcp [options] [user@]HOST
  -p PORT              SSH port
  -i KEY               SSH identity file (a relative path is made absolute)
  -o OPTION            extra ssh -o option, repeatable; wins over the defaults
  --no-redact          MCP_REDACT=0
  --max-output N       MCP_MAX_OUTPUT=N
  --call-timeout N     MCP_CALL_TIMEOUT=N
  --build FILE         write the joined server script to FILE and exit
  --print-config NAME  print "claude mcp add NAME -- <launcher> <options> HOST" and an
                       .mcp.json entry, and exit
```

- Bash, macOS and Linux; needs `ssh` (OpenSSH client) and `sha256sum` or `shasum`.
- One SSH login per start: the first connection is a ControlMaster (`ControlPersist=60`)
  on a socket in a private `mktemp -d` directory under `$TMPDIR` (or /tmp when that path
  is too long); it copies the server and the run goes over the same connection. On exit
  (EOF, SIGTERM, SIGHUP, SIGINT) the session is stopped, the master told to exit and the
  directory removed. If the launcher is killed hard, the master ends 60 s after the
  session.
- The copy goes to `/tmp/openwrt-mcp.<time>.<pid>.<random>.sh` with `umask 077; set -C`.
  The router runs `sha256sum` on it and starts it only when the hash matches; otherwise
  it deletes it and the launcher exits 1. The server starts with `MCP_SELF_DELETE=1` and
  removes the file at once. Router side needs only `sh`, `cat`, `sha256sum` (and `rm`).
- `BatchMode=yes`, `ConnectTimeout=15`, `ServerAliveInterval=30`, `LogLevel=ERROR`.
  When the login fails the launcher prints ssh's message and what to do: unknown or
  changed host key (log in once by hand), rejected key (install the public key, use
  `-i`), unreachable host. Exit status 1; usage errors 2.

## 3 System and network inventory

(server/10-system.sh, server/20-network.sh, server/05-lib.sh)

## 4 Files, forensics and audit

(server/30-files.sh, server/40-forensics.sh, server/50-audit.sh)
