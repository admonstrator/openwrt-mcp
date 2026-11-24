"""File tools: read_file, list_dir, find_files, file_hash.

The fixture lives in /fx inside the container, with a small firmware image at /fxrom
(passed as MCP_ROM) that holds some of the same paths.
"""

import hashlib
import re
import unittest

from mcp_client import OpenWrtTestCase

ROM = {"MCP_ROM": "/fxrom"}
PLAIN = {"MCP_ROM": "/fxrom", "MCP_REDACT": "0"}

SETUP = r"""
set -e
mkdir -p /fx/sub/deep /fxrom/etc /fxrom/fx/sub
seq 1 500 | sed 's/^/line /' > /fx/text.txt
{ printf 'MAGIC\000\001\002\003hello-world-string\000\377\376tail-marker-xyz\000'; head -c 600 /bin/busybox; } > /fx/bin.dat
mkfifo /fx/fifo
ln -s /proc/1/mem /fx/proclink
ln -s /dev/null /fx/devlink
ln -s /nowhere /fx/dangling
ln -s text.txt /fx/goodlink
cp /fx/text.txt /fxrom/fx/text.txt
echo changed > /fx/changed.txt
echo original > /fxrom/fx/changed.txt
echo new > /fx/new.txt
cp /fx/text.txt /fx/suid && chmod 4755 /fx/suid
echo x > /fx/ww && chmod 666 /fx/ww
printf '#!/bin/sh\n' > /fx/sub/deep/tool.sh && chmod 755 /fx/sub/deep/tool.sh
echo old > /fx/old.txt && touch -d '2020-01-01 00:00:00' /fx/old.txt
head -c 5000 /bin/busybox > /fx/big.bin
# secrets in the formats a router holds them
printf 'root:$1$saltsalt$hashhashhashhashhashha:19000:0:99999:7:::\n' > /fx/shadow
printf "config wifi-iface\n\toption ssid 'Home'\n\toption key 'hunter2secret'\n\toption key1 'wepkey98765'\n" > /fx/wireless
printf "wireless.wl0.ssid='Home'\nwireless.wl0.key2='wepkey98765'\n" > /fx/uci-show
printf 'ssid=Home\nwpa_passphrase=hunter2pass\nwpa_psk=abcdef0123\nchannel=6\n' > /fx/hostapd.conf
printf -- '-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAAsecretkeymaterial\n-----END OPENSSH PRIVATE KEY-----\n' > /fx/id_test
printf 'KEYBYTES\000\001secretbinarykey\000' > /fx/dropbear_ed25519_host_key
printf 'user * pppsecret99 *\n' > /fx/chap-secrets
printf '{"user":"a","password":"jsonsecret77","n":1}\n' > /fx/conf.json
"""

SECRETS = ["hashhashhashhashhashha", "hunter2secret", "wepkey98765", "hunter2pass", "abcdef0123",
           "secretkeymaterial", "secretbinarykey", "pppsecret99", "jsonsecret77"]


class FilesFixture(OpenWrtTestCase):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        if cls.container is None:
            raise unittest.SkipTest("needs a container")
        try:
            cls.container.sh(SETUP)
        except BaseException:
            cls.tearDownClass()
            raise


class TestReadFile(FilesFixture):
    def test_text_paging(self):
        text = self.tool_ok("read_file", ROM, path="/fx/text.txt", offset=10, limit=5)
        body = re.findall(r"^ +(\d+)  (line \d+)$", text, flags=re.M)
        self.assertEqual(body, [(str(i), f"line {i}") for i in range(11, 16)])
        self.assertIn("[lines 11-15 of 500; continue with offset=15]", text)
        self.assertIn("text file", text)
        self.assertIn("same as the firmware image", text)

    def test_text_end_and_beyond(self):
        text = self.tool_ok("read_file", ROM, path="/fx/text.txt", offset=495, limit=50)
        self.assertIn("line 500", text)
        self.assertIn("[lines 496-500, end of file]", text)
        text = self.tool_ok("read_file", ROM, path="/fx/text.txt", offset=900)
        self.assertIn("no lines after offset 900; the file has 500 lines", text)

    def test_default_limit_and_no_numbers(self):
        text = self.tool_ok("read_file", ROM, path="/fx/text.txt", line_numbers=False)
        self.assertIn("\nline 200\n", text)
        self.assertNotIn("line 201", text)
        self.assertIn("continue with offset=200", text)

    def test_header_reports_image_state(self):
        self.assertIn("image  CHANGED", self.tool_ok("read_file", ROM, path="/fx/changed.txt"))
        self.assertIn("image  not in the firmware image", self.tool_ok("read_file", ROM, path="/fx/new.txt"))
        self.assertIn("not compared", self.tool_ok("read_file", path="/fx/new.txt"))

    def test_binary_auto_is_hex(self):
        text = self.tool_ok("read_file", ROM, path="/fx/bin.dat")
        self.assertIn("binary file", text)
        self.assertIn("00000000  4d 41 47 49 43 00 01 02", text)
        self.assertIn("|MAGIC", text)
        self.assertIn("continue with view=hex offset=256", text)

    def test_hex_offset_and_length(self):
        text = self.tool_ok("read_file", ROM, path="/fx/bin.dat", view="hex", offset=16, limit=32)
        rows = [ln for ln in text.splitlines() if re.match(r"^[0-9a-f]{8}  ", ln)]
        self.assertEqual([r[:8] for r in rows], ["00000010", "00000020"])
        self.assertIn("[bytes 16-47 of", text)
        raw = self.sh("head -c 48 /fx/bin.dat | tail -c 32 | hexdump -C | head -n 1")
        self.assertEqual(rows[0][8:], raw.splitlines()[0][8:])

    def test_strings_view_and_paging(self):
        text = self.tool_ok("read_file", ROM, path="/fx/bin.dat", view="strings", min_length=8)
        self.assertIn("hello-world-string", text)
        self.assertIn("tail-marker-xyz", text)
        self.assertNotIn("MAGIC\n", text)  # shorter than min_length
        page = self.tool_ok("read_file", ROM, path="/fx/bin.dat", view="strings", min_length=8, offset=1, limit=1)
        self.assertIn("tail-marker-xyz", page)
        self.assertNotIn("hello-world-string", page)

    def test_refuses_what_could_hang(self):
        for path, why in (("/fx/fifo", "not a regular file"),
                          ("/fx/proclink", "links into /proc"),
                          ("/fx/devlink", "links into /proc, /sys and /dev"),
                          ("/fx/dangling", "dangling symlink"),
                          ("/dev/null", "not a regular file"),
                          ("/proc/kmsg", "blocks"),
                          ("/fx", "is a directory"),
                          ("/fx/nope", "no such file")):
            text, err = self.tool("read_file", ROM, timeout=30, path=path)
            self.assertTrue(err, f"{path}: {text}")
            self.assertIn(why, text, path)
        for view in ("hex", "strings"):
            text, err = self.tool("read_file", ROM, timeout=30, path="/fx/fifo", view=view)
            self.assertTrue(err, text)

    def test_bad_arguments(self):
        for args in ({"path": "relative/x"}, {}, {"path": "/fx/text.txt", "view": "raw"},
                     {"path": "/fx/text.txt", "limit": 0}, {"path": "/fx/text.txt", "offset": -1}):
            text, err = self.tool("read_file", ROM, **args)
            self.assertTrue(err, f"{args}: {text}")
            self.assertTrue(text.startswith("error:"), text)

    def test_follows_safe_links_and_kernel_files(self):
        self.assertIn("line 1\n", self.tool_ok("read_file", ROM, path="/fx/goodlink", limit=3))
        text = self.tool_ok("read_file", ROM, path="/proc/mounts")
        self.assertIn(" / ", text)
        self.assertIn("kernel file", text)
        self.assertIn("MemTotal", self.tool_ok("read_file", ROM, path="/proc/meminfo"))

    def test_text_view_masks_secrets(self):
        out = ""
        for name in ("shadow", "wireless", "uci-show", "hostapd.conf", "id_test", "chap-secrets", "conf.json"):
            out += self.tool_ok("read_file", ROM, path=f"/fx/{name}")
        for s in SECRETS:
            self.assertNotIn(s, out)
        self.assertIn("ssid 'Home'", out)
        self.assertIn("channel=6", out)
        self.assertIn('"user":"a"', out)
        self.assertIn("redacted", out)

    def test_raw_views_do_not_leak_secrets(self):
        out = ""
        for name in ("shadow", "wireless", "uci-show", "hostapd.conf", "id_test", "chap-secrets", "conf.json",
                     "dropbear_ed25519_host_key"):
            for view in ("hex", "strings", "auto"):
                text, _ = self.tool("read_file", ROM, path=f"/fx/{name}", view=view, min_length=4)
                # the ASCII column of hexdump wraps every 16 bytes: join it again
                out += text + "".join(re.findall(r"\|(.*)\|$", text, flags=re.M))
        for s in SECRETS:
            self.assertNotIn(s, out)
        text, err = self.tool("read_file", ROM, path="/fx/dropbear_ed25519_host_key", view="hex")
        self.assertTrue(err)
        self.assertIn("redaction is on", text)

    def test_redaction_off_shows_everything(self):
        self.assertIn("hunter2secret", self.tool_ok("read_file", PLAIN, path="/fx/wireless"))
        self.assertIn("hunter2pass", self.tool_ok("read_file", PLAIN, path="/fx/hostapd.conf"))
        text = self.tool_ok("read_file", PLAIN, path="/fx/dropbear_ed25519_host_key", view="strings", min_length=4)
        self.assertIn("secretbinarykey", text)


class TestListDir(FilesFixture):
    def entries(self, text):
        out = {}
        for ln in text.splitlines():
            m = re.match(r"^([fdlcbps]) (\d{4}) (\S+)\s+(\S+) (\d{4}-\d\d-\d\d \d\d:\d\d:\d\d) (\S+)\s+(/.*)$", ln)
            if m:
                path, _, target = m.group(7).partition(" -> ")
                out[path] = {"type": m.group(1), "mode": m.group(2), "owner": m.group(3), "size": m.group(4),
                             "mtime": m.group(5), "image": m.group(6), "target": target}
        return out

    def test_columns(self):
        e = self.entries(self.tool_ok("list_dir", ROM, path="/fx"))
        self.assertEqual(e["/fx/text.txt"]["type"], "f")
        self.assertEqual(e["/fx/text.txt"]["owner"], "root:root")
        self.assertEqual(e["/fx/text.txt"]["size"], "4392")
        self.assertEqual(e["/fx/sub"]["type"], "d")
        self.assertEqual(e["/fx/fifo"]["type"], "p")
        self.assertEqual(e["/fx/suid"]["mode"], "4755")
        self.assertEqual(e["/fx/ww"]["mode"], "0666")
        self.assertEqual(e["/fx/proclink"]["type"], "l")
        self.assertEqual(e["/fx/proclink"]["target"], "/proc/1/mem")
        self.assertEqual(e["/fx/old.txt"]["mtime"], "2020-01-01 00:00:00")
        self.assertNotIn("/fx/sub/deep", e)

    def test_image_column(self):
        e = self.entries(self.tool_ok("list_dir", ROM, path="/fx"))
        self.assertEqual(e["/fx/text.txt"]["image"], "same")
        self.assertEqual(e["/fx/changed.txt"]["image"], "CHANGED")
        self.assertEqual(e["/fx/new.txt"]["image"], "new")
        self.assertEqual(e["/fx/sub"]["image"], "same")
        e = self.entries(self.tool_ok("list_dir", path="/fx"))
        self.assertEqual(e["/fx/text.txt"]["image"], "-")
        e = self.entries(self.tool_ok("list_dir", ROM, path="/fx", compare_image=False))
        self.assertEqual(e["/fx/changed.txt"]["image"], "-")

    def test_depth_and_order(self):
        text = self.tool_ok("list_dir", ROM, path="/fx", depth=3)
        e = self.entries(text)
        self.assertIn("/fx/sub/deep/tool.sh", e)
        paths = list(e)
        self.assertEqual(paths, sorted(paths))

    def test_cap(self):
        text = self.tool_ok("list_dir", ROM, path="/fx", depth=3, max_entries=4)
        self.assertEqual(len(self.entries(text)), 4)
        self.assertRegex(text, r"\[showing 4 of \d+ entries")

    def test_special_directories(self):
        text = self.tool_ok("list_dir", path="/proc", depth=4, max_entries=2000)
        self.assertIn("depth forced to 1", text)
        self.assertIn("/proc/meminfo", text)
        self.assertNotIn("/proc/1/", text)
        text = self.tool_ok("list_dir", path="/", depth=2, max_entries=2000)
        self.assertIn(" /proc\n", text)  # the mount point itself
        self.assertNotIn("/proc/meminfo", text)  # but not what is inside

    def test_errors(self):
        text, err = self.tool("list_dir", path="/fx/text.txt")
        self.assertTrue(err)
        self.assertIn("not a directory", text)
        text, err = self.tool("list_dir", path="/fx/missing")
        self.assertTrue(err)
        text, err = self.tool("list_dir", path="fx")
        self.assertTrue(err)


class TestFindFiles(FilesFixture):
    def find(self, env=None, **args):
        # not self.tool(): its own "name" parameter collides with find_files' "name"
        return self.session(env).call_tool("find_files", args)

    def find_ok(self, env=None, **args):
        text, err = self.find(env, **args)
        self.assertFalse(err, text)
        return text

    def paths(self, text):
        return re.findall(r"^[fdlcbps] \d{4} .*? (/fx/\S+)(?: -> .*)?$", text, flags=re.M)

    def test_name_and_type(self):
        text = self.find_ok(ROM, path="/fx", name="*.txt", type="file")
        self.assertEqual(sorted(self.paths(text)),
                         ["/fx/changed.txt", "/fx/new.txt", "/fx/old.txt", "/fx/text.txt"])
        text = self.find_ok(ROM, path="/fx", type="fifo")
        self.assertEqual(self.paths(text), ["/fx/fifo"])
        text = self.find_ok(ROM, path="/fx", name="*/deep/*")
        self.assertEqual(self.paths(text), ["/fx/sub/deep/tool.sh"])

    def test_permissions(self):
        self.assertEqual(self.paths(self.find_ok(ROM, path="/fx", perm="suid")), ["/fx/suid"])
        self.assertEqual(self.paths(self.find_ok(ROM, path="/fx", perm="world_writable")), ["/fx/ww"])
        self.assertEqual(sorted(self.paths(self.find_ok(ROM, path="/fx", perm="executable"))),
                         ["/fx/sub/deep/tool.sh", "/fx/suid"])
        self.assertIn("no matches", self.find_ok(ROM, path="/fx", perm="sgid"))

    def test_time_filters(self):
        self.assertEqual(self.paths(self.find_ok(ROM, path="/fx", type="file",
                                                 modified_before_minutes=1440)), ["/fx/old.txt"])
        recent = self.paths(self.find_ok(ROM, path="/fx", type="file", modified_within_minutes=1440))
        self.assertIn("/fx/new.txt", recent)
        self.assertNotIn("/fx/old.txt", recent)
        newer = self.paths(self.find_ok(ROM, path="/fx", type="file", newer_than="/fx/old.txt"))
        self.assertIn("/fx/text.txt", newer)
        self.assertNotIn("/fx/old.txt", newer)

    def test_size_filters(self):
        self.assertEqual(self.paths(self.find_ok(ROM, path="/fx", min_size=5000)), ["/fx/big.bin"])
        self.assertEqual(self.paths(self.find_ok(ROM, path="/fx", min_size=5001)), [])
        small = self.paths(self.find_ok(ROM, path="/fx", max_size=4))
        self.assertIn("/fx/new.txt", small)  # 4 bytes
        self.assertNotIn("/fx/changed.txt", small)  # 8 bytes

    def test_cap_and_order(self):
        text = self.find_ok(ROM, path="/fx", max_results=3)
        self.assertEqual(len(self.paths(text)), 3)
        self.assertRegex(text, r"\[showing 3 of \d+ matches \(the newest\)")
        self.assertNotIn("/fx/old.txt", text)  # the oldest entry is cut first
        text = self.find_ok(ROM, path="/fx", order="path", max_depth=1, type="file")
        got = self.paths(text)
        self.assertEqual(got, sorted(got))
        self.assertNotIn("/fx/sub/deep/tool.sh", got)

    def test_image_column(self):
        text = self.find_ok(ROM, path="/fx", name="changed.txt")
        self.assertRegex(text, r"CHANGED\s+/fx/changed.txt")

    def test_default_roots_skip_kernel_filesystems(self):
        text = self.find_ok(None, name="meminfo")
        self.assertIn("no matches", text)
        text = self.find_ok(None, name="tool.sh")
        self.assertIn("/fx/sub/deep/tool.sh", text)
        text, err = self.find(None, path="/proc")
        self.assertTrue(err)

    def test_bad_arguments(self):
        for args in ({"path": "/fx/missing"}, {"type": "pipe"}, {"perm": "777"}, {"order": "size"},
                     {"newer_than": "/fx/missing"}, {"max_results": 0}):
            text, err = self.find(ROM, **args)
            self.assertTrue(err, f"{args}: {text}")


class TestFileHash(FilesFixture):
    def test_hash_and_image_comparison(self):
        text = self.tool_ok("file_hash", ROM, paths=["/fx/changed.txt", "/fx/text.txt", "/fx/new.txt"])
        blocks = dict((b.splitlines()[0], b) for b in text.strip().split("\n\n"))
        self.assertIn(hashlib.sha256(b"changed\n").hexdigest(), blocks["/fx/changed.txt"])
        self.assertIn("DIFFERENT: " + hashlib.sha256(b"original\n").hexdigest(), blocks["/fx/changed.txt"])
        self.assertIn("same content", blocks["/fx/text.txt"])
        self.assertIn("not in the firmware image", blocks["/fx/new.txt"])
        self.assertIn("8 bytes", blocks["/fx/changed.txt"])

    def test_md5(self):
        text = self.tool_ok("file_hash", ROM, paths=["/fx/changed.txt"], algorithm="md5")
        self.assertIn(hashlib.md5(b"changed\n").hexdigest(), text)

    def test_package_owner(self):
        text = self.tool_ok("file_hash", paths=["/bin/busybox", "/fx/new.txt"])
        self.assertRegex(text, r"package  busybox \(")
        self.assertIn("none owns this path", text)
        self.assertIn("no usable firmware image", text)

    def test_refusals_do_not_stop_the_rest(self):
        text = self.tool_ok("file_hash", ROM, paths=["/fx/fifo", "/fx/proclink", "/dev/null", "/fx/nope",
                                                     "relative", "/fx/new.txt"])
        self.assertEqual(text.count("error "), 5)
        self.assertIn(hashlib.sha256(b"new\n").hexdigest(), text)

    def test_limits(self):
        text, err = self.tool("file_hash", ROM, paths=[f"/fx/{i}" for i in range(51)])
        self.assertTrue(err)
        self.assertIn("at most 50", text)
        text, err = self.tool("file_hash", ROM)
        self.assertTrue(err)
        text, err = self.tool("file_hash", ROM, paths=["/fx/new.txt"], algorithm="sha1")
        self.assertTrue(err)


class TestReviewFindings(FilesFixture):
    """Round 3: what an independent review found in the file tools."""

    def find(self, env=None, **args):
        text, err = self.session(env).call_tool("find_files", args)
        self.assertFalse(err, text)
        return text

    def test_only_the_servers_own_temp_dir_is_left_out(self):
        # F3: /tmp/openwrt-mcp.<anything> used to be invisible, a ready hiding place
        self.sh("mkdir -p /tmp/openwrt-mcp.evil && printf '#!/bin/sh\\nid\\n' > /tmp/openwrt-mcp.evil/run.sh && "
                "chmod 755 /tmp/openwrt-mcp.evil/run.sh")
        self.assertIn("/tmp/openwrt-mcp.evil/run.sh", self.find(ROM, name="run.sh"))
        text = self.tool_ok("list_dir", ROM, path="/tmp", depth=2)
        self.assertIn("/tmp/openwrt-mcp.evil/run.sh", text)
        own = re.search(r"temp dir +(\S+)", self.tool_ok("server_info", ROM)).group(1)
        self.assertNotIn(own + "/", text)

    def test_hash_of_a_file_that_cannot_be_read_is_never_printed(self):
        # F4: /proc/mounts got the SHA-256 of the empty input
        empty = hashlib.sha256(b"").hexdigest()
        text = self.tool_ok("file_hash", ROM, paths=["/proc/mounts", "/proc/version", "/fx/new.txt"])
        self.assertNotIn(empty, text)
        self.assertIn(hashlib.sha256(b"new\n").hexdigest(), text)
        want = self.sh("sha256sum < /proc/version").split()[0]
        self.assertIn(want, text)
        text = self.tool_ok("file_hash", ROM, paths=["/proc/mounts"], algorithm="md5")
        self.assertNotIn(hashlib.md5(b"").hexdigest(), text)

    def test_fifo_in_the_package_database_does_not_hang(self):
        # F5: find -name '*.list' without -type f fed a FIFO to awk
        self.sh("mkdir -p /usr/lib/opkg/info && mkfifo /usr/lib/opkg/info/zz.list")
        try:
            text, err = self.tool("file_hash", ROM, timeout=40, paths=["/etc/hosts"])
            self.assertFalse(err, text)
            self.assertRegex(text, r"sha256 +[0-9a-f]{64}")
        finally:
            self.sh("rm -f /usr/lib/opkg/info/zz.list")

    def test_fifo_in_place_of_a_system_file_does_not_hang(self):
        # F5: /etc/group and /etc/passwd were read without a regular-file check.
        # The FIFO is made and removed through the running server: "docker exec" reads
        # /etc/group itself and would hang on the FIFO.
        s = self.session(ROM)
        s.call_tool("exec", {"command": "mv /etc/group /etc/group.real && mkfifo /etc/group"})
        try:
            text, err = s.call_tool("list_dir", {"path": "/fx"}, 40)
            self.assertFalse(err, text)
            self.assertIn("/fx/text.txt", text)
            self.assertRegex(text, r"f 0644 root:0 +4392 .* /fx/text\.txt")  # no group names without the file
        finally:
            s.call_tool("exec", {"command": "rm -f /etc/group && mv /etc/group.real /etc/group"})
            self.assertIn("root", self.sh("head -n 1 /etc/group"))

    def test_hex_view_without_hexdump_is_an_error(self):
        # F10
        self.sh("mv /usr/bin/hexdump /usr/bin/hexdump.off")
        try:
            text, err = self.tool("read_file", ROM, path="/fx/bin.dat", view="hex")
            self.assertTrue(err, text)
            self.assertIn("hexdump: not available", text)
            self.assertNotIn("not found", text)
        finally:
            self.sh("mv /usr/bin/hexdump.off /usr/bin/hexdump")

    def test_more_key_files_refuse_raw_views(self):
        # F9: dropbear client keys, hostapd per-station PSKs, WireGuard key files
        self.sh("mkdir -p /fx/etc/wireguard && printf 'KEY\\000\\001clientkeybytes\\000' > /fx/id_dropbear && "
                "echo '00:11:22:33:44:55 stationpsk123' > /fx/hostapd-wl0.psk && "
                "echo 'aGVsbG9oZWxsb2hlbGxvaGVsbG9oZWxsb2hlbGxvaGVsbG8=' > /fx/etc/wireguard/privatekey && "
                "echo 'aGVsbG9oZWxsb2hlbGxvaGVsbG9oZWxsb2hlbGxvaGVsbG8=' > /fx/etc/wireguard/wg0.key")
        for name in ("id_dropbear", "hostapd-wl0.psk", "etc/wireguard/privatekey", "etc/wireguard/wg0.key"):
            for view in ("hex", "strings"):
                text, err = self.tool("read_file", ROM, path=f"/fx/{name}", view=view, min_length=4)
                self.assertTrue(err, f"{name} {view}: {text}")
                self.assertIn("redaction is on", text)


if __name__ == "__main__":
    unittest.main()
