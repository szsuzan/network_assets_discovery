"""Unit tests for the scanner agent's pure logic: target validation, nmap XML
parsing, port arithmetic, subnet filtering, privilege detection and MAC
handling.

These need no server, no network and no privileges, so they are the fast tier
that should run on every change.

    python3 -m unittest discover -s backend/tests -t backend -v
"""
import importlib.util
import os
import unittest

_AGENT = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(
    os.path.abspath(__file__)))), "agent", "scanner_agent.py")
_spec = importlib.util.spec_from_file_location("scanner_agent", _AGENT)
sa = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(sa)


# Captured nmap XML shapes, matching what nmap 7.x actually emits.
XML_UP = """<?xml version="1.0"?>
<nmaprun><host><status state="up" reason="arp-response"/>
<address addr="192.168.1.50" addrtype="ipv4"/>
<address addr="AA:BB:CC:DD:EE:FF" addrtype="mac" vendor="Cisco Systems"/>
<hostnames><hostname name="router.lan" type="PTR"/></hostnames>
</host></nmaprun>"""
XML_DOWN = """<?xml version="1.0"?><nmaprun><host>
<status state="down" reason="no-response"/>
<address addr="192.168.1.99" addrtype="ipv4"/></host></nmaprun>"""
XML_NOMAC = """<?xml version="1.0"?><nmaprun><host>
<status state="up" reason="syn-ack"/>
<address addr="192.168.1.51" addrtype="ipv4"/></host></nmaprun>"""
XML_IPV6 = """<?xml version="1.0"?><nmaprun><host>
<status state="up" reason="syn-ack"/>
<address addr="fe80::1" addrtype="ipv6"/></host></nmaprun>"""

XML_HOST = """<?xml version="1.0"?>
<nmaprun><host><status state="up" reason="syn-ack"/>
<address addr="192.168.1.50" addrtype="ipv4"/>
<address addr="AA:BB:CC:DD:EE:FF" addrtype="mac" vendor="Apple"/>
<hostnames/>
<ports>
<port protocol="tcp" portid="22"><state state="open"/><service name="ssh" product="OpenSSH" version="9.6"/>
<script id="ssh-hostkey" output="2048 aa:bb"/></port>
<port protocol="tcp" portid="80"><state state="open"/><service name="http" product="nginx"/></port>
<port protocol="tcp" portid="23"><state state="closed"/><service name="telnet"/></port>
<port protocol="tcp" portid="8080"><state state="filtered"/></port>
</ports>
<os><osmatch name="Linux 5.X" accuracy="95"/><osmatch name="Linux 4.X" accuracy="60"/></os>
</host></nmaprun>"""
XML_OSCLASS = """<?xml version="1.0"?><nmaprun><host><status state="up"/>
<address addr="10.0.0.5" addrtype="ipv4"/>
<os><osclass vendor="Cisco" osfamily="Embedded" osgen="3.15" accuracy="88"/></os>
</host></nmaprun>"""
XML_SMB_NAME = XML_HOST.replace("2048 aa:bb", "NetBIOS computer name: DESKTOP-ABC123")
XML_SMB_MULTILINE = """<?xml version="1.0"?><nmaprun><host><status state="up"/>
<address addr="10.0.0.9" addrtype="ipv4"/>
<ports><port protocol="tcp" portid="445"><state state="open"/>
<script id="smb-os-discovery" output="OS: Windows&#xa;NetBIOS computer name: SRV-FILE"/></port></ports>
</host></nmaprun>"""
XML_DOWN_HOST = """<?xml version="1.0"?><nmaprun><host><status state="down"/>
<address addr="10.0.0.6" addrtype="ipv4"/></host></nmaprun>"""


class TestValidTarget(unittest.TestCase):
    """A compromised or buggy server must never be able to smuggle extra nmap
    arguments through a target string, so anything that is not a plain IPv4
    address or CIDR has to be refused."""

    def test_accepts_plain_ipv4_and_cidr(self):
        for t in ("192.168.1.1", "192.168.1.0/24", "10.0.0.1/32",
                  "172.16.0.0/12", "0.0.0.0/0", "  10.1.1.1  "):
            with self.subTest(target=t):
                self.assertTrue(sa._valid_target(t))

    def test_rejects_non_ipv4(self):
        for t in ("", "   ", None, 123, [], "example.com", "--script=http-vuln-*",
                  "192.168.1.1; rm -rf /", "192.168.1.1 extra", "999.1.1.1",
                  "192.168.1.0/33", "-sS", "--top-ports", "192.168.1.0/24 -sV",
                  "localhost", "192.168.1.-1", "0x7f000001"):
            with self.subTest(target=t):
                self.assertFalse(sa._valid_target(t))

    def test_rejects_ipv6_deliberately(self):
        """IPv6 is refused on purpose. nmap needs an explicit -6 for IPv6
        literals, both XML parsers only read addrtype="ipv4", and vendor/OS
        detection is ARP-based. Accepting ::1 and reporting zero hosts looks
        like a working scan that found nothing."""
        for t in ("::1", "2001:db8::/32", "fe80::1/64"):
            with self.subTest(target=t):
                self.assertFalse(sa._valid_target(t))


class TestSanePortRange(unittest.TestCase):
    def test_normalises(self):
        self.assertEqual(sa._sane_port_range("80"), "80")
        self.assertEqual(sa._sane_port_range(" 80 , 443 "), "80,443")
        self.assertEqual(sa._sane_port_range("1-65535"), "1-65535")

    def test_defaults_when_missing(self):
        self.assertEqual(sa._sane_port_range(""), "1-10000")
        self.assertEqual(sa._sane_port_range(None), "1-10000")

    def test_rejects_malformed(self):
        for bad in ("abc", "0", "65536", "100-80", "-sS", "80;rm", "1-1000000",
                    "--top-ports", "-p80", "80,,443", "80-", "-1"):
            with self.subTest(value=bad):
                with self.assertRaises(Exception):
                    sa._sane_port_range(bad)


class TestParseDiscovery(unittest.TestCase):
    def test_up_host(self):
        d = sa.parse_discovery(XML_UP)
        self.assertEqual(len(d), 1)
        self.assertEqual(d[0]["ip"], "192.168.1.50")
        self.assertEqual(d[0]["mac"], "AA:BB:CC:DD:EE:FF")
        self.assertEqual(d[0]["vendor"], "Cisco Systems")

    def test_hostname_trailing_dot_stripped(self):
        self.assertEqual(sa.parse_discovery(XML_UP)[0]["hostname"], "router.lan")

    def test_down_host_is_kept_with_state(self):
        d = sa.parse_discovery(XML_DOWN)
        self.assertEqual(d[0]["state"], "down")

    def test_up_host_without_mac(self):
        d = sa.parse_discovery(XML_NOMAC)
        self.assertIsNone(d[0]["mac"])
        self.assertEqual(d[0]["state"], "up")

    def test_ipv6_only_host_is_skipped_not_fatal(self):
        self.assertEqual(sa.parse_discovery(XML_IPV6), [])

    def test_malformed_xml_returns_empty(self):
        for bad, label in (("", "empty"), ("not xml", "garbage"),
                           ("<nmaprun><host>", "truncated")):
            with self.subTest(label=label):
                self.assertEqual(sa.parse_discovery(bad), [])
        self.assertEqual(sa.parse_discovery(None), [])


class TestParseHostXml(unittest.TestCase):
    def setUp(self):
        self.h = sa.parse_host_xml(XML_HOST)

    def test_parses(self):
        self.assertIsNotNone(self.h)

    def test_only_open_ports_kept(self):
        self.assertEqual([p["port"] for p in self.h["ports"]], [22, 80])

    def test_service_and_version(self):
        self.assertEqual(self.h["ports"][0]["service"], "ssh")
        self.assertEqual(self.h["ports"][0]["version"], "9.6")

    def test_script_output_lands_in_banner(self):
        self.assertIn("2048 aa:bb", self.h["ports"][0]["banner"])

    def test_best_osmatch_wins(self):
        self.assertEqual(self.h["os_guess"], "Linux 5.X")
        self.assertEqual(self.h["os_confidence"], 95)

    def test_mac_and_vendor(self):
        self.assertEqual(self.h["mac"], "AA:BB:CC:DD:EE:FF")

    def test_osclass_fallback(self):
        h = sa.parse_host_xml(XML_OSCLASS)
        self.assertEqual(h.get("os_guess"), "Cisco Embedded 3.15")

    def test_key_only_banner_yields_no_hostname(self):
        self.assertIsNone(self.h["hostname"])

    def test_windows_name_promoted_from_smb_banner(self):
        self.assertEqual(sa.parse_host_xml(XML_SMB_NAME)["hostname"], "DESKTOP-ABC123")

    def test_hostname_from_multiline_script_output(self):
        self.assertEqual(sa.parse_host_xml(XML_SMB_MULTILINE)["hostname"], "SRV-FILE")

    def test_down_host_is_not_reported_up(self):
        """nmap said state="down"; ingesting that as "up" would record dead
        hosts as live. This status used to be hardcoded to "up"."""
        h = sa.parse_host_xml(XML_DOWN_HOST)
        self.assertEqual(h["status"], "down")

    def test_malformed_xml_returns_none(self):
        for bad, label in (("", "empty"), ("garbage", "garbage"),
                           ("<nmaprun></nmaprun>", "no host")):
            with self.subTest(label=label):
                self.assertIsNone(sa.parse_host_xml(bad))
        self.assertIsNone(sa.parse_host_xml(None))


class TestHostnameFromBanner(unittest.TestCase):
    def test_nbstat_row_without_space_before_suffix(self):
        """nbtstat rows look like 'DESKTOP-ABC123<00>   UNIQUE' with no space
        before <00>. The old regex required one there, so it could never match
        the exact format it was written for and every such Windows name was
        silently dropped."""
        for banner in ("NAME<00> UNIQUE", "DESKTOP-ABC<00>   UNIQUE",
                       "NAME <00> UNIQUE"):
            with self.subTest(banner=banner):
                name = sa._hostname_from_banner([{"banner": banner}])
                self.assertTrue(name and "<00>" not in name, name)

    def test_key_value_forms(self):
        for banner in ("NetBIOS computer name: SRV9", "Computer name: PC42",
                       "Workstation: BOX"):
            with self.subTest(banner=banner):
                self.assertTrue(sa._hostname_from_banner([{"banner": banner}]))


class TestPrivilegedFlagStripping(unittest.TestCase):
    """Unprivileged nmap prints a usage error and QUITS when handed -sS/-O/-PR,
    which used to make every host come back with no service or version data."""

    def test_strips_privileged_flags(self):
        for flag in ("-O", "-sS", "-sU", "-PR", "-PS", "-PA", "-A"):
            with self.subTest(flag=flag):
                args = sa._strip_privileged_flags(["nmap", flag, "-sT", "1.1.1.1"])
                self.assertNotIn(flag, args)

    def test_keeps_privilege_free_flags(self):
        for flag in ("-sn", "-sT", "-sV", "-Pn", "--script=http-title"):
            with self.subTest(flag=flag):
                self.assertIn(flag, sa._strip_privileged_flags(["nmap", flag, "-sS"]))

    def test_never_returns_empty(self):
        self.assertIn("nmap", sa._strip_privileged_flags(["nmap", "-sS"]))


class TestUsableSubnet(unittest.TestCase):
    def test_keeps_routable_ranges(self):
        for ip, plen in (("192.168.1.5", "24"), ("10.0.0.1", "8"), ("172.16.5.3", "12")):
            with self.subTest(ip=ip):
                self.assertIsNotNone(sa._usable_subnet(ip, plen))

    def test_drops_unscannable_ranges(self):
        for ip, plen, why in (
            ("127.0.0.1", "8", "loopback"),
            ("169.254.1.1", "16", "link-local"),
            ("10.0.0.5", "31", "/31"), ("10.0.0.5", "32", "/32"),
            ("224.0.0.1", "4", "multicast"),
            ("255.255.255.255", "32", "broadcast"),
            ("0.0.0.0", "0", "unspecified"),
            ("1.2.3.4", "0", "/0 sweeps the whole internet"),
            ("240.0.0.1", "4", "reserved"),
        ):
            with self.subTest(ip=ip, prefix=plen, why=why):
                self.assertIsNone(sa._usable_subnet(ip, plen))

    def test_garbage_prefix(self):
        self.assertIsNone(sa._usable_subnet("192.168.1.5", "abc"))


class TestIpInSubnet(unittest.TestCase):
    def test_hit_and_miss(self):
        self.assertTrue(sa._ip_in_subnet("192.168.1.7", "192.168.1.0/24"))
        self.assertFalse(sa._ip_in_subnet("192.168.2.7", "192.168.1.0/24"))

    def test_bad_cidr_is_not_a_match(self):
        self.assertFalse(sa._ip_in_subnet("192.168.2.7", "garbage"))


class TestPortArithmetic(unittest.TestCase):
    def test_range_to_set(self):
        self.assertEqual(sa._range_to_ports_set("80,443,8000-8002"),
                         {80, 443, 8000, 8001, 8002})

    def test_full_range_size(self):
        self.assertEqual(len(sa._range_to_ports_set("1-10000")), 10000)

    def test_leftover_spec(self):
        """Everything that was NOT scanned, as a compact range list: a scan of
        80/443 leaves 1-79,81-442,444-65535 for a later top-ports pass."""
        left = sa._leftover_ports_spec({80, 443})
        self.assertTrue(left)
        ports = sa._range_to_ports_set(left)
        self.assertNotIn(80, ports)
        self.assertNotIn(443, ports)
        self.assertIn(81, ports)
        self.assertIn(444, ports)


class TestPrepareNmapArgs(unittest.TestCase):
    """Both privilege branches must be covered from an unprivileged shell.
    The privileged branch previously prepended --privileged BEFORE the binary
    name, so subprocess tried to execute a program called "--privileged" and
    every scan on a CAP_NET_RAW-but-not-root agent died with
    FileNotFoundError. That shipped because only the unprivileged path had ever
    been executed."""

    BASE = ["nmap", "-sS", "-O", "-p", "22", "192.168.1.5", "-oX", "-"]

    def test_privileged_flag_follows_the_binary(self):
        a = sa._prepare_nmap_args(self.BASE, True, is_windows=False)
        self.assertEqual(a[0], "nmap")
        self.assertEqual(a[1], "--privileged")

    def test_privileged_argv_keeps_every_scan_argument(self):
        a = sa._prepare_nmap_args(self.BASE, True, is_windows=False)
        self.assertEqual(a[2:], self.BASE[1:])

    def test_privileged_keeps_raw_socket_flags(self):
        a = sa._prepare_nmap_args(self.BASE, True, is_windows=False)
        for flag in ("-sS", "-O"):
            self.assertIn(flag, a)

    def test_flag_not_duplicated(self):
        a = sa._prepare_nmap_args(["nmap", "--privileged", "-sS"], True, False)
        self.assertEqual(a.count("--privileged"), 1)

    def test_windows_never_gets_the_posix_flag(self):
        """Windows nmap relies on Npcap; --privileged is not an nmap flag that
        means anything there and Npcap installs must not be disturbed."""
        a = sa._prepare_nmap_args(self.BASE, True, is_windows=True)
        self.assertNotIn("--privileged", a)
        self.assertIn("-sS", a)

    def test_unprivileged_strips_instead_of_adding(self):
        a = sa._prepare_nmap_args(self.BASE, False, is_windows=False)
        self.assertNotIn("--privileged", a)
        self.assertNotIn("-sS", a)
        self.assertNotIn("-O", a)

    def test_empty_argv_is_safe_at_either_privilege_level(self):
        """run_nmap([]) must short-circuit before any modification, or a
        privileged process tries to execute the empty argv."""
        for priv in (True, False):
            with self.subTest(privileged=priv):
                self.assertEqual(sa._prepare_nmap_args([], priv, False), [])
                self.assertEqual(sa.run_nmap([]), "")


class TestMacToIpCache(unittest.TestCase):
    """_mac_to_ip records MAC->IP into the shared passive map so the reverse
    lookup can attribute sniffed traffic to a discovered device."""

    def setUp(self):
        sa._passive_shared.pop("_mac2ip", None)

    def test_records_real_macs(self):
        sa._mac_to_ip("00:11:22:33:44:55", "192.168.1.5")
        sa._mac_to_ip("AA:BB:CC:DD:EE:FF", "192.168.1.6")
        m = sa._passive_shared["_mac2ip"]
        self.assertEqual(m.get("00:11:22:33:44:55"), "192.168.1.5")
        self.assertEqual(m.get("aa:bb:cc:dd:ee:ff"), "192.168.1.6")

    def test_first_write_wins(self):
        sa._mac_to_ip("11:22:33:44:55:66", "1.1.1.1")
        sa._mac_to_ip("11:22:33:44:55:66", "2.2.2.2")
        self.assertEqual(sa._passive_shared["_mac2ip"]["11:22:33:44:55:66"], "1.1.1.1")

    def test_transport_macs_are_not_devices(self):
        """The old guard compared a full 'ff:ff:ff:ff:ff:ff' string against
        'ffffff', which can never be equal, so broadcast MACs were cached like
        any other and reported as a discovered device."""
        for mac in ("FF:FF:FF:FF:FF:FF", "00:00:00:00:00:00",
                    "01:00:5e:00:00:fb", "33:33:00:00:00:01"):
            with self.subTest(mac=mac):
                sa._passive_shared.pop("_mac2ip", None)
                sa._mac_to_ip(mac, "192.168.1.7")
                self.assertNotIn("_mac2ip", sa._passive_shared)

    def test_malformed_macs_rejected(self):
        for mac in ("00", "", None, "not-a-mac", "00:11:22:33:44"):
            with self.subTest(mac=mac):
                sa._passive_shared.pop("_mac2ip", None)
                sa._mac_to_ip(mac, "192.168.1.7")
                self.assertNotIn("_mac2ip", sa._passive_shared)


class TestMacFromBytes(unittest.TestCase):
    def test_six_bytes(self):
        self.assertEqual(sa._mac_from_bytes(bytes([0x00, 0x11, 0x22, 0x33, 0x44, 0x55])),
                         "00:11:22:33:44:55")

    def test_short_buffers_produce_no_mac(self):
        """A truncated packet slice used to yield bogus 1-5 byte MACs like
        '00', which then reached the database as real addresses."""
        for b in (b"\x00", b"", bytes(5)):
            with self.subTest(length=len(b)):
                self.assertEqual(sa._mac_from_bytes(b), "")

    def test_longer_buffer_truncated_to_six(self):
        self.assertEqual(sa._mac_from_bytes(bytes(7)), "00:00:00:00:00:00")


class TestCleanStr(unittest.TestCase):
    def test_trims(self):
        self.assertEqual(sa._clean_str(b"  hi \n "), "hi")

    def test_blank_is_none(self):
        self.assertIsNone(sa._clean_str(b"   "))


class TestRuntimeWorkers(unittest.TestCase):
    """`agent.workers` is a user setting, so its value reaches
    ThreadPoolExecutor directly. Negative/zero raised ValueError and killed the
    whole phase; a huge value tried to spawn that many threads."""

    def tearDown(self):
        sa._set_runtime_workers({"workers": None})

    def test_clamped_to_sane_range(self):
        for given, expected in ((0, 1), (-3, 1), (None, 1), ("abc", 1),
                                (1, 1), (5, 5), (999, 64), (2 ** 31, 64)):
            with self.subTest(workers=given):
                sa._set_runtime_workers({"workers": given})
                self.assertEqual(sa._p2_workers(), expected)

    def test_defaults_without_task_key(self):
        sa._set_runtime_workers({})
        self.assertGreaterEqual(sa._p2_workers(), 1)


class TestPrivileges(unittest.TestCase):
    def test_returns_tuple(self):
        priv, reason = sa.raw_socket_privileges()
        self.assertIsInstance(priv, bool)
        self.assertIsInstance(reason, str)

    def test_nmap_verdict_matches_capability_check(self):
        """If these disagree the agent advertises capabilities nmap will
        refuse, and every nmap call silently returns nothing."""
        priv, _ = sa.raw_socket_privileges()
        self.assertEqual(sa.nmap_is_privileged(), priv)

    def test_unprivileged_reason_explains_why(self):
        priv, reason = sa.raw_socket_privileges()
        if not priv:
            self.assertIn("CAP_NET_RAW", reason)


class TestLocalSubnets(unittest.TestCase):
    def setUp(self):
        self.subs = sa.local_subnets()

    def test_shape(self):
        self.assertIsInstance(self.subs, list)
        for s in self.subs:
            self.assertIn("/", s)

    def test_never_advertises_loopback(self):
        self.assertFalse([s for s in self.subs if s.startswith("127.")], self.subs)

    def test_keeps_172_16_private_space(self):
        """172.16.0.0/12 is RFC1918 and includes Docker's own 172.17/16
        bridge; dropping every 172.* address hid an entire common LAN."""
        self.assertFalse([s for s in self.subs
                          if s.startswith("172.") and s.endswith("/12")], self.subs)

    def test_host_identity_shape(self):
        for part in sa.host_identity():
            self.assertTrue(part is None or isinstance(part, str))


class TestTypeFromHostname(unittest.TestCase):
    def test_returns_string_or_none(self):
        for name in ("printer", "iphone", "tv", "roku", "chromecast", "nas",
                     "unknown-xyz", None):
            with self.subTest(name=name):
                v = sa._type_from_hostname(name)
                self.assertTrue(v is None or isinstance(v, str))


if __name__ == "__main__":
    unittest.main()