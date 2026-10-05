"""Real nmap execution through the agent's own code path.

Only safe targets are used: loopback and RFC 5737 documentation ranges
(192.0.2.0/24), which route nowhere. The user's LAN is never touched, and no
privileges are required -- which is exactly the degraded mode this tier exists
to cover: an agent started without root must still return usable data instead
of nmap quitting on every host.

Skipped automatically when nmap is not installed.

    python3 -m unittest tests.test_agent_nmap -v
"""
import contextlib
import importlib.util
import os
import shutil
import socket
import threading
import unittest

_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
_AGENT = os.path.join(_ROOT, "agent", "scanner_agent.py")
_spec = importlib.util.spec_from_file_location("scanner_agent", _AGENT)
sa = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(sa)

DOC = "192.0.2.1"     # TEST-NET-1, guaranteed no response
DEAD = "192.0.2.0/29"
LOOP = "127.0.0.1"    # live


@contextlib.contextmanager
def listening_port():
    """A real TCP listener on an ephemeral loopback port.

    These tests must not depend on whether some unrelated service happens to be
    running. An earlier version scanned ports 22/80/8000 with --open and assumed
    an open port would be found; when nothing was listening, nmap emitted only a
    <hosthint> and no <host> element at all, and the test failed for reasons that
    had nothing to do with the code under test.
    """
    srv = socket.socket()
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((LOOP, 0))
    srv.listen(8)
    port = srv.getsockname()[1]
    stop = threading.Event()

    def accept_loop():
        srv.settimeout(0.5)
        while not stop.is_set():
            try:
                conn, _ = srv.accept()
                conn.close()
            except socket.timeout:
                continue
            except OSError:
                break

    th = threading.Thread(target=accept_loop, daemon=True)
    th.start()
    try:
        yield port
    finally:
        stop.set()
        th.join(timeout=2)
        srv.close()


def host_element_count(xml):
    """Count real <host> records.

    `xml.count("<host")` also matches <hosthint> and <hostname>, so it reports a
    successful scan even when nmap returned zero host records.
    """
    import re
    return len(re.findall(r"<host[ >]", xml))


@unittest.skipUnless(shutil.which("nmap"), "nmap is not installed")
class TestUnprivilegedDiscovery(unittest.TestCase):
    """This is the path an l2-degraded agent runs on every scan. If -sn finds
    nothing unprivileged, every such scan comes back with 0 hosts."""

    def test_sn_finds_loopback_unprivileged(self):
        xml = sa.run_nmap(["nmap", "-sn", "-n", "--max-retries", "1",
                           "--host-timeout", "20s", LOOP, "-oX", "-"])
        self.assertNotIn("QUITTING", xml)
        d = sa.parse_discovery(xml)
        self.assertGreaterEqual(len(d), 1, [h["ip"] for h in d])
        self.assertIn(LOOP, [h["ip"] for h in d])

    def test_dead_range_returns_nothing_and_does_not_crash(self):
        xml = sa.run_nmap(["nmap", "-sn", "-n", "--max-retries", "1",
                           "--host-timeout", "10s", DEAD, "-oX", "-"])
        self.assertEqual(sa.parse_discovery(xml), [])


@unittest.skipUnless(shutil.which("nmap"), "nmap is not installed")
class TestPrivilegedFlagsRemoved(unittest.TestCase):
    """Regression: -O unprivileged makes nmap print a usage error and QUIT,
    returning zero hosts. run_nmap() now strips those flags, so -sV data
    still comes back."""

    def test_connect_service_scan_returns_hosts_unprivileged(self):
        with listening_port() as port:
            args = ["nmap", "-sT", "-n", "-sV", "-O", "-p", str(port), "--open",
                    "--max-retries", "1", "--host-timeout", "30s", LOOP, "-oX", "-"]
            xml = sa.run_nmap(args)
        self.assertNotIn("QUITTING", xml)
        self.assertGreaterEqual(host_element_count(xml), 1, xml[-500:])

    def test_o_is_stripped_from_argv(self):
        args = ["nmap", "-sT", "-O", "-p", "22", LOOP, "-oX", "-"]
        self.assertNotIn("-O", sa._strip_privileged_flags(args))

    def test_output_parses(self):
        with listening_port() as port:
            xml = sa.run_nmap(["nmap", "-sT", "-n", "-sV", "-O", "-p", str(port),
                               "--open", "--max-retries", "1",
                               "--host-timeout", "30s", LOOP, "-oX", "-"])
        h = sa.parse_host_xml(xml)
        self.assertIsNotNone(h, "no host record parsed from a live open port")
        self.assertEqual(h["ip"], LOOP)
        self.assertIsInstance(h["ports"], list)

    def test_os_only_pass_does_not_quit(self):
        """A host with no open ports gets an extra '-O --osscan-guess' pass; if
        that silently returned nothing the OS guess would be lost."""
        xml = sa.run_nmap(["nmap", "-O", "--osscan-guess", "-n", "-T4",
                           "--max-retries", "1", "--host-timeout", "40s",
                           LOOP, "-oX", "-"])
        self.assertNotIn("QUITTING", xml)
        h = sa.parse_host_xml(xml)
        self.assertIsNotNone(h)
        # os_guess may legitimately be absent (fingerprinting needs privilege);
        # what matters is that the pass produced a parseable host.
        if h.get("os_guess"):
            self.assertIsInstance(h["os_confidence"], int)


@unittest.skipUnless(shutil.which("nmap"), "nmap is not installed")
class TestDeadAndFilteredHosts(unittest.TestCase):
    def test_dead_host_invents_no_ports(self):
        xml = sa.run_nmap(["nmap", "-sT", "-n", "-p", "80", "--max-retries", "1",
                           "--host-timeout", "15s", DOC, "-oX", "-"])
        h = sa.parse_host_xml(xml)
        self.assertTrue(h is None or not h.get("ports"))

    def test_dead_host_reported_down_or_absent(self):
        xml = sa.run_nmap(["nmap", "-sT", "-n", "-p", "80", "--max-retries", "1",
                           "--host-timeout", "15s", DOC, "-oX", "-"])
        d = sa.parse_discovery(xml)
        self.assertTrue(not d or d[0].get("state") == "down", d)

    def test_filtered_port_not_reported_open(self):
        xml = sa.run_nmap(["nmap", "-sT", "-n", "-p", "443", "--max-retries", "0",
                           "--host-timeout", "20s", DOC, "-oX", "-"])
        self.assertEqual(sa._parse_open_ports(xml), [])


class TestArgvSafety(unittest.TestCase):
    def test_empty_argv_short_circuits(self):
        """A bare `nmap` with no arguments would scan the whole internet."""
        self.assertEqual(sa.run_nmap([]), "")

    def test_stripping_never_leaves_a_bare_nmap(self):
        self.assertEqual(sa._strip_privileged_flags(["nmap", "-sS", "-O", "-PR"]),
                         ["nmap"])


@unittest.skipUnless(shutil.which("nmap"), "nmap is not installed")
class TestIPv6IsRefused(unittest.TestCase):
    """nmap does find ::1 given -6, but the agent cannot use it: both XML
    parsers read only addrtype="ipv4" and vendor detection is ARP-based. The
    contract under test is that it fails loudly instead of reporting zero
    hosts, which is indistinguishable from 'nothing responded'."""

    def test_nmap_really_does_find_it(self):
        xml = sa.run_nmap(["nmap", "-sT", "-n", "-6", "-p", "22", "--max-retries",
                           "1", "--host-timeout", "20s", "::1", "-oX", "-"])
        self.assertIn("<host", xml)

    def test_agent_refuses_ipv6_targets(self):
        self.assertFalse(sa._valid_target("::1"))
        self.assertFalse(sa._valid_target("2001:db8::/32"))


class _CapturingClient:
    def __init__(self):
        self.results = []
        self.logs = []

    def log(self, task_id, msg, level="out"):
        self.logs.append(msg)

    def result(self, task_id, hosts, status="completed", notes=None):
        self.results.append({"status": status, "notes": notes})


@unittest.skipUnless(shutil.which("nmap"), "nmap is not installed")
class TestIPv6TaskFailsLoudly(unittest.TestCase):
    def test_task_fails_and_says_why(self):
        c = _CapturingClient()
        sa.execute_task(c, {"id": "t", "scan_id": "s", "engagement_id": "e",
                            "targets": ["::1"], "profile": "standard"})
        self.assertEqual(len(c.results), 1)
        self.assertEqual(c.results[0]["status"], "failed")
        self.assertIn("IPv6", c.results[0]["notes"])


if __name__ == "__main__":
    unittest.main()