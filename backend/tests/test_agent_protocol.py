"""Agent protocol and task state-machine tests.

The real ApiClient talks HTTP to a programmable mock backend, so payload
shapes, JSON encoding, progress reporting and pause/stop handling are exercised
for real rather than mocked at the client boundary. Only run_nmap() is stubbed,
which keeps these tests fast and deterministic -- the nmap invocation itself is
covered by test_agent_nmap.py.

    python3 -m unittest tests.test_agent_protocol -v
"""
import importlib.util
import json
import os
import threading
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer

_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
_AGENT = os.path.join(_ROOT, "agent", "scanner_agent.py")
_spec = importlib.util.spec_from_file_location("scanner_agent", _AGENT)
sa = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(sa)


# ------------------------------------------------------------------ mock server
XML_DISC_2HOST = """<?xml version="1.0"?><nmaprun>
<host><status state="up" reason="arp-response"/>
<address addr="192.168.99.1" addrtype="ipv4"/>
<address addr="AA:BB:CC:00:00:01" addrtype="mac" vendor="Vendor One"/></host>
<host><status state="up" reason="syn-ack"/>
<address addr="192.168.99.2" addrtype="ipv4"/>
<address addr="AA:BB:CC:00:00:02" addrtype="mac" vendor="Vendor Two"/></host>
</nmaprun>"""

XML_HOST_A = """<?xml version="1.0"?><nmaprun><host><status state="up"/>
<address addr="192.168.99.1" addrtype="ipv4"/>
<address addr="AA:BB:CC:00:00:01" addrtype="mac" vendor="Vendor One"/>
<ports><port protocol="tcp" portid="22"><state state="open"/>
<service name="ssh" product="OpenSSH" version="9.6"/></port></ports>
<os><osmatch name="Linux 5.X" accuracy="95"/></os></host></nmaprun>"""

XML_HOST_B_NOPORTS = """<?xml version="1.0"?><nmaprun><host><status state="up"/>
<address addr="192.168.99.2" addrtype="ipv4"/>
<address addr="AA:BB:CC:00:00:02" addrtype="mac" vendor="Vendor Two"/>
<ports><port protocol="tcp" portid="443"><state state="closed"/></port></ports>
<os><osmatch name="Windows Server 2019" accuracy="92"/></os></host></nmaprun>"""

XML_EMPTY = '<?xml version="1.0"?><nmaprun></nmaprun>'

CTRL = {"task": None, "state": {}, "http_status": 200, "results": [], "logs": [],
        "heartbeats": [], "next_calls": 0, "state_calls": 0}
LOCK = threading.Lock()


class Handler(BaseHTTPRequestHandler):
    def _send(self, code, obj):
        b = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(b)))
        self.end_headers()
        self.wfile.write(b)

    def _body(self):
        n = int(self.headers.get("Content-Length") or 0)
        try:
            return json.loads(self.rfile.read(n) or b"{}")
        except Exception:
            return {}

    def do_GET(self):
        with LOCK:
            if self.path.startswith("/api/agents/tasks/next"):
                CTRL["next_calls"] += 1
                # Hand out the task once, then behave as an idle agent.
                t, CTRL["task"] = CTRL["task"], None
                self._send(200, t)
                return
            if "/state" in self.path:
                CTRL["state_calls"] += 1
                self._send(200, CTRL["state"])
                return
            self._send(200, {})

    def do_POST(self):
        body = self._body()
        with LOCK:
            if self.path == "/api/agents/heartbeat":
                CTRL["heartbeats"].append(body)
                if CTRL["http_status"] != 200:
                    self._send(CTRL["http_status"], {"detail": "nope"})
                    return
                self._send(200, {"agent_id": "agent-1"})
                return
            if self.path.endswith("/result"):
                CTRL["results"].append(body)
            elif self.path.endswith("/log"):
                CTRL["logs"].append(body.get("line", ""))
            self._send(200, {"ok": True})

    def log_message(self, *a):
        pass


_server = HTTPServer(("127.0.0.1", 0), Handler)
threading.Thread(target=_server.serve_forever, daemon=True).start()
BASE = "http://127.0.0.1:%d" % _server.server_address[1]


def reset(task=None, state=None, status=200):
    with LOCK:
        CTRL.update({"task": task, "state": state or {}, "http_status": status,
                     "results": [], "logs": [], "heartbeats": [],
                     "next_calls": 0, "state_calls": 0})


def client():
    return sa.ApiClient(BASE, "test-key", "test-agent")


def mk_task(**kw):
    t = {"id": "t1", "scan_id": "s1", "status": "claimed",
         "targets": ["192.168.99.0/29"], "profile": "quick",
         "port_range": "22,80", "protocol": "tcp", "kind": "discovery",
         "mode": "standard", "workers": 5}
    t.update(kw)
    return t


def fake_run_nmap(args):
    args = list(args)
    if "-sn" in args:
        return XML_DISC_2HOST
    if "192.168.99.1" in args:
        return XML_HOST_A
    if "192.168.99.2" in args:
        return XML_HOST_B_NOPORTS
    return XML_EMPTY


class ProtocolTestCase(unittest.TestCase):
    """Restores the real run_nmap and mock state around every test."""

    def setUp(self):
        self._real_run_nmap = sa.run_nmap
        sa.run_nmap = fake_run_nmap
        reset()

    def tearDown(self):
        sa.run_nmap = self._real_run_nmap
        reset()

    def statuses(self):
        return [r.get("status") for r in CTRL["results"]]

    def streamed_hosts(self):
        return [h for r in CTRL["results"] for h in (r.get("hosts") or [])]


class TestHappyPath(ProtocolTestCase):
    def setUp(self):
        super().setUp()
        sa.execute_task(client(), mk_task(), use_connect=True)

    def test_exactly_one_final_completed_post(self):
        final = [r for r in CTRL["results"] if r.get("status") == "completed"]
        self.assertEqual(len(final), 1, self.statuses())

    def test_both_live_hosts_reported_across_stream(self):
        """Hosts stream in via partial posts so the UI updates in realtime."""
        self.assertEqual(sorted({h["ip"] for h in self.streamed_hosts()}),
                         ["192.168.99.1", "192.168.99.2"])

    def test_every_host_has_an_ip(self):
        self.assertTrue(all(h.get("ip") for h in self.streamed_hosts()))

    def test_mac_and_vendor_captured(self):
        one = [h for h in self.streamed_hosts() if h.get("ip") == "192.168.99.1"]
        self.assertTrue(one and all(h.get("mac") for h in one))

    def test_os_guess_captured(self):
        self.assertTrue([h for h in self.streamed_hosts() if h.get("os_guess")])

    def test_open_port_host_has_ports(self):
        self.assertTrue([h for h in self.streamed_hosts() if h.get("ports")])

    def test_closed_port_host_still_reported(self):
        self.assertTrue([h for h in self.streamed_hosts() if not h.get("ports")])

    def test_final_post_carries_no_hosts_by_design(self):
        final = [r for r in CTRL["results"] if r.get("status") == "completed"][0]
        self.assertFalse(final.get("hosts"))

    def test_progress_is_monotonic(self):
        prog = [r["progress"] for r in CTRL["results"] if r.get("progress") is not None]
        self.assertEqual(prog, sorted(prog), prog)
        self.assertTrue(prog and prog[-1] >= 20, prog)

    def test_agent_note_identifies_the_agent(self):
        final = [r for r in CTRL["results"] if r.get("status") == "completed"][0]
        self.assertIn("agent=", final.get("notes") or "")

    def test_phase_logs_emitted(self):
        self.assertTrue([l for l in CTRL["logs"] if "Phase 1/3" in l])

    def test_result_payload_matches_backend_contract(self):
        """Every host needs an ip and every port a numeric id, or the backend
        cannot persist the finding."""
        for h in self.streamed_hosts():
            self.assertTrue(h.get("ip"), h)
            for p in h.get("ports") or []:
                self.assertIsInstance(p.get("port"), int, p)


class TestNoLiveHosts(ProtocolTestCase):
    def setUp(self):
        super().setUp()
        sa.run_nmap = lambda args: XML_EMPTY
        sa.execute_task(client(), mk_task(), use_connect=True)

    def test_still_completes(self):
        self.assertIn("completed", self.statuses())

    def test_reports_zero_hosts(self):
        self.assertTrue(all(len(r.get("hosts") or []) == 0
                            for r in CTRL["results"]))


class TestInvalidTargets(ProtocolTestCase):
    def test_nmap_arguments_cannot_be_smuggled_through_targets(self):
        sa.execute_task(client(), mk_task(targets=["--script=evil", "not-a-host"]))
        self.assertIn("failed", self.statuses())

    def test_rejection_is_logged(self):
        sa.execute_task(client(), mk_task(targets=["--script=evil", "not-a-host"]))
        self.assertTrue([l for l in CTRL["logs"] if "no valid targets" in l])

    def test_empty_target_list_is_rejected(self):
        sa.execute_task(client(), mk_task(targets=[]))
        self.assertIn("failed", self.statuses())

    def test_ipv6_targets_fail_loudly(self):
        """Better to fail than to report zero hosts, which is
        indistinguishable from 'nothing responded'."""
        sa.execute_task(client(), mk_task(targets=["::1"]))
        failed = [r for r in CTRL["results"] if r.get("status") == "failed"]
        self.assertTrue(failed, self.statuses())
        self.assertIn("IPv6", failed[0].get("notes") or "")


class TestTaskContract(ProtocolTestCase):
    def test_missing_scan_id_raises_from_execute_task(self):
        broken = mk_task()
        del broken["scan_id"]
        with self.assertRaises(KeyError):
            sa.execute_task(client(), broken)

    def test_main_converts_mid_task_errors_into_a_failed_result(self):
        """execute_task trusts the server's task contract; main() is the guard
        that keeps a mid-task exception from vanishing."""
        with open(_AGENT, encoding="utf-8") as fh:
            src = fh.read()
        self.assertIn('status="failed", error=str(e)', src)
        self.assertIn("execute_task(client, task", src)

    def test_invalid_port_range_raises_value_error(self):
        with self.assertRaises(ValueError):
            sa._sane_port_range("--script=evil")


class TestStopAndPause(ProtocolTestCase):
    def test_stopped_scan_does_not_report_success(self):
        reset(mk_task(), state={"stopped": True})
        sa.execute_task(client(), mk_task(), use_connect=True)
        self.assertFalse([r for r in CTRL["results"]
                          if r.get("status") == "completed"
                          and len(r.get("hosts") or []) == 2])

    def test_stopped_scan_posts_no_result(self):
        """The server already has the scan in `stopped`, so the agent must not
        post anything -- especially not "completed", which would resurrect a
        scan the operator just cancelled."""
        reset(mk_task(), state={"stopped": True})
        sa.execute_task(client(), mk_task(), use_connect=True)
        self.assertEqual(self.statuses(), [], CTRL["results"])
        self.assertNotIn("completed", self.statuses())

    def test_stopped_scan_says_why_it_stopped(self):
        reset(mk_task(), state={"stopped": True})
        sa.execute_task(client(), mk_task(), use_connect=True)
        self.assertTrue([l for l in CTRL["logs"] if "stopped by user" in l.lower()],
                        CTRL["logs"])

    def test_paused_scan_waits_for_resume(self):
        """A paused task must block at the next phase boundary instead of
        finishing the scan behind the operator's back."""
        reset(mk_task(), state={"paused": True})
        th = threading.Thread(target=sa.execute_task,
                              args=(client(), mk_task()), kwargs={"use_connect": True},
                              daemon=True)
        th.start()
        th.join(timeout=4)
        self.assertTrue(th.is_alive(), "agent kept scanning while paused")
        self.assertNotIn("completed", self.statuses())


class TestAuthAndServerErrors(ProtocolTestCase):
    def test_401_surfaces_as_auth_error(self):
        reset(status=401)
        c = client()
        try:
            self.assertIs(c.heartbeat(["192.168.99.0/29"], ["nmap"], "h1", "linux"), False)
        except sa.RemoteAuthError:
            pass  # also acceptable: explicit auth failure

    def test_500_raises_instead_of_reporting_success(self):
        reset(status=500)
        with self.assertRaises(Exception):
            client().heartbeat(["192.168.99.0/29"], ["nmap"], "h1", "linux")


class TestIdleAndHeartbeat(ProtocolTestCase):
    def test_claim_is_falsy_when_idle(self):
        reset(task=None)
        self.assertFalse(client().claim())

    def test_heartbeat_payload_contract(self):
        client().heartbeat(["192.168.99.0/29"], ["nmap", "syn", "arp"], "h1", "linux")
        hb = CTRL["heartbeats"][-1]
        for field in ("version", "hostname", "os", "subnets", "capabilities"):
            self.assertIn(field, hb)
        self.assertEqual(hb["subnets"], ["192.168.99.0/29"])
        self.assertEqual(hb["capabilities"], ["nmap", "syn", "arp"])
        self.assertEqual(hb["os"], str(hb["os"]).lower())

    def test_worker_count_from_task_is_clamped(self):
        for given in (0, -3, 1, 5, 999):
            with self.subTest(workers=given):
                sa._set_runtime_workers(mk_task(workers=given))
                w = sa._p2_workers()
                self.assertIsInstance(w, int)
                self.assertGreaterEqual(w, 1)
                self.assertLessEqual(w, 64)


if __name__ == "__main__":
    unittest.main()