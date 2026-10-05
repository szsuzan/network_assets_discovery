"""End-to-end agent tests against a live server.

Covers the whole loop the unit tiers cannot: agent registration and heartbeat,
task delegation, host rows landing in the database, and the pause/resume/stop
lifecycle. Every record is created inside a throwaway engagement scoped to
loopback and RFC 5737 documentation ranges, and is deleted again in tearDown --
the user's own engagements, scans and hosts are never touched.

Opt-in, because it needs a running server and an admin token:

    SCANNER_E2E_TOKEN="$(python3 -c 'from app.core.security import create_access_token; print(create_access_token({\"sub\": \"admin\", \"role\": \"admin\"}))')" \\
        python3 -m unittest tests.test_agent_live -v

Set SCANNER_E2E_SLOW=1 to include the multi-minute mid-phase pause/stop tests
(they sweep live loopback hosts over the full port range so a phase lasts long
enough to interrupt).
"""
import json
import os
import signal
import subprocess
import sys
import time
import unittest
import urllib.error
import urllib.request

_TOKEN = os.environ.get("SCANNER_E2E_TOKEN")
_SLOW = bool(os.environ.get("SCANNER_E2E_SLOW"))
_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
DOC = "192.0.2.1"
AGENT_NAME = "ci-live-test-agent"


def _api(method, path, body=None, timeout=60, base="http://localhost:8000"):
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(base + path, data=data, method=method)
    req.add_header("Authorization", "Bearer " + _TOKEN)
    if data:
        req.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            raw = r.read()
            return r.status, (json.loads(raw) if raw else None)
    except urllib.error.HTTPError as e:
        raw = e.read()
        try:
            return e.code, json.loads(raw)
        except Exception:
            return e.code, raw[:300].decode("utf-8", "replace")


def _wait_for(fn, timeout=300, interval=3):
    end = time.time() + timeout
    last = None
    while time.time() < end:
        last = fn()
        if last:
            return last
        time.sleep(interval)
    return last


def _terminal(sid):
    s = _api("GET", "/api/scans/%s" % sid)[1]
    return s if s and s.get("status") in ("completed", "failed", "stopped") else None


@unittest.skipUnless(_TOKEN, "set SCANNER_E2E_TOKEN to run live end-to-end tests")
class LiveTestCase(unittest.TestCase):
    """One throwaway engagement + agent for the whole class."""

    @classmethod
    def setUpClass(cls):
        st, eng = _api("POST", "/api/engagements", {
            "client_name": "ci", "engagement_name": "ci-agent-live",
            "authorized_scope": ["192.0.2.0/24", "127.0.0.0/8"]})
        assert st in (200, 201), "engagement create -> HTTP %s %s" % (st, eng)
        cls.eng_id = eng["id"]

        st, ag = _api("POST", "/api/agents", {"name": AGENT_NAME})
        assert st in (200, 201), "agent create -> HTTP %s %s" % (st, ag)
        cls.agent_id, cls.agent_key = ag["id"], ag["api_key"]

        cls.proc = subprocess.Popen(
            [sys.executable, "-u", "agent/scanner_agent.py", "--server",
             "http://localhost:8000", "--name", AGENT_NAME,
             "--subnets", "127.0.0.0/8,192.0.2.0/24", "--interval", "3",
             "--connect"],
            stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT,
            env=dict(os.environ, SCANNER_AGENT_KEY=cls.agent_key), cwd=_ROOT)

    @classmethod
    def tearDownClass(cls):
        _stop_agent(cls)
        for path in ("/api/agents/%s" % cls.agent_id,
                     "/api/engagements/%s" % cls.eng_id):
            try:
                _api("DELETE", path)
            except Exception:
                pass

    def create_scan(self, **body):
        st, sc = _api("POST", "/api/engagements/%s/scans" % self.eng_id, body)
        self.assertIn(st, (200, 201), sc)
        self.addCleanup(_api, "DELETE", "/api/scans/%s" % sc["id"])
        return sc["id"]

    def test_agent_comes_online_and_advertises_capabilities(self):
        """The server can only delegate to an agent that has actually
        heartbeated inside the online window."""
        a = _wait_for(lambda: next(
            (x for x in (_api("GET", "/api/agents")[1] or [])
             if x["id"] == self.agent_id and x.get("last_seen")), None), timeout=60)
        self.assertIsNotNone(a, "agent never came online")
        self.assertIn("connect", a.get("capabilities") or [], a.get("capabilities"))


class TestDelegatedScan(LiveTestCase):
    def test_dead_range_completes_with_no_invented_hosts(self):
        """192.0.2.0/24 is TEST-NET-1: reserved and unroutable. A completed
        scan must report zero hosts rather than inventing any."""
        sid = self.create_scan(targets=["192.0.2.0/29"], profile="quick",
                               port_range="80", mode="discovery")
        fin = _wait_for(lambda: _terminal(sid))
        self.assertIsNotNone(fin, "scan never finished")
        self.assertEqual(fin["status"], "completed")
        hosts = _api("GET", "/api/scans/%s/hosts" % sid)[1] or []
        self.assertFalse([h for h in hosts if h.get("status") == "up"], hosts)
        self.assertEqual(fin.get("hosts_discovered"), len(hosts))

    def test_live_host_is_persisted(self):
        """Loopback has a real open port, so at least one host row with
        genuine service data must land in the database."""
        sid = self.create_scan(targets=["127.0.0.1"], profile="quick",
                               port_range="8000,22,443", mode="standard")
        fin = _wait_for(lambda: _terminal(sid))
        self.assertEqual((fin or {}).get("status"), "completed")
        hosts = _api("GET", "/api/scans/%s/hosts" % sid)[1] or []
        self.assertTrue(hosts, "no host rows persisted for a live host")
        self.assertTrue(any(h.get("ip") == "127.0.0.1" and h.get("status") == "up"
                            for h in hosts), hosts)
        self.assertEqual(fin.get("hosts_discovered"), len(hosts))

    def test_scan_was_delegated_to_the_agent(self):
        sid = self.create_scan(targets=["192.0.2.0/29"], profile="quick",
                               port_range="80", mode="discovery")
        _wait_for(lambda: _terminal(sid))
        logs = _api("GET", "/api/scans/%s/logs" % sid)[1] or []
        joined = " ".join((l.get("line") or l.get("message") or "") for l in logs)
        self.assertIn("agent", joined.lower(), joined[:200])


class TestPauseBeforeClaim(LiveTestCase):
    """Regression: claim_next_task() used to claim a task regardless of the
    scan's status, overwriting `paused` with `agent_running`, after which
    resume returned 400 and the scan was stuck forever."""

    def test_pause_holds_and_scan_resumes(self):
        # Live loopback hosts over a real port range, so the scan reliably
        # outlives the observation window. A dead-range discovery scan can
        # finish in a couple of seconds, which would make this regression test
        # pass or fail on timing alone.
        sid = self.create_scan(targets=["127.0.0.0/29"], profile="full",
                               port_range="1-20000", mode="standard")
        time.sleep(2)
        st, p = _api("POST", "/api/scans/%s/pause" % sid)
        self.assertEqual(st, 200, p)
        self.assertEqual(p.get("status"), "paused")

        # Several agent polls must not undo the pause.
        seen = []
        for _ in range(6):
            s = _api("GET", "/api/scans/%s" % sid)[1]
            seen.append(s.get("status"))
            if s.get("status") in ("completed", "failed", "stopped"):
                break
            time.sleep(2)
        self.assertEqual(set(seen), {"paused"},
                         "agent polling changed the paused scan: %s" % seen)

        st, r = _api("POST", "/api/scans/%s/resume" % sid)
        self.assertEqual(st, 200, "resume rejected: %s" % r)
        fin = _wait_for(lambda: _terminal(sid), timeout=600)
        self.assertEqual((fin or {}).get("status"), "completed")


class TestStopWhileRunning(LiveTestCase):
    def test_stop_ends_the_scan_stopped(self):
        sid = self.create_scan(targets=["192.0.2.0/28"], profile="full",
                               port_range="1-1000", mode="discovery")
        time.sleep(6)
        st, s = _api("POST", "/api/scans/%s/stop" % sid)
        self.assertEqual(st, 200, s)
        self.assertIn(s.get("status"), ("stopped", "stopping"))
        fin = _wait_for(lambda: (lambda x: x if x and x.get("status") in
                                 ("stopped", "completed", "failed") else None)(
                                     _api("GET", "/api/scans/%s" % sid)[1]), timeout=180)
        self.assertEqual((fin or {}).get("status"), "stopped")


class TestApiValidation(LiveTestCase):
    def test_invalid_port_range_rejected(self):
        st, bad = _api("POST", "/api/engagements/%s/scans" % self.eng_id,
                       {"targets": ["192.0.2.0/29"], "port_range": "not-a-range"})
        self.assertIn(st, (400, 422), bad)

    def test_empty_target_list_rejected(self):
        st, bad = _api("POST", "/api/engagements/%s/scans" % self.eng_id,
                       {"targets": []})
        self.assertIn(st, (400, 422), bad)

    def test_out_of_scope_target_rejected(self):
        """Scope enforcement must happen at scan creation, before any nmap
        traffic is generated."""
        st, bad = _api("POST", "/api/engagements/%s/scans" % self.eng_id,
                       {"targets": ["10.99.99.0/24"], "profile": "quick",
                        "port_range": "80", "mode": "discovery"})
        self.assertGreaterEqual(st, 400)
        self.assertLess(st, 500)
        self.assertIn("scope", str(bad).lower())


@unittest.skipUnless(_SLOW, "set SCANNER_E2E_SLOW=1 to run multi-minute scans")
class TestPauseMidPhase(LiveTestCase):
    """Pausing while the agent is genuinely inside a phase. A dead range
    finishes in seconds, so these sweep live loopback hosts over the full port
    range to make a phase last long enough to interrupt."""

    @classmethod
    def _long_scan(cls, net):
        st, sc = _api("POST", "/api/engagements/%s/scans" % cls.eng_id,
                      {"targets": [net], "profile": "full",
                       "port_range": "1-65535", "mode": "standard"})
        assert st in (200, 201), sc
        return sc["id"]

    def test_pause_holds_during_a_long_phase_and_resumes(self):
        sid = self._long_scan("127.0.0.16/28")
        self.addCleanup(_api, "DELETE", "/api/scans/%s" % sid)
        _wait_for(lambda: _api("GET", "/api/scans/%s" % sid)[1].get("status")
                  == "agent_running", timeout=180)
        time.sleep(20)   # let a phase get under way

        st, p = _api("POST", "/api/scans/%s/pause" % sid)
        self.assertEqual(st, 200, p)
        self.assertEqual(p.get("status"), "paused")

        # The agent re-checks between phases, so the in-flight phase may still
        # finish and post progress. What must hold is that the scan does not run
        # away to completion while paused.
        seen = []
        for _ in range(8):
            s = _api("GET", "/api/scans/%s" % sid)[1]
            seen.append((s.get("status"), s.get("progress_pct")))
            if s.get("status") in ("completed", "failed", "stopped"):
                break
            time.sleep(4)
        self.assertEqual(seen[0][0], "paused", seen)

        st, r = _api("POST", "/api/scans/%s/resume" % sid)
        self.assertEqual(st, 200, r)
        fin = _wait_for(lambda: _terminal(sid), timeout=900)
        self.assertEqual((fin or {}).get("status"), "completed", seen)

    def test_stop_stays_stopped_during_a_long_phase(self):
        sid = self._long_scan("127.0.0.32/28")
        self.addCleanup(_api, "DELETE", "/api/scans/%s" % sid)
        _wait_for(lambda: _api("GET", "/api/scans/%s" % sid)[1].get("status")
                  == "agent_running", timeout=180)
        time.sleep(20)
        st, s = _api("POST", "/api/scans/%s/stop" % sid)
        self.assertEqual(st, 200, s)
        fin = _wait_for(lambda: (lambda x: x if x and x.get("status") in
                                 ("stopped", "completed", "failed") else None)(
                                     _api("GET", "/api/scans/%s" % sid)[1]), timeout=300)
        self.assertEqual((fin or {}).get("status"), "stopped")


def _stop_agent(cls):
    if getattr(cls, "proc", None) and cls.proc.poll() is None:
        cls.proc.send_signal(signal.SIGTERM)
        try:
            cls.proc.wait(timeout=15)
        except Exception:
            cls.proc.kill()


@unittest.skipUnless(_TOKEN, "set SCANNER_E2E_TOKEN to run live end-to-end tests")
class TestInWorkerFallback(unittest.TestCase):
    """With no agent online the scan must still complete in the worker."""

    def test_scan_completes_without_any_agent(self):
        """A scan must still complete in the worker when nothing can take it.

        Delegation prefers subnet coverage but falls back to ANY online agent
        while agent.require_subnet_match is false, so with someone else's agent
        registered this scan would be delegated instead -- and a broken agent
        would fail it. Require coverage for the duration of this test to pin
        the in-worker path, then restore whatever the setting was.
        """
        st, before = _api("GET", "/api/settings")
        self.assertEqual(st, 200, before)
        original = next((s.get("value") for s in before or []
                         if s.get("key") == "agent.require_subnet_match"), False)

        st, snapshot = _api("PUT", "/api/settings",
                            {"agent.require_subnet_match": True})
        self.assertEqual(st, 200, snapshot)
        # Capture the value BEFORE overwriting it, so cleanup puts it back.
        self.addCleanup(lambda: _api("PUT", "/api/settings",
                                     {"agent.require_subnet_match": original}))

        st, eng = _api("POST", "/api/engagements", {
            "client_name": "ci", "engagement_name": "ci-no-agent",
            "authorized_scope": ["192.0.2.0/24"]})
        self.assertIn(st, (200, 201), eng)
        self.addCleanup(_api, "DELETE", "/api/engagements/%s" % eng["id"])
        st, sc = _api("POST", "/api/engagements/%s/scans" % eng["id"],
                      {"targets": ["192.0.2.0/30"], "profile": "quick",
                       "port_range": "80", "mode": "discovery"})
        self.assertIn(st, (200, 201), sc)
        self.addCleanup(_api, "DELETE", "/api/scans/%s" % sc["id"])
        fin = _wait_for(lambda: _terminal(sc["id"]))
        self.assertEqual((fin or {}).get("status"), "completed", fin)


if __name__ == "__main__":
    unittest.main()