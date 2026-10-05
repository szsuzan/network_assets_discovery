"""Tests for the autostart units agentctl writes.

The most important property is negative: a background service must never be
able to ask for a password. A `sudo` inside ExecStart with `Restart=always`
cannot prompt (no terminal), so every retry is a failed PAM authentication and
pam_faillock eventually locks the account out of the machine. That shipped once
already, so it is asserted here against both the generated text and a captured
copy of the real broken unit.

    python3 -m unittest tests.test_agent_unit -v
"""
import importlib.util
import os
import unittest

_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
_AGENTCTL = os.path.join(_ROOT, "agent", "agentctl.py")
_spec = importlib.util.spec_from_file_location("agentctl", _AGENTCTL)
ctl = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(ctl)

def _execstart_argv(text):
    """The argv systemd will execute, with the `ExecStart=` key stripped."""
    line = next(l for l in text.splitlines() if l.startswith("ExecStart="))
    return line[len("ExecStart="):].split()


SYSTEM = ctl.render_system_unit("/usr/bin/python3", "/opt/agent/agentctl.py",
                                "'run' '--foreground' '--server' 'http://x'")
USER = ctl.render_user_unit("/usr/bin/python3", "/opt/agent/agentctl.py",
                            "'run' '--foreground' '--server' 'http://x'")

# The unit that actually locked the account out, captured verbatim from
# ~/.config/systemd/user/subnex-agent.service after the incident.
BROKEN = """[Unit]
Description=SubNex LAN scanner agent
After=network-online.target
Wans=network-online.target

[Service]
Type=simple
Restart=always
RestartSec=5
ExecStart=sudo /usr/bin/python3 -u /home/sz/subnex-agent/agent/agentctl.py 'run' '--foreground' '--server' 'http://localhost:8000' '--name' 'test'
Environment=SCANNER_AGENT_KEY=REDACTED-EXAMPLE-KEY-NOT-A-REAL-SECRET

[Install]
WantedBy=default.target
"""


class TestNoUnitCanPromptForAPassword(unittest.TestCase):
    """The regression that locked the user out of their machine."""

    def test_real_broken_unit_is_flagged_dangerous(self):
        self.assertTrue(ctl.unit_is_dangerous(BROKEN))

    def test_generated_units_are_not_dangerous(self):
        for name, text in (("system", SYSTEM), ("user", USER)):
            with self.subTest(unit=name):
                self.assertFalse(ctl.unit_is_dangerous(text), text)

    def test_no_sudo_anywhere_in_generated_units(self):
        for name, text in (("system", SYSTEM), ("user", USER)):
            with self.subTest(unit=name):
                for line in text.splitlines():
                    self.assertNotIn("sudo", line.split("#")[0],
                                     "sudo outside a comment: %r" % line)

    def test_detects_every_elevation_helper(self):
        for helper in ("sudo", "su", "pkexec", "doas", "runuser"):
            with self.subTest(helper=helper):
                unit = "[Service]\nExecStart=%s /usr/bin/python3 agentctl.py run\n" % helper
                self.assertTrue(ctl.unit_is_dangerous(unit))

    def test_detects_helper_by_full_path(self):
        unit = "[Service]\nExecStart=/usr/bin/sudo -n /usr/bin/python3 x\n"
        self.assertTrue(ctl.unit_is_dangerous(unit))

    def test_ignores_mentions_outside_execstart(self):
        """A comment or description mentioning sudo is harmless; only the
        executed command line matters."""
        unit = ("[Unit]\nDescription=agent (does not need sudo)\n"
                "[Service]\nExecStart=/usr/bin/python3 agentctl.py run\n")
        self.assertFalse(ctl.unit_is_dangerous(unit))

    def test_safe_unit_is_not_flagged(self):
        self.assertFalse(ctl.unit_is_dangerous(SYSTEM))
        self.assertFalse(ctl.unit_is_dangerous(USER))
        self.assertFalse(ctl.unit_is_dangerous(""))


class TestNoCrashLoops(unittest.TestCase):
    """Restart=always on a service that cannot succeed turns one mistake into
    an infinite retry loop; start limits cap the blast radius."""

    def test_never_restart_always(self):
        for name, text in (("system", SYSTEM), ("user", USER)):
            with self.subTest(unit=name):
                self.assertNotIn("Restart=always", text)

    def test_restart_on_failure(self):
        for name, text in (("system", SYSTEM), ("user", USER)):
            with self.subTest(unit=name):
                self.assertIn("Restart=on-failure", text)

    def test_start_limits_present(self):
        for name, text in (("system", SYSTEM), ("user", USER)):
            with self.subTest(unit=name):
                self.assertIn("StartLimitIntervalSec", text)
                self.assertIn("StartLimitBurst", text)

    def test_has_a_restart_delay(self):
        for name, text in (("system", SYSTEM), ("user", USER)):
            with self.subTest(unit=name):
                self.assertIn("RestartSec=", text)


class TestUnitContents(unittest.TestCase):
    def test_execstart_is_well_formed(self):
        """systemd runs argv[0] as the program. Prepending a flag makes it try
        to execute a program with that name."""
        for name, text in (("system", SYSTEM), ("user", USER)):
            with self.subTest(unit=name):
                argv = _execstart_argv(text)
                self.assertEqual(argv[0], "/usr/bin/python3")
                self.assertEqual(argv[1], "-u")

    def test_arguments_are_preserved(self):
        for name, text in (("system", SYSTEM), ("user", USER)):
            with self.subTest(unit=name):
                self.assertIn("agentctl.py", text)
                self.assertIn("--server", text)

    def test_script_path_appears_once(self):
        """A duplicated path makes argparse die with 'unrecognized arguments'."""
        self.assertEqual(" ".join(_execstart_argv(SYSTEM)).count("agentctl.py"), 1)

    def test_api_key_not_inline_in_unit(self):
        """The key belongs in a 0600 EnvironmentFile, not a world-readable
        unit file."""
        for name, text in (("system", SYSTEM), ("user", USER)):
            with self.subTest(unit=name):
                self.assertNotIn("SCANNER_AGENT_KEY=", text)
                self.assertIn("EnvironmentFile=", text)

    def test_system_unit_targets_boot(self):
        self.assertIn("WantedBy=multi-user.target", SYSTEM)
        self.assertIn("WantedBy=default.target", USER)

    def test_stdin_is_null(self):
        """A service must never be able to wait on input."""
        for name, text in (("system", SYSTEM), ("user", USER)):
            with self.subTest(unit=name):
                self.assertIn("StandardInput=null", text)

    def test_required_sections_present(self):
        for name, text in (("system", SYSTEM), ("user", USER)):
            with self.subTest(unit=name):
                for section in ("[Unit]", "[Service]", "[Install]"):
                    self.assertIn(section, text)


class TestStatusAuditsDiskBeforeConfig(unittest.TestCase):
    """`status` must not report a clean machine while a dangerous unit exists.

    The original bug: the function returned "not_installed" from the config
    marker before ever looking at the filesystem, so the leftover unit that
    caused the incident was invisible to `status` and `repair`.
    """

    def _with_fake_unit(self, text, tmp):
        path = tmp / "subnex-agent.service"
        path.write_text(text, encoding="utf-8")
        real_expand = ctl.os.path.expanduser
        real_isfile = ctl.os.path.isfile

        def expanduser(p):
            return str(path) if p == ctl.LEGACY_USER_UNIT else real_expand(p)

        def isfile(p):
            return str(path) == p or real_isfile(p)

        ctl.os.path.expanduser = expanduser
        ctl.os.path.isfile = isfile
        self.addCleanup(setattr, ctl.os.path, "expanduser", real_expand)
        self.addCleanup(setattr, ctl.os.path, "isfile", real_isfile)

    def test_dangerous_unit_reported_even_when_config_says_uninstalled(self):
        import tempfile
        from pathlib import Path
        with tempfile.TemporaryDirectory() as d:
            tmp = Path(d)
            self._with_fake_unit(BROKEN, tmp)
            real_read = ctl.read_config
            ctl.read_config = lambda: {}
            self.addCleanup(setattr, ctl, "read_config", real_read)
            self.assertEqual(ctl.autostart_status(), "dangerous")

    def test_safe_unit_does_not_trigger_dangerous(self):
        import tempfile
        from pathlib import Path
        with tempfile.TemporaryDirectory() as d:
            tmp = Path(d)
            self._with_fake_unit(USER, tmp)
            real_read = ctl.read_config
            ctl.read_config = lambda: {}
            self.addCleanup(setattr, ctl, "read_config", real_read)
            self.assertNotEqual(ctl.autostart_status(), "dangerous")


class TestBothInstallPathsAreCovered(unittest.TestCase):
    def test_paths_are_defined(self):
        self.assertEqual(ctl.SYSTEM_UNIT, "/etc/systemd/system/subnex-agent.service")
        self.assertEqual(ctl.UNIT_NAME, "subnex-agent")

    def test_legacy_user_unit_path_is_known(self):
        """The dangerous unit has to be findable so install can clean it up."""
        self.assertIn("subnex-agent.service", ctl.LEGACY_USER_UNIT)

    def test_system_env_file_is_root_only_path(self):
        self.assertTrue(ctl.SYSTEM_ENV.startswith("/etc/"))


if __name__ == "__main__":
    unittest.main()