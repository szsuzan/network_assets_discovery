#!/usr/bin/env python3
"""SubNex LAN agent controller -- cross-platform (Windows / Linux / macOS).

Single entry point that installs, runs, supervises and repairs the LAN scanner
agent on any OS with Python 3.8+ and nmap, using only the standard library:

    python agentctl.py run     --server http://<host>:8000 --name lan-agent \
                               --subnets 192.168.1.0/24 --api-key <KEY>
    python agentctl.py install    # persist across reboot/logon (nice-to-have)
    python agentctl.py status     # is the agent up? does the key still work?
    python agentctl.py repair     # restart + re-register autostart if broken
    python agentctl.py stop       # stop without uninstalling
    python agentctl.py uninstall  # stop AND remove the autostart entry

Agent secrets/config live in ~/.subnex/ (config.json, agent_key, *.pid).
"""
import argparse
import json
import os
import platform
import shutil
import signal
import subprocess
import sys
import tempfile
import time
import urllib.request
import urllib.error

VERSION = "1.0.0"
APP_DIR_NAME = ".subnex"
DEFAULT_NAME = "lan-agent"
SUBNET_SEP = ","


def app_dir() -> str:
    return os.path.join(os.path.expanduser("~"), APP_DIR_NAME)


def ensure_dir() -> str:
    d = app_dir()
    os.makedirs(d, exist_ok=True)
    return d


def config_path() -> str:
    return os.path.join(app_dir(), "config.json")


def key_path() -> str:
    return os.path.join(app_dir(), "agent_key")


def pid_path(which: str) -> str:
    return os.path.join(app_dir(), f"{which}.pid")


def log_path() -> str:
    return os.path.join(app_dir(), "agent.log")


def agent_py(root: str) -> str:
    return os.path.join(root, "scanner_agent.py")


def read_config() -> dict:
    try:
        with open(config_path(), encoding="utf-8") as fh:
            cfg = json.load(fh)
    except Exception:
        return {}
    if not isinstance(cfg, dict):
        return {}
    return cfg


def write_config(cfg: dict) -> None:
    ensure_dir()
    with open(config_path(), "w", encoding="utf-8") as fh:
        json.dump(cfg, fh, indent=2)


def read_key() -> str:
    try:
        with open(key_path(), encoding="utf-8") as fh:
            return fh.read().strip()
    except Exception:
        return ""


def write_key(key: str) -> None:
    ensure_dir()
    with open(key_path(), "w", encoding="utf-8") as fh:
        fh.write(key.strip())
    try:
        os.chmod(key_path(), 0o600)
    except OSError:
        pass


def read_pid(which: str) -> int:
    try:
        with open(pid_path(which), encoding="utf-8") as fh:
            return int(fh.read().strip() or "0")
    except Exception:
        return 0


def write_pid(which: str, pid: int) -> None:
    ensure_dir()
    with open(pid_path(which), "w", encoding="utf-8") as fh:
        fh.write(str(pid))


def _lock_dir() -> str:
    """Directory for cross-user instance locks.

    Must be shared by every account, so it must NOT be tempfile.gettempdir():
    on Windows that is %LOCALAPPDATA%\\Temp, which is per-user, and the lock
    would silently fail to stop two users registering the same agent name.
    """
    if os.name == "nt":
        base = os.environ.get("PROGRAMDATA") or r"C:\ProgramData"
        d = os.path.join(base, "SubNex")
    else:
        d = "/tmp"
    try:
        os.makedirs(d, exist_ok=True)
        if not os.access(d, os.W_OK):
            raise OSError
    except Exception:
        d = tempfile.gettempdir()  # last resort: shared on POSIX, not on Windows
    return d


def _instance_lock_path(name: str, server: str) -> str:
    """System-wide lock, deliberately NOT under $HOME.

    The per-user state dir can't stop two agents of the same name: root and a
    normal user each get their own app_dir(), so each sees no pid file and both
    start. They then share one API key, resolve to the same DB row, and the
    unprivileged instance wins the task queue -- handing back scans with blank
    MAC/vendor/OS and no error anywhere. Keying the lock on name+server in a
    shared location makes the collision visible at startup instead.
    """
    tag = "".join(ch if ch.isalnum() or ch in "-_." else "_" for ch in f"{name}@{server}")
    return os.path.join(_lock_dir(), f"subnex-agent-{tag}.lock")


def claim_instance(name: str, server: str) -> tuple:
    """Claim the shared lock for this name+server.

    Returns (ok, holder_pid). ok is False when a different live process already
    owns it; caller must refuse to start so there is never a silent shadow.
    """
    path = _instance_lock_path(name, server)
    me = os.getpid()
    for _ in range(2):
        try:
            with open(path, encoding="utf-8") as fh:
                holder = int(fh.read().strip() or "0")
        except Exception:
            holder = 0
        if holder and holder != me and pid_alive(holder):
            return False, holder
        try:
            fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o644)
            os.write(fd, str(me).encode())
            os.close(fd)
            return True, me
        except FileExistsError:
            # Dead or stale: overwrite it and re-check once.
            try:
                os.unlink(path)
            except Exception:
                pass
    return True, me


def release_instance(name: str, server: str) -> None:
    try:
        os.unlink(_instance_lock_path(name, server))
    except Exception:
        pass


def _same_user(pid: int) -> bool:
    """True when pid runs under the same account as us."""
    if os.name == "nt":
        return _win_process_owner(pid).lower() == (os.environ.get("USERNAME") or "").lower()
    try:
        return os.stat(f"/proc/{pid}").st_uid == os.geteuid()
    except Exception:
        return False


def _win_process_owner(pid: int) -> str:
    try:
        out = subprocess.run(
            ["tasklist", "/FI", f"PID eq {pid}", "/FO", "CSV", "/NH"],
            capture_output=True, text=True, timeout=15,
        ).stdout
        parts = [c.strip('" ') for c in out.split(",")]
        return parts[1] if len(parts) > 2 else "?"
    except Exception:
        return "?"


def all_agent_processes() -> list:
    """(pid, owner) for every running agentctl/scanner_agent process.

    Portable across Linux/macOS (/proc) and Windows (tasklist). The pid file is
    useless here because it lives under $HOME, so it cannot see an agent running
    as a different account -- which is exactly the one that has to be cleaned up.
    """
    out = []
    me = os.getpid()
    if os.name == "nt":
        try:
            txt = subprocess.run(["tasklist", "/FO", "CSV", "/NH", "/FI", "IMAGENAME eq python.exe"],
                                 capture_output=True, text=True, timeout=30).stdout
            for line in txt.splitlines():
                parts = [c.strip('" ') for c in line.split(",")]
                if len(parts) < 2 or not parts[1].isdigit():
                    continue
                pid = int(parts[1])
                if pid == me:
                    continue
                # Only python processes running our script; tasklist has no cmdline.
                if _win_cmdline_has(pid, ("agentctl.py", "scanner_agent.py")):
                    out.append((pid, parts[0]))
        except Exception:
            pass
        return out
    import glob
    for entry in glob.glob("/proc/[0-9]*/cmdline"):
        try:
            pid = int(entry.split("/")[2])
            if pid == me:
                continue
            with open(entry, "rb") as fh:
                cmd = fh.read().decode("utf-8", "replace").replace("\x00", " ")
            if "agentctl.py" in cmd or "scanner_agent.py" in cmd:
                out.append((pid, _proc_owner(pid)))
        except Exception:
            continue
    return out


def _win_cmdline_has(pid: int, needles) -> bool:
    """True when a Windows process's command line contains any of `needles`."""
    for src in (
        ["wmic", "process", "where", f"ProcessId={pid}", "get", "CommandLine"],
        ["powershell", "-NoProfile", "-Command",
         f"(Get-CimInstance Win32_Process -Filter 'ProcessId={pid}').CommandLine"],
    ):
        try:
            r = subprocess.run(src, capture_output=True, text=True, timeout=25)
            blob = (r.stdout or "") + (r.stderr or "")
            if any(n in blob for n in needles):
                return True
        except Exception:
            continue
    return False


def all_user_homes() -> list:
    """(username, home_dir) for every account on the machine.

    macOS/Windows have no pwd module, so fall back to the accounts we can
    discover from that platform's own user database.
    """
    out = []
    if os.name != "nt":
        try:
            import pwd as _pwd
            return [(p.pw_name, p.pw_dir) for p in _pwd.getpwall()]
        except Exception:
            pass
        who = os.environ.get("USER")
        if who:
            out.append((who, os.path.expanduser("~")))
        return out
    # Windows: enumerate real (non special) accounts via the Win32 API.
    try:
        import ctypes
        from ctypes import wintypes
        advapi = ctypes.WinDLL("advapi32", use_last_error=True)
        netapi = ctypes.WinDLL("netapi32", use_last_error=True)
        LEVEL0 = 1
        FILTER_NORMAL = 0x0002
        buf = ctypes.create_string_buffer(1024)
        size = wintypes.DWORD(1024)
        resume = wintypes.DWORD(0)

        class USER_INFO_0(ctypes.Structure):
            _fields_ = [("name", wintypes.LPWSTR)]

        class USER_INFO_1(ctypes.Structure):
            _fields_ = [("name", wintypes.LPWSTR), ("password", wintypes.LPWSTR),
                        ("password_age", wintypes.DWORD), ("priv", wintypes.DWORD),
                        ("home_dir", wintypes.LPWSTR), ("comment", wintypes.LPWSTR),
                        ("flags", wintypes.DWORD), ("script_path", wintypes.LPWSTR)]

        PLIST = (ctypes.POINTER(USER_INFO_1) * 1024)()
        got = wintypes.DWORD(0)
        rc = netapi.NetUserEnum(
            None, 1, ctypes.byref(PLIST), 1024, ctypes.byref(got),
            ctypes.byref(resume), FILTER_NORMAL)
        if rc == 0 or rc == 234:  # NERR_Success / ERROR_MORE_DATA
            for i in range(got.value):
                u = PLIST[i].contents
                if u.name and u.home_dir:
                    out.append((u.name, u.home_dir))
    except Exception:
        pass
    me = os.environ.get("USERPROFILE")
    uname = os.environ.get("USERNAME")
    if uname and me and (uname, me) not in out:
        out.append((uname, me))
    return out


def pid_alive(pid: int) -> bool:
    if pid <= 0:
        return False
    if os.name == "nt":
        try:
            out = subprocess.run(
                ["tasklist", "/FI", f"PID eq {pid}", "/FO", "CSV", "/NH"],
                capture_output=True, text=True, timeout=10,
            ).stdout
            return f'"{pid}"' in out
        except Exception:
            return False
    try:
        os.kill(pid, 0)
        return True
    except OSError:
        return False


def _windows_is_elevated() -> bool:
    """True when this Windows token is actually elevated.

    IsUserAnAdmin() is unreliable: after UAC it returns FALSE for an account that
    IS a member of Administrators whenever it is running with a medium-integrity
    filtered token -- i.e. every ordinary terminal. That made a genuinely
    capable agent advertise l2-degraded. Check the real elevation type via
    TokenElevation, and keep IsUserAnAdmin as a fallback.
    """
    try:
        import ctypes
        from ctypes import wintypes
        advapi = ctypes.WinDLL("advapi32", use_last_error=True)
        kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        TOKEN_ELEVATION = 20
        TokenElevation = 20  # TokenElevation

        class TOKEN_ELEVATION(ctypes.Structure):
            _fields_ = [("TokenIsElevated", wintypes.DWORD)]

        h = wintypes.HANDLE()
        if not advapi.OpenProcessToken(kernel.GetCurrentProcess(),
                                       wintypes.DWORD(TOKEN_QUERY | TOKEN_QUERY),
                                       ctypes.byref(h)):
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        elev = TOKEN_ELEVATION()
        ok = advapi.GetTokenInformation(h, TokenElevation, ctypes.byref(elev),
                                        ctypes.sizeof(elev), None)
        kernel.CloseHandle(h)
        if ok and elev.TokenIsElevated:
            return True
        # Not elevated: it can still be an admin filtered for UAC, which is
        # exactly the case IsUserAnAdmin gets wrong. Check group membership.
        SID = ctypes.c_void_p()
        admins = ctypes.c_void_p()
        NtAuthority = 5
        if not advapi.ConvertStringSidToSidW("S-1-5-32-544", ctypes.byref(SID)):
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        admin_ok = bool(advapi.IsMemberSid(SID, SID))
        advapi.FreeSid(SID)
        return admin_ok
    except Exception:
        try:
            import ctypes
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        except Exception:
            return False


def is_privileged() -> bool:
    """True when this process can open raw sockets.

    Root is the usual answer, but a container (or a systemd unit) can hold
    CAP_NET_RAW without being uid 0, so check the effective capability set too.
    Getting this wrong is how agents end up reporting L2 capability they do not
    have and returning scans with blank MAC/vendor/OS.
    """
    try:
        if os.name == "nt":
            return _windows_is_elevated()
    except Exception:
        return False
    try:
        if os.geteuid() == 0:
            return True
    except AttributeError:
        return False
    try:
        with open("/proc/self/status", "r") as fh:
            for line in fh:
                if line.startswith("CapEff:"):
                    mask = int(line.split()[1], 16)
                    return bool(mask & ((1 << 13) | (1 << 12)))  # NET_RAW | NET_ADMIN
    except Exception:
        pass
    return False


def shell_quote(s: str) -> str:
    if os.name == "nt":
        return '"' + s.replace('"', '\\"') + '"'
    return "'" + s.replace("'", "'\\''") + "'"


def request(method: str, url: str, headers=None, body=None, timeout: int = 15):
    if body is not None:
        data = body.encode("utf-8")
    else:
        data = None
    headers = dict(headers or {})
    if data is not None:
        headers.setdefault("Content-Type", "application/json")
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status, resp.read().decode("utf-8", errors="replace")
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read().decode("utf-8", errors="replace")
    except urllib.error.URLError as exc:
        raise RuntimeError(f"cannot reach server: {exc.reason}")


def server_healthy(server: str) -> bool:
    try:
        code, _ = request("GET", server.rstrip("/") + "/health", timeout=8)
        return code == 200
    except Exception:
        return False


def verify_key(server: str, key: str) -> tuple:
    cfg = read_config()
    payload = {
        "version": VERSION,
        "hostname": platform.node() or "",
        "os": platform.system().lower() or "",
        "subnets": cfg.get("subnets") or [],
        "capabilities": [],
    }
    code, text = request(
        "POST", server.rstrip("/") + "/api/agents/heartbeat",
        headers={"X-API-Key": key},
        body=json.dumps(payload),
    )
    if code == 200:
        try:
            agent_id = json.loads(text).get("agent_id")
        except Exception:
            agent_id = None
        return True, agent_id
    if code == 401:
        return False, None
    raise RuntimeError(f"key check failed (HTTP {code}): {text[:200]}")


def resolve_args(args) -> dict:
    cfg = read_config()
    env_srv = os.environ.get("SCANNER_AGENT_SERVER")
    env_name = os.environ.get("SCANNER_AGENT_NAME")
    env_sub = os.environ.get("SCANNER_AGENT_SUBNETS")
    key = args.api_key or os.environ.get("SCANNER_AGENT_KEY") or os.environ.get("SCANNER_AGENT_API_KEY") or read_key()
    server = args.server or env_srv or cfg.get("server")
    name = args.name or env_name or cfg.get("name") or DEFAULT_NAME
    subnets = (args.subnets or env_sub or cfg.get("subnets") or "").strip()
    if not server:
        raise SystemExit("no server URL given. Pass --server or store it via `run --server ...`")
    if not key:
        raise SystemExit(
            "no API key found. Create the agent on the Agents page, then pass --api-key "
            f"once (it is saved to {key_path()}).")
    subs = [s.strip() for s in subnets.split(SUBNET_SEP) if s.strip()]
    # Persist --connect so autostart, the supervised child and `repair` all keep
    # the same privilege-free scan type instead of silently reverting to -sS.
    connect = bool(getattr(args, "connect", False)) or bool(
        os.environ.get("SCANNER_AGENT_CONNECT")) or bool(cfg.get("connect"))
    return {"key": key, "server": server, "name": name, "subnets": subs,
            "connect": connect}


def _supervisor_cmd(root: str, cfg: dict) -> list:
    py = sys.executable
    ctl = os.path.join(root, "agentctl.py")
    cmd = [py, "-u", ctl, "run", "--foreground",
           "--server", cfg["server"], "--name", cfg["name"]]
    if cfg.get("subnets"):
        cmd += ["--subnets", SUBNET_SEP.join(cfg["subnets"])]
    # Deliberately no --api-key here. The key is already on disk (write_key runs
    # before this is called) and resolve_args() falls back to read_key(), so the
    # detached supervisor can pick it up without ever publishing it to argv,
    # where `ps` / wmic / the Windows registry-backed process list would show it.
    return cmd


def _spawn_detached(cmd: list, log: str) -> int:
    kwargs = {}
    if os.name == "nt":
        creation = subprocess.CREATE_NEW_PROCESS_GROUP
        try:
            creation |= subprocess.CREATE_NO_WINDOW
        except AttributeError:
            pass
        kwargs["creationflags"] = creation
    logf = open(log, "ab", buffering=0)
    proc = subprocess.Popen(cmd, stdout=logf, stderr=logf, stdin=subprocess.DEVNULL,
                            close_fds=True, **kwargs)
    return proc.pid


def cmd_run(args) -> int:
    cfg = resolve_args(args)
    root = os.path.dirname(os.path.abspath(agent_py(os.path.dirname(os.path.abspath(__file__)))))
    script = agent_py(os.path.dirname(os.path.abspath(__file__)))
    if not os.path.isfile(script):
        raise SystemExit(f"agent script not found: {script}")
    write_key(cfg["key"])
    write_config({
        "server": cfg["server"], "name": cfg["name"], "subnets": cfg["subnets"],
        "connect": bool(cfg.get("connect")),
        "installed": read_config().get("installed", False),
    })
    parent = _supervisor_cmd(os.path.dirname(os.path.abspath(__file__)), cfg)
    if args.foreground:
        return _supervise(script, cfg, parent)
    pid = _spawn_detached(parent, log_path())
    write_pid("supervisor", pid)
    print(f"agent supervisor started. PID: {pid}")
    print(f"  log       : {log_path()}")
    print(f"  config    : {config_path()}")
    print(f"  key       : {key_path()}")
    print("Check `python agentctl.py status` when ready.")
    return 0


def _child_cmd(script: str, cfg: dict) -> list:
    cmd = [sys.executable, "-u", script,
           "--server", cfg["server"], "--name", cfg["name"],
           "--interval", "10"]
    if cfg.get("subnets"):
        cmd += ["--subnets", SUBNET_SEP.join(cfg["subnets"])]
    if cfg.get("connect"):
        cmd += ["--connect"]
    env = dict(os.environ)
    env["SCANNER_AGENT_KEY"] = cfg["key"]
    return cmd, env


def _supervise(script: str, cfg: dict, parent: list) -> int:
    stop = threading_event()
    def _sig(signum, _frame):
        stop.set()
    try:
        signal.signal(signal.SIGINT, _sig)
        signal.signal(signal.SIGTERM, _sig)
    except Exception:
        pass
    # Claim the shared name+server lock. Refusing here is what turns a silent
    # two-agent shadow into a clear error message.
    ok, holder = claim_instance(cfg["name"], cfg["server"])
    if not ok:
        who = "another user (likely root)" if not _same_user(holder) else "another copy"
        raise SystemExit(
            f"an agent named '{cfg['name']}' is already running as {who} (PID {holder}).\n"
            f"  stop it first:  sudo kill {holder}\n"
            f"  then re-run this command.\n"
            f"  Two agents with one name share an API key, so whichever is alive last\n"
            f"  claims every scan -- and an unprivileged one silently returns blank MACs."
        )
    backoff = 1
    runs = 0
    print(f"[agentctl] supervising {cfg['name']} -> {cfg['server']}")
    try:
        while not stop.is_set():
            cmd, env = _child_cmd(script, cfg)
            proc = subprocess.Popen(cmd, env=env, stdout=sys.stdout, stderr=sys.stderr)
            write_pid("agent", proc.pid)
            print(f"[agentctl] agent PID {proc.pid} started (run {runs + 1})")
            while proc.poll() is None:
                if stop.wait(1.0):
                    proc.terminate()
                    try:
                        proc.wait(timeout=10)
                    except Exception:
                        proc.kill()
                    print("[agentctl] stopped")
                    return 0
            code = proc.returncode
            print(f"[agentctl] agent exited with code {code}")
            if stop.is_set():
                return 0
            print(f"[agentctl] restarting in {backoff}s...")
            stop.wait(backoff)
            backoff = min(backoff * 2, 30)
            runs += 1
    finally:
        release_instance(cfg["name"], cfg["server"])
    return 0


def threading_event():
    import threading
    return threading.Event()


def find_supervisor_pids() -> list:
    out = []
    pid = read_pid("supervisor")
    if pid > 0 and pid_alive(pid):
        out.append(pid)
    return out


def cmd_stop(args) -> int:
    stopped = []
    agent = read_pid("agent")
    if agent > 0 and pid_alive(agent):
        try:
            os.kill(agent, signal.SIGTERM)
        except Exception:
            pass
        stopped.append(agent)
    for pid in find_supervisor_pids():
        if os.name == "nt":
            subprocess.run(["taskkill", "/PID", str(pid), "/T", "/F"],
                           capture_output=True, timeout=15)
        else:
            try:
                os.kill(pid, signal.SIGTERM)
            except Exception:
                pass
        stopped.append(pid)
    for pid in stopped:
        print(f"  stopped agent PID {pid}")
    for which in ("supervisor", "agent"):
        try:
            os.remove(pid_path(which))
        except OSError:
            pass
    if not stopped:
        print("  no agent processes running")
    # Drop the shared lock too, otherwise a restart after a clean stop would
    # trip the duplicate guard against our own dead pid file.
    cfg = read_config()
    if cfg.get("name") and cfg.get("server"):
        release_instance(cfg["name"], cfg["server"])
    print("agent stopped.")
    return 0


WINDOWS_TASK = "SubNexAgent"


def install_command() -> list:
    root = os.path.dirname(os.path.abspath(__file__))
    cfg = read_config()
    cmd = _supervisor_cmd(root, cfg)
    return cmd


def autostart_status() -> str:
    # Audit the filesystem BEFORE trusting the config marker. A leftover unit
    # from an older version is the thing most likely to be wrong, and it keeps
    # working (or keeps failing) regardless of what the config file claims.
    # Reporting "not_installed" while a dangerous unit sits on disk hides the
    # one problem that actually matters.
    for probe in (os.path.expanduser(LEGACY_USER_UNIT),):
        if os.path.isfile(probe):
            try:
                with open(probe, encoding="utf-8", errors="replace") as fh:
                    if unit_is_dangerous(fh.read()):
                        return "dangerous"
            except Exception:
                pass
    cfg = read_config()
    if not cfg.get("installed"):
        return "not_installed"
    if os.name == "nt":
        try:
            out = subprocess.run(
                ["schtasks", "/query", "/tn", WINDOWS_TASK, "/fo", "LIST"],
                capture_output=True, text=True, timeout=15,
            ).stdout
            return "installed" if WINDOWS_TASK in out else "missing"
        except Exception:
            return "unknown"
    if sys.platform == "darwin":
        plist = os.path.expanduser("~/Library/LaunchAgents/local.subnex.agent.plist")
        if not os.path.isfile(plist):
            return "missing"
        # Ask launchd, not just the filesystem: a plist can exist while the job
        # failed to load, and reporting "installed" made `repair` refuse to fix it.
        try:
            out = subprocess.run(["launchctl", "list"], capture_output=True,
                                 text=True, timeout=15).stdout
            if "local.subnex.agent" in out:
                return "installed"
            return "missing"
        except Exception:
            return "installed"
    # A system unit (root, the preferred install) or a per-user unit.
    if os.path.isfile(SYSTEM_UNIT):
        try:
            out = subprocess.run(["systemctl", "is-enabled", UNIT_NAME],
                                 capture_output=True, text=True, timeout=15).stdout.strip()
            return "installed" if out == "enabled" else "missing"
        except Exception:
            return "installed"
    unit = os.path.expanduser(LEGACY_USER_UNIT)
    if os.path.isfile(unit):
        try:
            # A per-user unit that prompts for a password is not a working
            # install -- it fails auth forever and can lock the account out.
            with open(unit, encoding="utf-8", errors="replace") as fh:
                if unit_is_dangerous(fh.read()):
                    return "dangerous"
        except Exception:
            pass
        try:
            out = subprocess.run(["systemctl", "--user", "is-enabled", UNIT_NAME],
                                 capture_output=True, text=True, timeout=15).stdout.strip()
            return "installed" if out == "enabled" else "missing"
        except Exception:
            return "installed"
    try:
        crontab = subprocess.run(["crontab", "-l"], capture_output=True,
                                 text=True, timeout=15).stdout
    except Exception:
        crontab = ""
    # Require the well-formed marker: the old broken line also contained this
    # text, so status reported "installed" for a job that died every boot.
    return "installed" if "agentctl.py run --foreground" in crontab else "missing"


UNIT_NAME = "subnex-agent"
SYSTEM_UNIT = "/etc/systemd/system/subnex-agent.service"
SYSTEM_ENV = "/etc/subnex-agent.env"
LEGACY_USER_UNIT = "~/.config/systemd/user/subnex-agent.service"


def render_system_unit(py_exe: str, ctl: str, args_str: str) -> str:
    """A SYSTEM unit for the privileged agent.

    Two hard rules, both learned the hard way:

    1. NEVER put `sudo` in ExecStart. A background service has no terminal, so
       sudo cannot prompt, cannot read a cached credential and cannot use
       askpass -- it just fails the PAM auth. With Restart=always that becomes
       an infinite retry loop, and pam_faillock counts every attempt until it
       locks the account out of the machine entirely. If the agent needs root,
       the unit itself must be a system unit that already runs as root.
    2. Restart=on-failure, never always -- a service that was asked to stop
       should stay stopped, and a crash loop must not be able to spin forever.

    StartLimit* caps the blast radius of any future failure: systemd gives up
    after a few attempts rather than retrying forever.
    """
    return f"""[Unit]
Description=SubNex LAN scanner agent
After=network-online.target
Wants=network-online.target
StartLimitIntervalSec=300
StartLimitBurst=3

[Service]
Type=simple
Restart=on-failure
RestartSec=10
# Runs as root because it needs raw sockets. No sudo: this is a system unit,
# so privilege is already there and asking for it again can only fail.
ExecStart={py_exe} -u {ctl} {args_str}
# The API key lives in a 0600 root-owned file, not inline here, so it does not
# sit in a world-readable unit file.
EnvironmentFile={SYSTEM_ENV}
# Never block waiting for input: a service must never be able to prompt.
StandardInput=null
StandardOutput=journal
StandardError=journal
SyslogIdentifier=subnex-agent

[Install]
WantedBy=multi-user.target
"""


def render_user_unit(py_exe: str, ctl: str, args_str: str) -> str:
    """A per-user unit that CANNOT elevate.

    Used when install runs without root. This runs as the logged-in user, so it
    gets TCP connect scanning and hostname data but no ARP/MAC/vendor/OS. It
    deliberately contains no `sudo` -- see render_system_unit().
    """
    return f"""[Unit]
Description=SubNex LAN scanner agent (unprivileged, no Layer-2 data)
After=network-online.target
Wants=network-online.target
StartLimitIntervalSec=300
StartLimitBurst=3

[Service]
Type=simple
Restart=on-failure
RestartSec=10
ExecStart={py_exe} -u {ctl} {args_str}
EnvironmentFile=%h/.config/subnex-agent/agent.env
StandardInput=null
StandardOutput=journal
StandardError=journal
SyslogIdentifier=subnex-agent

[Install]
WantedBy=default.target
"""


def unit_is_dangerous(text: str) -> bool:
    """True if a unit would prompt for a password in the background.

    Used both when writing units (refuse to emit one) and when auditing units
    written by older versions.
    """
    for line in text.splitlines():
        line = line.strip()
        # Strip the `ExecStart=` key, not just `ExecStart` -- leaving the `=`
        # attached makes the first token "=sudo", which matches nothing and
        # silently reports every dangerous unit as safe.
        if not line.startswith("ExecStart="):
            continue
        argv = line[len("ExecStart="):].split()
        for tok in argv:
            base = os.path.basename(tok)
            if base in ("sudo", "su", "pkexec", "doas", "runuser"):
                return True
    return False


def cmd_install(args) -> int:
    cfg = read_config()
    if not cfg.get("server") or not read_key():
        raise SystemExit("run the agent once first (`python agentctl.py run ...`) so config exists")
    root = os.path.dirname(os.path.abspath(__file__))
    cmd = install_command()
    py = shell_quote(sys.executable)
    ctl = shell_quote(os.path.abspath(os.path.join(root, "agentctl.py")))
    # install_command() returns a full argv that ALREADY begins with
    # [python, -u, agentctl.py]. Slicing off cmd[2:] and re-emitting
    # "<python> -u <agentctl.py> <rest>" duplicates the script path, producing
    #   ExecStart=/usr/bin/python3 -u /path/agentctl.py /path/agentctl.py run ...
    # argparse then treats the second path as a positional and the unit dies with
    # "unrecognized arguments". Join from cmd[3:] and keep the prefix ourselves.
    tail = cmd[3:] if cmd[:3] == [sys.executable, "-u", os.path.abspath(os.path.join(root, "agentctl.py"))] else cmd[2:]
    args_str = " ".join(shell_quote(a) for a in tail)
    logr = log_path()
    if os.name == "nt":
        tr = f"{py} {ctl} {args_str} >> {shell_quote(logr)} 2>&1"
        base = ["schtasks", "/create", "/tn", WINDOWS_TASK, "/tr", tr, "/f"]
        ok = False
        for sc in ("onlogon", "onstart"):
            r = subprocess.run(base + ["/sc", sc], capture_output=True, text=True)
            if r.returncode == 0:
                ok = True
                break
        if not ok:
            raise SystemExit("failed to register a Windows scheduled task (try running as admin)")
        cfg["installed"] = "windows:onlogon"
        write_config(cfg)
        print(f"installed scheduled task '{WINDOWS_TASK}' (runs at logon)")
        return 0
    if sys.platform == "darwin":
        plist_dir = os.path.expanduser("~/Library/LaunchAgents")
        os.makedirs(plist_dir, exist_ok=True)
        plist = os.path.join(plist_dir, "local.subnex.agent.plist")
        launchd_label = "local.subnex.agent"

        def _x(v) -> str:
            # Interpolated values are agent name / server URL / paths. An
            # unescaped &, < or > produces a malformed plist that launchctl
            # rejects, and the raw returncode used to be ignored.
            return (str(v).replace("&", "&amp;").replace("<", "&lt;")
                    .replace(">", "&gt;"))

        with open(plist, "w", encoding="utf-8") as fh:
            fh.write(f"""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>Label</key><string>{_x(launchd_label)}</string>
  <key>ProgramArguments</key>
  <array>
    <string>{_x(sys.executable)}</string>
    <string>-u</string>
    <string>{_x(os.path.abspath(os.path.join(root, 'agentctl.py')))}</string>
    {''.join(f'<string>{_x(a)}</string>' for a in tail)}
  </array>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><true/>
  <key>StandardOutPath</key><string>{_x(logr)}</string>
  <key>StandardErrorPath</key><string>{_x(logr)}</string>
</dict></plist>""")
        subprocess.run(["launchctl", "unload", plist], capture_output=True)
        # Check the result. launchctl reports a malformed plist (e.g. an agent
        # name containing & or <) only in its output; ignoring returncode made
        # install claim success for a job that would never start.
        load = subprocess.run(["launchctl", "load", plist], capture_output=True, text=True)
        if load.returncode != 0:
            detail = (load.stderr or load.stdout or "").strip()
            print(f"launchctl failed to load {plist}: {detail}")
            print("  The plist may be malformed if the agent name or server URL")
            print("  contains &, < or >. Re-run install with a simpler name.")
            return 1
        cfg["installed"] = "macos:launchd"
        write_config(cfg)
        print(f"installed LaunchAgent {plist}")
        if not is_privileged():
            # A LaunchAgent always runs as the logged-in user, so it can never
            # hold raw sockets on its own. Unlike systemd's ExecStart there is
            # no clean way to re-elevate inside the plist, so say it plainly
            # rather than let the user discover it via blank MACs at the next scan.
            print("warning: macOS LaunchAgents cannot elevate. The autostart agent will")
            print("         run unprivileged and return blank MAC/vendor/OS. For Layer-2")
            print("         data on macOS use a LaunchDaemon instead, or run the agent")
            print("         from a root shell:")
            print(f"           sudo {sys.executable} {os.path.abspath(os.path.join(root, 'agentctl.py'))} run --server {cfg.get('server','')} --name {cfg.get('name','')}")
        return 0
    unit_name = UNIT_NAME
    if shutil.which("systemctl"):
        sudo_user = os.environ.get("SUDO_USER") or ""
        run_user = sudo_user or os.environ.get("USER") or ""
        pw = None
        if run_user:
            try:
                import pwd
                pw = pwd.getpwnam(run_user)
            except Exception:
                pw = None

        # --- Clean up any unit written by an older version -----------------
        # Those wrote `ExecStart=sudo ...` into a per-user unit with
        # Restart=always. With no terminal to prompt on, every restart was a
        # failed PAM authentication, and pam_faillock eventually locked the
        # user's account out of the whole machine. Never leave one in place.
        legacy = os.path.expanduser(LEGACY_USER_UNIT)
        legacy_bad = False
        if os.path.isfile(legacy):
            with open(legacy, encoding="utf-8", errors="replace") as fh:
                legacy_bad = unit_is_dangerous(fh.read())
        if legacy_bad:
            print("REMOVING a dangerous unit from a previous version:")
            print(f"  {legacy}")
            print("  It ran `sudo` in the background with Restart=always, which fails")
            print("  PAM authentication on every retry and can lock your account")
            print("  (pam_faillock). Disable and delete it now.")
            env_l = dict(os.environ)
            as_user_l = (["runuser", "-u", run_user, "--"]
                         if run_user and os.geteuid() == 0
                         and shutil.which("runuser") else [])
            subprocess.run(as_user_l + ["systemctl", "--user", "disable", "--now",
                                        unit_name], capture_output=True, env=env_l)
            try:
                os.remove(legacy)
            except Exception as e:
                print(f"  could not delete it: {e}")
                print(f"  remove it manually: rm {legacy}")
            else:
                print("  removed.")

        ctl_abs = os.path.abspath(os.path.join(root, "agentctl.py"))
        key = read_key()
        can_write_system = os.geteuid() == 0

        if can_write_system:
            # Preferred: a system unit that is already root. No sudo, no PAM,
            # no password prompt, full ARP/MAC/vendor/OS.
            unit_text = render_system_unit(sys.executable, ctl_abs, args_str)
            with open(SYSTEM_UNIT, "w", encoding="utf-8") as fh:
                fh.write(unit_text)
            os.chmod(SYSTEM_UNIT, 0o644)
            # Key in a root-only file rather than inline in the unit.
            with open(SYSTEM_ENV, "w", encoding="utf-8") as fh:
                fh.write(f"SCANNER_AGENT_KEY={key}\n")
            os.chmod(SYSTEM_ENV, 0o600)
            if unit_is_dangerous(unit_text):  # belt and braces
                raise SystemExit("refusing to install a unit that prompts for a password")
            subprocess.run(["systemctl", "daemon-reload"], capture_output=True)
            r = subprocess.run(["systemctl", "enable", "--now", unit_name],
                               capture_output=True, text=True)
            if r.returncode != 0:
                detail = (r.stderr or r.stdout or "").strip()
                print(f"could not start the unit automatically: {detail}")
                print(f"  start it yourself with:  sudo systemctl enable --now {unit_name}")
                print(f"  inspect it with:        journalctl -u {unit_name} -f")
            else:
                print(f"installed system unit {SYSTEM_UNIT} (runs as root, no sudo)")
            cfg["installed"] = "linux:systemd-system"
            write_config(cfg)
            return 0

        # No root: write a per-user unit that cannot and does not try to
        # elevate. This is the honest degraded mode -- TCP connect scanning and
        # hostnames work, ARP/MAC/vendor/OS do not.
        env_dir = os.path.join(os.path.expanduser("~"), ".config", "subnex-agent")
        os.makedirs(env_dir, exist_ok=True)
        unit_dir = os.path.join(os.path.expanduser("~"), ".config", "systemd", "user")
        os.makedirs(unit_dir, exist_ok=True)
        unit_text = render_user_unit(sys.executable, ctl_abs, args_str)
        if unit_is_dangerous(unit_text):
            raise SystemExit("refusing to install a unit that prompts for a password")
        with open(os.path.join(unit_dir, f"{unit_name}.service"), "w",
                  encoding="utf-8") as fh:
            fh.write(unit_text)
        with open(os.path.join(env_dir, "agent.env"), "w", encoding="utf-8") as fh:
            fh.write(f"SCANNER_AGENT_KEY={key}\n")
        os.chmod(os.path.join(env_dir, "agent.env"), 0o600)
        subprocess.run(["systemctl", "--user", "daemon-reload"], capture_output=True)
        r = subprocess.run(["systemctl", "--user", "enable", "--now", unit_name],
                           capture_output=True, text=True)
        if r.returncode != 0:
            detail = (r.stderr or r.stdout or "").strip()
            print(f"could not start the unit automatically: {detail}")
            print(f"  start it yourself with:  systemctl --user enable --now {unit_name}")
        else:
            print(f"installed user systemd unit {unit_dir}/{unit_name}.service")
        if run_user:
            try:
                subprocess.run(["loginctl", "enable-linger", run_user], capture_output=True)
            except Exception:
                pass
        print()
        print("NOTE: this unit runs as your user, so it cannot open raw sockets.")
        print("      Scans still work over TCP connect, but MAC/vendor/OS stay blank.")
        print("      For Layer-2 data, re-run install as root to get a system unit:")
        print(f"        sudo {sys.executable} {ctl_abs} install")
        print()
        print("      This unit deliberately contains no sudo: a background service has")
        print("      no terminal to answer a password prompt, so it would fail")
        print("      authentication forever and lock your account via pam_faillock.")
        cfg["installed"] = "linux:systemd-user"
        write_config(cfg)
        return 0
    cron_line = (f"@reboot {sys.executable} -u "
                   f"{os.path.abspath(os.path.join(root, 'agentctl.py'))} run --foreground "
                   f"{' '.join(shell_quote(a) for a in tail)} >> {shell_quote(logr)} 2>&1")
    # Write via stdin, not shell string interpolation. Building an `os.system`
    # command with the agent name / server URL / existing crontab embedded in
    # single and double quotes breaks on any quote character and replaces the
    # whole crontab. This used `tail`-less cmd[2:], which also emitted the
    # script path twice and made argparse die with "unrecognized arguments".
    try:
        existing = subprocess.run(["crontab", "-l"], capture_output=True, text=True).stdout
    except Exception:
        existing = ""
    kept = [l for l in existing.splitlines() if "agentctl.py" not in l or "run" not in l]
    body = "\n".join(kept + [cron_line]).strip() + "\n"
    try:
        r = subprocess.run(["crontab", "-"], input=body, capture_output=True, text=True)
        if r.returncode != 0:
            raise SystemExit(f"could not write crontab: {r.stderr.strip()}")
    except FileNotFoundError:
        raise SystemExit("`crontab` not found; install a cron implementation or use Docker")
    cfg["installed"] = "linux:cron"
    write_config(cfg)
    print("installed @reboot crontab entry")
    return 0


def cmd_uninstall(args) -> int:
    cmd_stop(args)
    if os.name == "nt":
        subprocess.run(["schtasks", "/delete", "/tn", WINDOWS_TASK, "/f"], capture_output=True)
    elif sys.platform == "darwin":
        plist = os.path.expanduser("~/Library/LaunchAgents/local.subnex.agent.plist")
        subprocess.run(["launchctl", "unload", plist], capture_output=True)
        try:
            os.remove(plist)
        except OSError:
            pass
    elif shutil.which("systemctl"):
        # Remove BOTH shapes: the root system unit and the per-user unit.
        subprocess.run(["systemctl", "disable", "--now", UNIT_NAME], capture_output=True)
        subprocess.run(["systemctl", "--user", "disable", "--now", UNIT_NAME],
                       capture_output=True)
        for p in (SYSTEM_UNIT,
                  os.path.expanduser(LEGACY_USER_UNIT),
                  os.path.expanduser("~/.config/subnex-agent/agent.env")):
            try:
                os.remove(p)
            except OSError:
                pass
        subprocess.run(["systemctl", "daemon-reload"], capture_output=True)
        subprocess.run(["systemctl", "--user", "daemon-reload"], capture_output=True)
        if os.geteuid() == 0:
            try:
                os.remove(SYSTEM_ENV)
            except OSError:
                pass
    else:
        try:
            out = subprocess.run(["crontab", "-l"], capture_output=True,
                                 text=True, timeout=15).stdout
        except Exception:
            out = ""
        kept = [l for l in out.splitlines() if "agentctl.py run" not in l]
        subprocess.run(["crontab", "-"], input="\n".join(kept).strip() + "\n",
                       capture_output=True, text=True)
    cfg = read_config()
    cfg["installed"] = False
    write_config(cfg)
    print("agent uninstalled (autostart removed).")
    return 0


def cmd_purge(args) -> int:
    """Complete local removal: processes, autostart, state, keys, and the
    cross-user lock.

    Needed because deleting the agent row in the UI only removes the server
    side. Everything on disk survives -- and the survivors actively cause
    trouble later:

      * ~/.subnex keeps the old API key, so `run` re-registers the deleted
        agent instead of a fresh one;
      * an installed unit/LaunchAgent restarts the agent at every logon, which
        then 401s against a key the server no longer knows;
      * the /tmp instance lock survives, making the NEXT agent refuse to start
        with a bogus "already running" error;
      * root's copy is invisible when purging as a normal user, so a privileged
        agent keeps polling and steals tasks from its unprivileged twin.

    Run it as root to clean up both users at once.
    """
    import glob as _glob
    import shutil as _shutil

    removed, missing = [], []

    # System-level install (root). Stopped before the files are touched so a
    # running unit cannot rewrite them underneath us.
    if os.name != "nt" and shutil.which("systemctl"):
        subprocess.run(["systemctl", "disable", "--now", UNIT_NAME],
                       capture_output=True)
        subprocess.run(["systemctl", "--user", "disable", "--now", UNIT_NAME],
                       capture_output=True)
    for p in (SYSTEM_UNIT, SYSTEM_ENV):
        if os.path.exists(p):
            try:
                os.remove(p)
                removed.append(f"removed {p}")
            except Exception as e:
                missing.append(f"{p} ({e})")

    # -- 1. processes ------------------------------------------------------
    # The pid file is per-$HOME, so as a normal user it cannot see an agent owned
    # by another account. Sweep every agent process on the box instead.
    killed = []
    for pid, owner in all_agent_processes():
        try:
            if os.name == "nt":
                subprocess.run(["taskkill", "/PID", str(pid), "/T", "/F"],
                               capture_output=True, timeout=20)
            else:
                os.kill(pid, signal.SIGTERM)
            killed.append((pid, owner))
        except PermissionError:
            tip = (f"stop-Process -Id {pid} -Force" if os.name == "nt"
                   else f"sudo kill {pid}")
            print(f"  ! PID {pid} ({owner}) needs elevation: {tip}")
        except Exception:
            pass
    if killed:
        time.sleep(2)
        for pid, owner in killed:
            removed.append(f"stopped agent process PID {pid} (user {owner})")
        left = [p for p, _o in killed if pid_alive(p)]
        for p in left:
            tip = (f"stop-Process -Id {p} -Force" if os.name == "nt"
                   else f"sudo kill -9 {p}")
            print(f"  ! PID {p} still alive: {tip}")

    # -- 2. autostart entries, for every user on the box --------------------
    users = all_user_homes()
    seen_homes = set()
    for u, home in users:
        if not home or home in seen_homes:
            continue
        seen_homes.add(home)
        for rel in (".config/systemd/user/subnex-agent.service",
                    ".config/subnex-agent/agent.env",
                    "Library/LaunchAgents/local.subnex.agent.plist"):
            p = os.path.join(home, rel.replace("/", os.sep))
            if os.path.exists(p):
                try:
                    os.remove(p)
                    removed.append(f"removed {p}")
                except Exception as e:
                    missing.append(f"{p} ({e})")

    # macOS: also unload the job, or launchd keeps the old plist loaded.
    if sys.platform == "darwin":
        for _u, home in users:
            plist = os.path.join(home, "Library", "LaunchAgents", "local.subnex.agent.plist")
            if os.path.exists(plist):
                subprocess.run(["launchctl", "unload", plist], capture_output=True)

    # systemctl --user for each real user, best-effort
    if os.name != "nt" and shutil.which("systemctl"):
        for u, home in users:
            if u == "root" or not home:
                continue
            try:
                import pwd as _pwd
                uid = _pwd.getpwnam(u).pw_uid
                env = dict(os.environ, HOME=home, USER=u,
                           XDG_RUNTIME_DIR=f"/run/user/{uid}")
                env.pop("DBUS_SESSION_BUS_ADDRESS", None)
                if os.geteuid() == 0 and shutil.which("runuser"):
                    subprocess.run(["runuser", "-u", u, "--", "systemctl", "--user",
                                    "disable", "--now", "subnex-agent"],
                                   capture_output=True, env=env)
                    subprocess.run(["runuser", "-u", u, "--", "systemctl", "--user",
                                    "daemon-reload"], capture_output=True, env=env)
                else:
                    subprocess.run(["systemctl", "--user", "disable", "--now",
                                    "subnex-agent"], capture_output=True, env=env)
            except Exception:
                pass
    if os.name == "nt":
        r = subprocess.run(["schtasks", "/delete", "/tn", WINDOWS_TASK, "/f"],
                           capture_output=True, text=True)
        if r.returncode == 0:
            removed.append(f"deleted scheduled task {WINDOWS_TASK}")
        else:
            missing.append(f"scheduled task {WINDOWS_TASK} ({r.stderr.strip() or 'not present'})")

    # -- 3. cross-user instance locks --------------------------------------
    # These live in a shared dir and are the reason a freshly-created agent can
    # be told "already running" when nothing is. Always clear them.
    for lock in _glob.glob(os.path.join(_lock_dir(), "subnex-agent-*.lock")):
        try:
            os.unlink(lock)
            removed.append(f"removed stale lock {lock}")
        except Exception:
            pass

    # -- 4. state dirs, for every user --------------------------------------
    for u, home in users:
        if not home:
            continue
        try:
            d = os.path.join(home, APP_DIR_NAME)
        except Exception:
            continue
        if os.path.isdir(d):
            try:
                _shutil.rmtree(d)
                removed.append(f"removed {d} (config, key, pid files, log)")
            except Exception as e:
                missing.append(f"{d} ({e})")

    # -- 5. the downloaded bundle dir, if we are inside one -----------------
    here = os.path.dirname(os.path.abspath(__file__))
    if os.path.basename(here) == "agent" and os.path.basename(os.path.dirname(here)) == "subnex-agent":
        try:
            _shutil.rmtree(os.path.dirname(here))
            removed.append(f"removed {os.path.dirname(here)}")
        except Exception as e:
            missing.append(f"{os.path.dirname(here)} ({e})")

    for line in removed:
        print(f"  {line}")
    for line in missing:
        print(f"  ! could not remove {line}")
    print()
    if not removed:
        print("nothing to clean (agent may already be gone).")
    print("agent fully purged. Register a new agent in the UI when ready.")
    if missing or any(pid_alive(p) for p, _ in killed):
        print("note: some items need root. Re-run as: sudo python3 agentctl.py purge")
    return 0


def _proc_owner(pid: int) -> str:
    try:
        import pwd as _pwd
        return _pwd.getpwuid(os.stat(f"/proc/{pid}").st_uid).pw_name
    except Exception:
        return "?"


def cmd_status(args) -> int:
    cfg = read_config()
    key = read_key()
    print(f"agent config   : {config_path()}")
    print(f"server         : {cfg.get('server') or '(not configured)'}")
    print(f"name           : {cfg.get('name') or DEFAULT_NAME}")
    print(f"subnets        : {SUBNET_SEP.join(cfg.get('subnets') or []) or '(auto)'}")
    print(f"privileged     : {'yes' if is_privileged() else 'no'}{' (Windows: run as admin for SYN/running as a service)' if os.name == 'nt' and not is_privileged() else ''}")
    if not is_privileged():
        print()
        print("  ! Scans delegated to this agent will return NO MAC/vendor/OS.")
        print("    ARP, SYN and passive sniffing all need raw sockets. Fix with one of:")
        if os.name == "nt":
            print("      - reopen this terminal as Administrator")
        else:
            print("      - restart the agent with sudo")
        print("      - or run it as a container with --cap-add NET_RAW --cap-add NET_ADMIN")
        print("      - or add --connect for privilege-free TCP connect scanning")
    print(f"nmap           : {shutil.which('nmap') or 'NOT FOUND (install nmap first)'}")
    sup = read_pid("supervisor")
    ag = read_pid("agent")
    print(f"supervisor pid : {sup if pid_alive(sup) else 'not running'}")
    print(f"agent pid      : {ag if pid_alive(ag) else 'not running'}")
    st = autostart_status()
    print(f"autostart      : {st}")
    if st == "dangerous":
        # Loud, actionable, and specific: this state locked a user out of their
        # machine once already.
        print()
        print("  *** DANGEROUS AUTOSTART ENTRY ***")
        print("  An installed unit runs `sudo` in the background with no terminal to")
        print("  answer a password prompt. Every retry is a failed PAM authentication,")
        print("  which pam_faillock counts -- it can lock your account out of the")
        print("  whole machine.")
        print(f"  Remove it with:  python {os.path.abspath(__file__)} repair")
        print()
    if not key:
        print("API key        : MISSING -- run with --api-key after creating the agent")
        return 1
    if not cfg.get("server"):
        print("server         : MISSING -- run `python agentctl.py run --server ...` once")
        return 1
    try:
        ok, agent_id = verify_key(cfg["server"], key)
    except Exception as exc:
        print(f"server         : UNREACHABLE ({exc})")
        return 1
    if not ok:
        print("API key        : REJECTED by server (HTTP 401) -- reset the key on the Agents page and `python agentctl.py key --set <new>`")
        return 1
    print(f"agent id       : {agent_id}")
    print("status         : key valid, server reachable")
    return 0


def cmd_repair(args) -> int:
    exit_code = cmd_status(args)
    key = read_key()
    cfg = read_config()
    if exit_code == 0:
        print()
        print("--- repairing ---")
    else:
        print()
        print("--- attempting repair ---")
    if not key or not cfg.get("server"):
        print("cannot repair: agent config/key missing. Follow the setup steps first.")
        return 1
    try:
        ok, _ = verify_key(cfg["server"], key)
    except Exception as exc:
        print(f"server unreachable ({exc}): is the backend up?")
        return 1
    if not ok:
        print("key rejected. Reset it on the Agents page, then:")
        print(f"  python agentctl.py key --set <NEW_KEY>")
        print(f"  python agentctl.py repair")
        return 1
    sup = read_pid("supervisor")
    if sup > 0 and pid_alive(sup):
        print(f"supervisor already running (PID {sup})")
    else:
        root = os.path.dirname(os.path.abspath(__file__))
        pid = _spawn_detached(_supervisor_cmd(root, cfg), log_path())
        write_pid("supervisor", pid)
        print(f"restarted agent supervisor (PID {pid})")
    if autostart_status() in ("missing", "not_installed", "dangerous"):
        try:
            cmd_install(args)
        except SystemExit as exc:
            print(f"autostart re-install skipped: {exc}")
    else:
        print(f"autostart entry OK ({autostart_status()})")
    print("repair complete. Verify with `python agentctl.py status`.")
    return 0


def cmd_key(args) -> int:
    if args.set_key:
        write_key(args.set_key)
        print(f"saved agent key to {key_path()}")
        return 0
    print(f"key file       : {key_path()}")
    print(f"key present    : {'yes' if read_key() else 'no'}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="agentctl",
        description="SubNex LAN agent controller (cross-platform setup/repair).",
    )
    sub = p.add_subparsers(dest="command", required=True)

    def add_common(sp):
        sp.add_argument("--server", default=None, help="backend base URL, e.g. http://192.168.1.50:8000")
        sp.add_argument("--name", default=None, help=f"agent name (default {DEFAULT_NAME})")
        sp.add_argument("--subnets", default=None, help="comma-separated L2 subnets, e.g. 192.168.1.0/24")
        sp.add_argument("--api-key", default=None, help="agent API key from the Agents page (saved to disk)")

    s = sub.add_parser("run", help="start (and supervise) the agent")
    add_common(s)
    s.add_argument("--foreground", action="store_true",
                   help="supervise in this terminal (recommended; autostart uses this)")
    # `status` tells unprivileged users to add this, so argparse has to accept
    # it. Privileged-only nmap flags are stripped automatically when the agent
    # has no raw sockets, so this is genuinely privilege-free.
    s.add_argument("--connect", action="store_true",
                   help="TCP connect scanning only: needs no root/Administrator, "
                        "so no MAC/vendor/OS but works unprivileged")

    sub.add_parser("stop", help="stop the agent (keep autostart entry)")
    s = sub.add_parser("install", help="persist the agent across reboot/logon")
    s.add_argument("--name", default=None)
    s.add_argument("--subnets", default=None)
    s.add_argument("--server", default=None)
    sub.add_parser("uninstall", help="stop the agent and remove autostart")
    sub.add_parser("purge", help="uninstall + delete ALL local state (use after deleting the agent in the UI)")
    sub.add_parser("status", help="agent + server health")
    sub.add_parser("repair", help="restart agent / re-add autostart / re-check key")
    s = sub.add_parser("key", help="manage the stored API key")
    s.add_argument("--set", dest="set_key", default=None, help="store a new key (e.g. after reset-key)")
    return p


def main() -> None:
    args = build_parser().parse_args()
    handlers = {
        "run": cmd_run,
        "stop": cmd_stop,
        "install": cmd_install,
        "uninstall": cmd_uninstall,
        "purge": cmd_purge,
        "status": cmd_status,
        "repair": cmd_repair,
        "key": cmd_key,
    }
    try:
        sys.exit(handlers[args.command](args) or 0)
    except SystemExit:
        raise
    except KeyboardInterrupt:
        sys.exit(130)
    except Exception as exc:
        print(f"agentctl error: {exc}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()