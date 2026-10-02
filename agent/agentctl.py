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


def _instance_lock_path(name: str, server: str) -> str:
    """System-wide lock, deliberately NOT under $HOME.

    The per-user state dir can't stop two agents of the same name: root and a
    normal user each get their own app_dir(), so each sees no pid file and both
    start. They then share one API key, resolve to the same DB row, and the
    unprivileged instance wins the task queue -- handing back scans with blank
    MAC/vendor/OS and no error anywhere. Keying the lock on name+server in a
    shared location (/tmp) makes the collision visible at startup instead.
    """
    tag = f"{name}@{server}".replace("/", "_").replace(":", "_")
    return os.path.join(tempfile.gettempdir(), f"subnex-agent-{tag}.lock")


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
    """True when pid runs under the same uid as us."""
    try:
        return os.stat(f"/proc/{pid}").st_uid == os.geteuid()
    except Exception:
        return False


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


def is_privileged() -> bool:
    """True when this process can open raw sockets.

    Root is the usual answer, but a container (or a systemd unit) can hold
    CAP_NET_RAW without being uid 0, so check the effective capability set too.
    Getting this wrong is how agents end up reporting L2 capability they do not
    have and returning scans with blank MAC/vendor/OS.
    """
    try:
        if os.name == "nt":
            import ctypes
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
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
    return {"key": key, "server": server, "name": name, "subnets": subs}


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
        return "installed" if os.path.isfile(plist) else "missing"
    unit = os.path.expanduser("~/.config/systemd/user/subnex-agent.service")
    if os.path.isfile(unit):
        try:
            out = subprocess.run(["systemctl", "--user", "is-enabled", "subnex-agent"],
                                 capture_output=True, text=True, timeout=15).stdout.strip()
            return "installed" if out == "enabled" else "missing"
        except Exception:
            return "installed"
    crontab = os.popen("crontab -l 2>/dev/null").read()
    return "installed" if "agentctl.py run --foreground" in crontab else "missing"


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
        with open(plist, "w", encoding="utf-8") as fh:
            fh.write(f"""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>Label</key><string>{launchd_label}</string>
  <key>ProgramArguments</key>
  <array>
    <string>{sys.executable}</string>
    <string>-u</string>
    <string>{os.path.abspath(os.path.join(root, 'agentctl.py'))}</string>
    {''.join(f'<string>{a}</string>' for a in tail)}
  </array>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><true/>
  <key>StandardOutPath</key><string>{logr}</string>
  <key>StandardErrorPath</key><string>{logr}</string>
</dict></plist>""")
        subprocess.run(["launchctl", "unload", plist], capture_output=True)
        subprocess.run(["launchctl", "load", plist])
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
    unit_name = "subnex-agent"
    if shutil.which("systemctl"):
        # Resolve the *real* user's home. Running this under sudo leaves HOME=/root,
        # which silently installs a root-owned unit that never starts at the user's
        # login. SUDO_USER names who actually invoked us.
        sudo_user = os.environ.get("SUDO_USER") or ""
        run_user = sudo_user or os.environ.get("USER") or ""
        pw = None
        home = os.path.expanduser("~")
        if run_user:
            try:
                import pwd
                pw = pwd.getpwnam(run_user)
                home = pw.pw_dir
            except Exception:
                pw = None
        unit_dir = os.path.join(home, ".config", "systemd", "user")
        os.makedirs(unit_dir, exist_ok=True)
        unit = os.path.join(unit_dir, f"{unit_name}.service")
        # Elevation goes INSIDE the unit, and it is ALWAYS needed here: a
        # `systemctl --user` unit runs as the logged-in user and can never be
        # root, no matter what privilege the `install` command itself had.
        # Checking is_privileged() here is wrong -- when install is run under
        # sudo it returns True and emits a unit with no `sudo`, which then
        # starts unprivileged at boot and quietly returns blank MAC/vendor/OS.
        elevate = "sudo "
        with open(unit, "w", encoding="utf-8") as fh:
            fh.write(f"""[Unit]
Description=SubNex LAN scanner agent
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
Restart=always
RestartSec=5
ExecStart={elevate}{sys.executable} -u {os.path.abspath(os.path.join(root, 'agentctl.py'))} {args_str}
Environment=SCANNER_AGENT_KEY={read_key()}

[Install]
WantedBy=default.target
""")
        if sudo_user and os.geteuid() == 0 and pw:
            # Fix ownership so the user can later enable/disable their own unit.
            try:
                os.chown(unit_dir, pw.pw_uid, pw.pw_gid)
                os.chown(unit, pw.pw_uid, pw.pw_gid)
            except Exception:
                pass
        env = dict(os.environ)
        if run_user:
            env["HOME"] = home
            env["USER"] = run_user
            # systemctl --user needs the session bus; a sudo'd shell has neither
            # of the variables it looks for, which is the "Failed to connect to
            # user scope bus" error.
            if pw:
                env["XDG_RUNTIME_DIR"] = f"/run/user/{pw.pw_uid}"
            env.pop("DBUS_SESSION_BUS_ADDRESS", None)
        as_user = ["runuser", "-u", run_user, "--"] if run_user and os.geteuid() == 0 and shutil.which("runuser") else []
        subprocess.run(as_user + ["systemctl", "--user", "daemon-reload"], capture_output=True, env=env)
        r = subprocess.run(as_user + ["systemctl", "--user", "enable", "--now", unit_name],
                           capture_output=True, text=True, env=env)
        if r.returncode != 0:
            detail = (r.stderr or r.stdout or "").strip()
            print(f"could not start the unit automatically: {detail}")
            print(f"  start it yourself with:  systemctl --user enable --now {unit_name}")
            print(f"  or at boot without a login:  sudo loginctl enable-linger {run_user}")
        else:
            print(f"installed user systemd unit {unit_name}")
        if run_user:
            try:
                subprocess.run(["loginctl", "enable-linger", run_user], capture_output=True)
            except Exception:
                pass
        if not is_privileged():
            print("note: the unit re-elevates with sudo on start, so it still gets raw-socket")
            print("      privileges. Allow NOPASSWD for it, or the start will prompt at boot:")
            print(f"      sudo visudo   # rule: sz ALL=(ALL) NOPASSWD: {sys.executable} *")
        cfg["installed"] = "linux:systemd-user"
        write_config(cfg)
        return 0
    cron_line = f"@reboot {sys.executable} -u {os.path.abspath(os.path.join(root, 'agentctl.py'))} run --foreground {' '.join(shell_quote(a) for a in cmd[2:])} >> {shell_quote(logr)} 2>&1"
    existing = os.popen("crontab -l 2>/dev/null").read()
    os.system(f"(echo '{cron_line}'; echo \"{existing}\") | crontab -")
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
        subprocess.run(["systemctl", "--user", "disable", "--now", "subnex-agent"], capture_output=True)
        try:
            os.remove(os.path.expanduser("~/.config/systemd/user/subnex-agent.service"))
        except OSError:
            pass
        subprocess.run(["systemctl", "--user", "daemon-reload"], capture_output=True)
    else:
        out = os.popen("crontab -l 2>/dev/null").read()
        kept = [l for l in out.splitlines() if "agentctl.py run" not in l]
        data = "\n".join(kept) + "\n"
        os.system(f"(echo '{data}') | crontab -")
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
    import glob
    import pwd as _pwd
    import shutil as _shutil

    removed, missing = [], []

    # -- 1. processes ------------------------------------------------------
    # The pid file is per-$HOME, so as a normal user it cannot see a root-owned
    # agent. Sweep every agent process on the box instead.
    killed = []
    for entry in glob.glob("/proc/[0-9]*/cmdline"):
        try:
            pid = int(entry.split("/")[2])
            with open(entry, "rb") as fh:
                cmd = fh.read().decode("utf-8", "replace").replace("\x00", " ")
            if "agentctl.py" in cmd or "scanner_agent.py" in cmd:
                if pid == os.getpid():
                    continue
                try:
                    os.kill(pid, signal.SIGTERM)
                    killed.append((pid, _proc_owner(pid)))
                except PermissionError:
                    print(f"  ! PID {pid} ({_proc_owner(pid)}) needs root: sudo kill {pid}")
                except Exception:
                    pass
        except Exception:
            continue
    if killed:
        time.sleep(2)
        for pid, _u in killed:
            removed.append(f"stopped agent process PID {pid} (user {_u})")
        left = [p for p, _u in killed if pid_alive(p)]
        for p in left:
            print(f"  ! PID {p} still alive: sudo kill -9 {p}")

    # -- 2. autostart entries, for every user on the box --------------------
    users = []
    try:
        users = [p.pw_name for p in _pwd.getpwall()]
    except Exception:
        users = [os.environ.get("USER") or "root"]
    for u in users:
        try:
            home = _pwd.getpwnam(u).pw_dir
        except Exception:
            continue
        for rel in (".config/systemd/user/subnex-agent.service",
                    "Library/LaunchAgents/local.subnex.agent.plist"):
            p = os.path.join(home, rel)
            if os.path.exists(p):
                try:
                    os.remove(p)
                    removed.append(f"removed {p}")
                except Exception as e:
                    missing.append(f"{p} ({e})")

    # systemctl --user for each real user, best-effort
    for u in users:
        if u == "root":
            continue
        try:
            uid = _pwd.getpwnam(u).pw_uid
            env = dict(os.environ, HOME=_pwd.getpwnam(u).pw_dir, USER=u,
                       XDG_RUNTIME_DIR=f"/run/user/{uid}")
            env.pop("DBUS_SESSION_BUS_ADDRESS", None)
            if os.geteuid() == 0:
                subprocess.run(["runuser", "-u", u, "--", "systemctl", "--user",
                                "disable", "--now", "subnex-agent"],
                               capture_output=True, env=env)
                subprocess.run(["runuser", "-u", u, "--", "systemctl", "--user",
                                "daemon-reload"], capture_output=True, env=env)
            else:
                subprocess.run(["systemctl", "--user", "disable", "--now", "subnex-agent"],
                               capture_output=True, env=env)
        except Exception:
            pass
    if os.name == "nt":
        subprocess.run(["schtasks", "/delete", "/tn", WINDOWS_TASK, "/f"], capture_output=True)
        removed.append(f"deleted scheduled task {WINDOWS_TASK}")

    # -- 3. cross-user instance locks --------------------------------------
    # These live in /tmp and are the reason a freshly-created agent can be told
    # "already running" when nothing is. Always clear them.
    for lock in glob.glob(os.path.join(tempfile.gettempdir(), "subnex-agent-*.lock")):
        try:
            os.unlink(lock)
            removed.append(f"removed stale lock {lock}")
        except Exception:
            pass

    # -- 4. state dirs, for every user --------------------------------------
    for u in users:
        try:
            d = os.path.join(_pwd.getpwnam(u).pw_dir, APP_DIR_NAME)
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
    print(f"autostart      : {autostart_status()}")
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
    if autostart_status() in ("missing", "not_installed"):
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