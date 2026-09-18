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
    try:
        if os.name == "nt":
            import ctypes
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        return os.geteuid() == 0
    except Exception:
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
    if os.environ.get("SCANNER_AGENT_KEY") or not read_key():
        cmd += ["--api-key", os.environ.get("SCANNER_AGENT_KEY") or cfg["key"]]
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
    backoff = 1
    runs = 0
    print(f"[agentctl] supervising {cfg['name']} -> {cfg['server']}")
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
    args_str = " ".join(shell_quote(a) for a in cmd[2:])
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
    {''.join(f'<string>{a}</string>' for a in cmd[2:])}
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
        return 0
    unit_name = "subnex-agent"
    if shutil.which("systemctl"):
        unit_dir = os.path.expanduser("~/.config/systemd/user")
        os.makedirs(unit_dir, exist_ok=True)
        unit = os.path.join(unit_dir, f"{unit_name}.service")
        with open(unit, "w", encoding="utf-8") as fh:
            fh.write(f"""[Unit]
Description=SubNex LAN scanner agent
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
Restart=always
RestartSec=5
ExecStart={sys.executable} -u {os.path.abspath(os.path.join(root, 'agentctl.py'))} {' '.join(cmd[2:])}
Environment=SCANNER_AGENT_KEY={read_key()}

[Install]
WantedBy=default.target
""")
        subprocess.run(["systemctl", "--user", "daemon-reload"], capture_output=True)
        r = subprocess.run(["systemctl", "--user", "enable", "--now", unit_name], capture_output=True, text=True)
        if r.returncode != 0:
            print(r.stderr.strip())
        try:
            subprocess.run(["loginctl", "enable-linger", os.environ.get("USER", "")], capture_output=True)
        except Exception:
            pass
        cfg["installed"] = "linux:systemd-user"
        write_config(cfg)
        print(f"installed user systemd unit {unit_name}")
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


def cmd_status(args) -> int:
    cfg = read_config()
    key = read_key()
    print(f"agent config   : {config_path()}")
    print(f"server         : {cfg.get('server') or '(not configured)'}")
    print(f"name           : {cfg.get('name') or DEFAULT_NAME}")
    print(f"subnets        : {SUBNET_SEP.join(cfg.get('subnets') or []) or '(auto)'}")
    print(f"privileged     : {'yes' if is_privileged() else 'no'}{' (Windows: run as admin for SYN/running as a service)' if os.name == 'nt' and not is_privileged() else ''}")
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