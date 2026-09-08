"""Single-process supervisor: runs uvicorn (the API) and optionally the Celery
scan worker in the same container.

Usage:
    python -m app.run_server [--worker] [--reload] [--port 8000]

Crashed children are restarted with exponential backoff; SIGTERM/SIGINT stop
both processes cleanly. Logs are inherited, so `docker compose logs` shows the
API and scan-worker output interleaved.
"""
import argparse
import signal
import subprocess
import sys
import time


def main() -> int:
    parser = argparse.ArgumentParser(description="Run the API (+ Celery worker).")
    parser.add_argument("--worker", action="store_true", help="also run the Celery scan worker")
    parser.add_argument("--reload", action="store_true", help="pass --reload to uvicorn")
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", default="8000")
    args = parser.parse_args()

    children = {}
    stop = False

    def _stop(_signum=None, _frame=None):
        nonlocal stop
        stop = True
        for p in children.values():
            if p.poll() is None:
                try:
                    p.terminate()
                except OSError:
                    pass

    signal.signal(signal.SIGTERM, _stop)
    signal.signal(signal.SIGINT, _stop)

    def _spawn(cmd, key):
        p = subprocess.Popen(cmd)
        children[key] = p
        return p

    while not stop:
        if "api" not in children or children["api"].poll() is not None:
            cmd = ["uvicorn", "app.main:app", "--host", args.host, "--port", args.port]
            if args.reload:
                cmd.append("--reload")
            _spawn(cmd, "api")
        if args.worker and ("worker" not in children or children["worker"].poll() is not None):
            _spawn(["celery", "-A", "app.services.scan_worker", "worker", "--loglevel=info"], "worker")

        alive = False
        for key, p in list(children.items()):
            if p.poll() is None:
                alive = True
            else:
                code = p.poll()
                print(f"[supervisor] {key} exited (code {code}); restarting", file=sys.stderr)
                children.pop(key, None)
                if code == 0:
                    _stop()
        if stop:
            break
        if not alive:
            time.sleep(2)
        time.sleep(1)

    for p in children.values():
        try:
            p.wait(timeout=5)
        except Exception:
            try:
                p.kill()
            except OSError:
                pass
    return 0


if __name__ == "__main__":
    sys.exit(main())