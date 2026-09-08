import json
import threading
from collections import deque
from datetime import datetime, timezone
from typing import Dict, Set
from fastapi import WebSocket
from .config import get_settings
from .services.activity import append_activity

EVENT_CHANNEL = "scan_events"
MAX_RETRIES = 5
BUFFER_SIZE = 100
MAX_TRACKED_SCANS = 200


def _redis_client():
    import redis
    return redis.Redis.from_url(get_settings().REDIS_URL, decode_responses=True)


class ConnectionManager:
    def __init__(self):
        self.active_connections: Dict[str, Set[WebSocket]] = {}
        self._recent: Dict[str, deque] = {}
        self._loop = None
        self._loop_lock = threading.Lock()
        self._relay_started = False

    def _get_loop(self):
        """Return a long-lived background asyncio loop for sync (Celery) callers."""
        with self._loop_lock:
            if self._loop is None or self._loop.is_closed():
                import asyncio
                self._loop = asyncio.new_event_loop()
                t = threading.Thread(target=self._loop.run_forever, daemon=True)
                t.start()
            return self._loop

    def publish_event(self, scan_id: str, event: dict):
        """Publish a scan event to the shared Redis channel.

        Called from Celery workers (separate process) so the backend's relay
        loop can forward it to the relevant WebSocket clients.
        """
        try:
            payload = json.dumps({"scan_id": scan_id, "event": event})
            r = _redis_client()
            try:
                r.publish(EVENT_CHANNEL, payload)
            finally:
                r.close()
        except Exception:
            pass

    def broadcast_sync(self, scan_id: str, event: dict):
        """Broadcast a scan event.

        Publishes to Redis (worker -> backend relay) AND sends to any clients
        connected directly in this process. Safe to call from Celery workers.

        Delivery is fire-and-forget: the Redis publish is synchronous (fast) and
        the direct local send is scheduled onto the shared loop without waiting,
        so long-running scans never block the API on WebSocket fan-out.
        """
        # Stamp the emission timestamp here, once, so the WS message, the Redis
        # relay and the persisted activity feed all carry the same value (the UI
        # dedupes replayed history against live events using this key).
        if not event.get("ts"):
            event["ts"] = datetime.now(timezone.utc).isoformat()
        self.publish_event(scan_id, event)
        append_activity(scan_id, event)
        import asyncio
        loop = self._get_loop()
        try:
            asyncio.run_coroutine_threadsafe(self.broadcast(scan_id, event), loop)
        except Exception:
            pass

    async def connect(self, scan_id: str, websocket: WebSocket):
        await websocket.accept()
        if scan_id not in self.active_connections:
            self.active_connections[scan_id] = set()
        self.active_connections[scan_id].add(websocket)
        for event in list(self._recent.get(scan_id, ())):
            # Console (cmd_log) history is served by the persisted per-scan
            # console.log via GET /api/scans/{id}/logs and seeded by the UI, so
            # don't replay it here too - doing so renders every line twice.
            if event.get("type") == "cmd_log":
                continue
            try:
                await websocket.send_text(json.dumps(event))
            except Exception:
                break

    def disconnect(self, scan_id: str, websocket: WebSocket):
        if scan_id in self.active_connections:
            self.active_connections[scan_id].discard(websocket)

    async def broadcast(self, scan_id: str, event: dict):
        # Emission timestamp carried on every event (live AND replayed from the
        # buffer) so the UI can show real per-entry times even when a client
        # connects after several events were already produced.
        try:
            from datetime import datetime, timezone
            if not event.get("ts"):
                event["ts"] = datetime.now(timezone.utc).isoformat()
        except Exception:
            pass
        buf = self._recent.setdefault(scan_id, deque(maxlen=BUFFER_SIZE))
        buf.append(event)
        if len(self._recent) > MAX_TRACKED_SCANS:
            for old_scan in list(self._recent):
                if old_scan not in self.active_connections and self._recent[old_scan] is not buf:
                    del self._recent[old_scan]
        if scan_id in self.active_connections:
            message = json.dumps(event)
            dead = []
            for conn in self.active_connections[scan_id]:
                try:
                    await conn.send_text(message)
                except Exception:
                    dead.append(conn)
            for conn in dead:
                self.active_connections[scan_id].discard(conn)

    # ------------------------------------------------------------------ #
    # Redis relay: backend subscribes to shared channel and forwards to WS
    # ------------------------------------------------------------------ #
    def _relay_body(self):
        import asyncio
        # Dedicated private loop for this thread. pubsub.listen() is a *blocking*
        # iterator; running it on the shared loop (used by broadcast_sync) would
        # wedge every WebSocket fan-out for up to a timeout each call.
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        loop.run_until_complete(self._run_relay())

    async def _run_relay(self):
        import asyncio

        async def _relay():
            r = None
            pubsub = None
            try:
                r = _redis_client()
                pubsub = r.pubsub()
                pubsub.subscribe(EVENT_CHANNEL)
            except Exception:
                return
            try:
                for message in pubsub.listen():
                    if message.get("type") != "message":
                        continue
                    data = message.get("data")
                    try:
                        parsed = json.loads(data)
                        scan_id = parsed.get("scan_id")
                        event = parsed.get("event")
                        if scan_id and event:
                            # Forward onto the shared loop for safe websocket sends.
                            shared = self._get_loop()
                            try:
                                asyncio.run_coroutine_threadsafe(
                                    self.broadcast(scan_id, event), shared)
                            except Exception:
                                pass
                    except Exception:
                        continue
            finally:
                try:
                    if pubsub:
                        pubsub.close()
                except Exception:
                    pass
                try:
                    if r:
                        r.close()
                except Exception:
                    pass

        for attempt in range(MAX_RETRIES):
            try:
                await _relay()
            except Exception:
                pass
            await asyncio.sleep(2)

    def start_relay(self):
        """Spawn the Redis->WS relay in the backend process."""
        if self._relay_started:
            return
        self._relay_started = True
        t = threading.Thread(target=self._relay_body, daemon=True)
        t.start()


manager = ConnectionManager()
