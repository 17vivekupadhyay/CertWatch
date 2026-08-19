"""Optional CertStream-compatible websocket source.

A CertStream aggregator gives a pre-parsed firehose so there's no leaf parsing
to do. The well-known public endpoint has been unreliable and deprecated at
times, so this is OFF by default, never the only real-data path, and falls back
(via the caller) to direct polling if the socket drops.
"""

import json
import logging
import threading
import time

log = logging.getLogger("certwatch.certstream")

try:
    import websocket  # websocket-client
except ImportError:  # pragma: no cover
    websocket = None


def _normalize(msg):
    """Convert a CertStream ``certificate_update`` message to our record shape."""
    data = msg.get("data", {})
    leaf = data.get("leaf_cert", {})
    domains = [d.lower() for d in leaf.get("all_domains", []) if d]
    if not domains:
        return None
    issuer = ""
    issuer_obj = leaf.get("issuer", {}) or {}
    issuer = issuer_obj.get("O") or issuer_obj.get("CN") or ""
    not_before = leaf.get("not_before")
    source = data.get("source", {}) or {}
    return {
        "seen_at": data.get("seen", time.time()),
        "not_before": float(not_before) if not_before else time.time(),
        "issuer": issuer,
        "domains": domains,
        "log": source.get("name", "certstream"),
        "is_precert": data.get("update_type") == "PrecertLogEntry",
    }


class CertStreamClient(threading.Thread):
    """Connects to a CertStream websocket and pushes records to a queue.

    Sets ``self.failed`` if it cannot maintain a connection, so the caller can
    fall back to direct polling.
    """

    def __init__(self, url, out_queue, stop_event, stats=None, max_retries=5):
        super().__init__(daemon=True, name="certstream")
        self.url = url
        self.out_queue = out_queue
        self.stop_event = stop_event
        self.stats = stats
        self.max_retries = max_retries
        self.failed = False
        self._retries = 0

    def run(self):
        if websocket is None:
            log.error("websocket-client not installed; cannot use certstream")
            self.failed = True
            return
        while not self.stop_event.is_set() and self._retries < self.max_retries:
            try:
                ws = websocket.create_connection(self.url, timeout=30)
                log.info("connected to certstream %s", self.url)
                self._retries = 0
                ws.settimeout(30)
                while not self.stop_event.is_set():
                    raw = ws.recv()
                    if not raw:
                        break
                    try:
                        msg = json.loads(raw)
                    except json.JSONDecodeError:
                        continue
                    if msg.get("message_type") != "certificate_update":
                        continue
                    rec = _normalize(msg)
                    if self.stats is not None:
                        self.stats.note_seen()
                    if rec:
                        self.out_queue.put(rec)
                ws.close()
            except Exception as e:
                self._retries += 1
                log.warning("certstream error (%d/%d): %s", self._retries,
                            self.max_retries, e)
                self.stop_event.wait(min(2 ** self._retries, 30))
        self.failed = True
        log.warning("certstream gave up; falling back to direct polling")
