"""Shared in-memory state: exact counters, ring buffers, and dedupe cache.

Everything here is thread-safe. Rate accounting stays exact regardless of how
much the server samples down the websocket stream.
"""

import threading
import time
from collections import deque, Counter, OrderedDict


class TTLCache:
    """Registrable-domain dedupe: remembers domains for ``ttl`` seconds and
    counts repeats so renewals don't spam the feed."""

    def __init__(self, ttl=3600, maxsize=20000):
        self.ttl = ttl
        self.maxsize = maxsize
        self._data = OrderedDict()  # key -> (first_seen, count)
        self._lock = threading.Lock()

    def seen(self, key):
        """Register a sighting. Returns (is_new, repeat_count)."""
        now = time.time()
        with self._lock:
            entry = self._data.get(key)
            if entry and now - entry[0] < self.ttl:
                self._data[key] = (entry[0], entry[1] + 1)
                self._data.move_to_end(key)
                return False, entry[1] + 1
            self._data[key] = (now, 1)
            self._data.move_to_end(key)
            if len(self._data) > self.maxsize:
                self._data.popitem(last=False)
            return True, 1


class Stats:
    """Exact server-side counters and a rolling per-second rate."""

    def __init__(self, window=60):
        self._lock = threading.Lock()
        self.started_at = time.time()
        self.total_seen = 0
        self.total_flagged = 0
        self.total_assets = 0
        self.severity = Counter()
        self.brands = Counter()
        self.asset_severity = Counter()
        self.exposed_tech = Counter()
        self._buckets = deque()  # (second, count) for rate over `window`
        self.window = window

    def note_seen(self, n=1):
        with self._lock:
            self.total_seen += n
            sec = int(time.time())
            if self._buckets and self._buckets[-1][0] == sec:
                self._buckets[-1] = (sec, self._buckets[-1][1] + n)
            else:
                self._buckets.append((sec, n))
            self._trim(sec)

    def note_alert(self, severity, brand):
        with self._lock:
            self.total_flagged += 1
            self.severity[severity] += 1
            if brand:
                self.brands[brand] += 1

    def note_asset(self, severity, tech=None):
        with self._lock:
            self.total_assets += 1
            self.asset_severity[severity] += 1
            for t in (tech or []):
                self.exposed_tech[t] += 1

    def _trim(self, now_sec):
        cutoff = now_sec - self.window
        while self._buckets and self._buckets[0][0] < cutoff:
            self._buckets.popleft()

    def _rate_nolock(self):
        """Compute the rolling rate. Caller must already hold ``self._lock``."""
        now_sec = int(time.time())
        self._trim(now_sec)
        if not self._buckets:
            return 0.0
        total = sum(c for _, c in self._buckets)
        span = max(1, now_sec - self._buckets[0][0] + 1)
        return round(total / span, 1)

    def rate(self):
        with self._lock:
            return self._rate_nolock()

    def snapshot(self):
        # NOTE: threading.Lock is not reentrant, so compute the rate inline
        # rather than calling the public (locking) rate().
        with self._lock:
            return {
                "total_seen": self.total_seen,
                "total_flagged": self.total_flagged,
                "total_assets": self.total_assets,
                "rate": self._rate_nolock(),
                "severity": dict(self.severity),
                "asset_severity": dict(self.asset_severity),
                "top_brands": self.brands.most_common(6),
                "top_tech": self.exposed_tech.most_common(6),
                "uptime": round(time.time() - self.started_at, 1),
            }


class RingBuffers:
    def __init__(self, alert_cap=2000, cert_cap=10000, asset_cap=2000):
        self._lock = threading.Lock()
        self.alerts = deque(maxlen=alert_cap)
        self.certs = deque(maxlen=cert_cap)
        self.assets = deque(maxlen=asset_cap)
        self._alert_seq = 0
        self._asset_seq = 0

    def add_alert(self, alert):
        with self._lock:
            self._alert_seq += 1
            alert["seq"] = self._alert_seq
            self.alerts.append(alert)
            return self._alert_seq

    def update_alert(self, seq, patch):
        """Patch an existing alert in place (e.g. late enrichment)."""
        with self._lock:
            for a in reversed(self.alerts):
                if a.get("seq") == seq:
                    a.update(patch)
                    return True
        return False

    def add_asset(self, asset):
        with self._lock:
            self._asset_seq += 1
            asset["seq"] = self._asset_seq
            self.assets.append(asset)
            return self._asset_seq

    def update_asset(self, seq, patch):
        with self._lock:
            for a in reversed(self.assets):
                if a.get("seq") == seq:
                    a.update(patch)
                    return True
        return False

    def recent_assets(self, since=0, limit=500):
        with self._lock:
            out = [a for a in self.assets if a["seq"] > since]
        return out[-limit:]

    def all_assets(self):
        with self._lock:
            return list(self.assets)

    def add_cert(self, cert):
        with self._lock:
            self.certs.append(cert)

    def recent_alerts(self, since=0, min_score=0, limit=500):
        with self._lock:
            out = [a for a in self.alerts
                   if a["seq"] > since and a["score"] >= min_score]
        return out[-limit:]

    def all_alerts(self):
        with self._lock:
            return list(self.alerts)
