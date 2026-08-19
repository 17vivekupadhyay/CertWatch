"""Replay a recorded JSONL of alerts at (optionally scaled) original timing.

``--record`` captures every alert with the fields needed to reconstruct the
underlying cert record; this module reads them back and re-feeds cert records
into the same pipeline, so a captured hour of real traffic becomes a
deterministic demo.
"""

import json
import time


def load_records(path):
    """Read a recorded JSONL and reconstruct cert records, sorted by seen_at."""
    records = []
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                continue
            domains = obj.get("all_domains") or ([obj["domain"]] if obj.get("domain") else [])
            if not domains:
                continue
            records.append({
                "seen_at": float(obj.get("seen_at") or time.time()),
                "not_before": obj.get("not_before"),
                "issuer": obj.get("issuer", ""),
                "domains": domains,
                "log": obj.get("log", "replay"),
                "is_precert": obj.get("is_precert", False),
            })
    records.sort(key=lambda r: r["seen_at"])
    return records


def replay(path, out_queue, stop_event, stats=None, speed=1.0, loop=True):
    """Feed reconstructed records onto ``out_queue`` honoring inter-arrival gaps.

    ``speed`` > 1 replays faster. Loops by default so a short capture keeps the
    dashboard alive.
    """
    records = load_records(path)
    if not records:
        return
    while not stop_event.is_set():
        base = records[0]["seen_at"]
        start_wall = time.time()
        for rec in records:
            if stop_event.is_set():
                return
            target = (rec["seen_at"] - base) / max(speed, 0.01)
            elapsed = time.time() - start_wall
            wait = target - elapsed
            if wait > 0:
                stop_event.wait(min(wait, 2.0))
            fresh = dict(rec)
            fresh["seen_at"] = time.time()
            out_queue.put(fresh)
            if stats is not None:
                stats.note_seen()
        if not loop:
            return
