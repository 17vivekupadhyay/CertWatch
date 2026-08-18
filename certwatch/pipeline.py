"""The processing pipeline.

Reads normalized cert records off a queue, scores each one, dedupes flagged
registrable domains, records alerts, kicks off best-effort enrichment, and
stages data for the websocket emitter. One worker thread; enrichment runs on
its own pool so it never blocks ingest.
"""

import json
import threading
import time
from collections import deque


class Pipeline(threading.Thread):
    def __init__(self, in_queue, scorer, watchlist, stats, buffers, enricher,
                 stop_event, min_score=30, record_path=None, dedupe=None,
                 emit_alert=None):
        super().__init__(daemon=True, name="pipeline")
        self.in_queue = in_queue
        self.scorer = scorer
        self.watchlist = watchlist
        self.stats = stats
        self.buffers = buffers
        self.enricher = enricher
        self.stop_event = stop_event
        self.min_score = min_score
        self.dedupe = dedupe
        self.emit_alert = emit_alert or (lambda a: None)

        self._cert_stage = deque(maxlen=500)
        self._cert_lock = threading.Lock()
        self._repeat_seq = {}  # registrable -> alert seq (this run)
        self._record_fp = open(record_path, "a", encoding="utf-8") if record_path else None
        self._last_reload_check = 0.0

    # -- emitter drains this for the sampled cert ticker -------------------
    def drain_cert_samples(self, limit=40):
        out = []
        with self._cert_lock:
            while self._cert_stage and len(out) < limit:
                out.append(self._cert_stage.popleft())
        return out

    def run(self):
        while not self.stop_event.is_set():
            try:
                rec = self.in_queue.get(timeout=0.5)
            except Exception:
                continue
            try:
                self._handle(rec)
            except Exception:
                # Never let one bad record kill the pipeline.
                continue

    def _handle(self, rec):
        # Hot-reload the watchlist at most once a second.
        now = time.time()
        if now - self._last_reload_check > 1.0:
            self._last_reload_check = now
            self.watchlist.maybe_reload()

        result = self.scorer.score_cert(rec)
        domain = result.get("domain") or (rec["domains"][0] if rec["domains"] else "")

        # Stage a compact cert summary for the ticker (sampled downstream).
        with self._cert_lock:
            self._cert_stage.append({
                "domain": rec["domains"][0] if rec["domains"] else "",
                "issuer": rec.get("issuer", ""),
                "log": rec.get("log", ""),
                "is_precert": rec.get("is_precert", False),
                "score": result["score"],
                "severity": result["severity"] if result["score"] >= self.min_score else "",
            })

        if result["score"] < self.min_score:
            return

        reg = result["registrable"]
        # Dedupe renewals: same registrable domain only alerts once per run.
        if self.dedupe is not None:
            is_new, count = self.dedupe.seen(reg)
            if not is_new:
                seq = self._repeat_seq.get(reg)
                if seq is not None:
                    self.buffers.update_alert(seq, {"repeat_count": count})
                return

        alert = {
            "domain": domain,
            "registrable": reg,
            "score": result["score"],
            "severity": result["severity"],
            "signals": result["signals"],
            "matched_brand": result["matched_brand"],
            "issuer": rec.get("issuer", ""),
            "log": rec.get("log", ""),
            "is_precert": rec.get("is_precert", False),
            "not_before": rec.get("not_before"),
            "seen_at": rec.get("seen_at", now),
            "all_domains": rec.get("domains", [])[:200],
            "n_sans": result.get("n_sans", len(rec.get("domains", []))),
            "n_registrable": result.get("n_registrable", 1),
            "repeat_count": 1,
            "enrichment": None,
        }

        seq = self.buffers.add_alert(alert)
        self._repeat_seq[reg] = seq
        self.stats.note_alert(result["severity"], result["matched_brand"])

        if self._record_fp:
            try:
                self._record_fp.write(json.dumps(alert, default=str) + "\n")
                self._record_fp.flush()
            except Exception:
                pass

        # Emit the alert immediately — this is the moment that matters.
        self.emit_alert(alert)

        # Best-effort enrichment; patches the alert in place when it returns.
        target = domain.lstrip("*.")

        def _on_enriched(enrichment, seq=seq, target=target):
            self.buffers.update_alert(seq, {"enrichment": enrichment})
            self.emit_alert({**self._alert_by_seq(seq), "_enriched": True})

        if self.enricher is not None:
            demo_enrich = rec.get("_demo_enrich")
            if demo_enrich is not None:
                self.enricher.submit_precomputed(demo_enrich, _on_enriched)
            else:
                self.enricher.submit(target, _on_enriched)

    def _alert_by_seq(self, seq):
        for a in self.buffers.all_alerts():
            if a.get("seq") == seq:
                return a
        return {"seq": seq}

    def close(self):
        if self._record_fp:
            try:
                self._record_fp.close()
            except Exception:
                pass
