#!/usr/bin/env python3
"""CertWatch — watch phishing domains come into existence, in real time.

Entry point. Wires the chosen data source into the scoring pipeline and starts
the dashboard. Demo mode (no flags) works fully offline.
"""

import argparse
import logging
import os
import queue
import sys
import threading
import time
import webbrowser

from certwatch.detect.brands import Watchlist
from certwatch.detect.score import Scorer
from certwatch.detect.discovery import AssetWatch, DiscoveryScorer
from certwatch.state import Stats, RingBuffers, TTLCache
from certwatch.enrich import Enricher
from certwatch.pipeline import Pipeline
from certwatch.server import create_app

HERE = os.path.dirname(os.path.abspath(__file__))


def parse_args(argv=None):
    p = argparse.ArgumentParser(
        prog="certwatch",
        description="Watch Certificate Transparency logs for phishing domains as they are born.",
    )
    p.add_argument("--live", action="store_true",
                   help="Poll real Certificate Transparency logs")
    p.add_argument("--certstream", metavar="URL",
                   help="Use a CertStream-compatible websocket instead of polling")
    p.add_argument("--logs", type=str, default=None,
                   help="Comma-separated CT log names to follow (default: auto-select 3)")
    p.add_argument("--brands", type=str, default=os.path.join(HERE, "brands.json"),
                   help="Path to brands.json")
    p.add_argument("--recon", "--discovery", dest="discovery", action="store_true",
                   help="Enable recon mode: passively map a target's attack surface "
                        "(new subdomains) from CT. Authorized targets only.")
    p.add_argument("--assets", "--targets", dest="assets", type=str,
                   default=os.path.join(HERE, "assets.json"),
                   help="Path to targets file (assets.json) for --recon")
    p.add_argument("--min-score", type=int, default=30,
                   help="Minimum score to record as an alert (default: 30)")
    p.add_argument("--record", metavar="PATH", help="Append all alerts to a JSONL file")
    p.add_argument("--replay", metavar="PATH", help="Replay a recorded JSONL at original timing")
    p.add_argument("--replay-speed", type=float, default=1.0,
                   help="Replay speed multiplier (default: 1.0)")
    p.add_argument("--seed", type=int, default=None, help="Seed the demo generator")
    p.add_argument("--rate", type=float, default=25.0, help="Demo certs/sec (default: 25)")
    p.add_argument("--no-geo", action="store_true", help="Disable IP geolocation lookups")
    p.add_argument("--host", type=str, default="127.0.0.1", help="Bind host")
    p.add_argument("--port", type=int, default=8765, help="Port")
    p.add_argument("--no-browser", action="store_true", help="Don't auto-open the dashboard")
    p.add_argument("-v", "--verbose", action="store_true", help="Verbose logging")
    return p.parse_args(argv)


def _demo_feeder(gen, q, stats, stop_event):
    for rec in gen.stream(sleep=True):
        if stop_event.is_set():
            break
        q.put(rec)
        stats.note_seen()


def _start_source(args, q, stats, stop_event, owned_domains=None):
    """Start the chosen data source. Returns (mode_label, list_of_threads)."""
    threads = []

    if args.replay:
        from certwatch.sources.replay import replay
        t = threading.Thread(
            target=replay, args=(args.replay, q, stop_event),
            kwargs={"stats": stats, "speed": args.replay_speed}, daemon=True)
        t.start()
        threads.append(t)
        return f"replay:{os.path.basename(args.replay)}", threads

    if args.certstream:
        from certwatch.sources.certstream import CertStreamClient
        client = CertStreamClient(args.certstream, q, stop_event, stats=stats)
        client.start()
        threads.append(client)

        # Never let certstream be the only path: fall back to polling if it dies.
        def _watchdog():
            while not stop_event.is_set():
                if getattr(client, "failed", False):
                    logging.getLogger("certwatch").warning(
                        "certstream failed — falling back to direct CT polling")
                    try:
                        from certwatch.sources.ctlog import start_polling
                        start_polling(q, stop_event,
                                      wanted_names=_log_names(args), stats=stats)
                    except Exception as e:
                        logging.getLogger("certwatch").error("fallback failed: %s", e)
                    return
                stop_event.wait(2.0)
        wt = threading.Thread(target=_watchdog, daemon=True)
        wt.start()
        threads.append(wt)
        return "certstream", threads

    if args.live:
        from certwatch.sources.ctlog import start_polling
        pollers = start_polling(q, stop_event, wanted_names=_log_names(args), stats=stats)
        threads.extend(pollers)
        return "live", threads

    # Default: demo mode.
    from certwatch.sources.demo import DemoGenerator
    gen = DemoGenerator(seed=args.seed, rate=args.rate, owned_domains=owned_domains)
    t = threading.Thread(target=_demo_feeder, args=(gen, q, stats, stop_event), daemon=True)
    t.start()
    threads.append(t)
    return "demo", threads


def _log_names(args):
    if args.logs:
        return [n.strip() for n in args.logs.split(",") if n.strip()]
    return None


def main(argv=None):
    args = parse_args(argv)
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
        datefmt="%H:%M:%S",
    )
    logging.getLogger("werkzeug").setLevel(logging.WARNING)

    if not os.path.exists(args.brands):
        print(f"brands file not found: {args.brands}", file=sys.stderr)
        return 2

    watchlist = Watchlist(args.brands)
    scorer = Scorer(watchlist)
    stats = Stats()
    buffers = RingBuffers()
    dedupe = TTLCache(ttl=3600)
    enricher = Enricher(enable_geo=not args.no_geo)
    q = queue.Queue(maxsize=50000)
    stop_event = threading.Event()

    # Optional discovery mode.
    asset_watch = None
    discovery_scorer = None
    asset_dedupe = None
    owned_domains = []
    if args.discovery:
        if not os.path.exists(args.assets):
            print(f"assets file not found: {args.assets}", file=sys.stderr)
            return 2
        asset_watch = AssetWatch(args.assets)
        discovery_scorer = DiscoveryScorer(asset_watch)
        asset_dedupe = TTLCache(ttl=3600)
        owned_domains = sorted(asset_watch.all_domains())

    meta = {
        "mode": None,
        "min_score": args.min_score,
        "brands": sorted(b.name for b in watchlist.all_brands()),
        "discovery": bool(args.discovery),
        "owned_domains": owned_domains,
        "started_at": time.time(),
    }

    pipeline_ref = [None]
    app, socketio, start_background, alert_emitter, asset_emitter = create_app(
        stats, buffers, pipeline_ref, meta)

    pipeline = Pipeline(
        q, scorer, watchlist, stats, buffers, enricher, stop_event,
        min_score=args.min_score, record_path=args.record, dedupe=dedupe,
        emit_alert=alert_emitter, discovery_scorer=discovery_scorer,
        asset_watch=asset_watch, asset_dedupe=asset_dedupe, emit_asset=asset_emitter,
    )
    pipeline.start()
    pipeline_ref[0] = pipeline

    mode, _threads = _start_source(args, q, stats, stop_event, owned_domains=owned_domains)
    meta["mode"] = mode

    start_background()

    url = f"http://{args.host}:{args.port}/"
    banner(mode, url, args)

    if not args.no_browser:
        def _open():
            time.sleep(1.2)
            try:
                webbrowser.open(url)
            except Exception:
                pass
        threading.Thread(target=_open, daemon=True).start()

    try:
        socketio.run(app, host=args.host, port=args.port,
                     allow_unsafe_werkzeug=True)
    except KeyboardInterrupt:
        pass
    finally:
        stop_event.set()
        pipeline.close()
        enricher.shutdown()
    return 0


def banner(mode, url, args):
    line = "─" * 58
    print(f"\n┌{line}┐")
    print(f"│  CertWatch — CT phishing radar" + " " * 27 + "│")
    print(f"│  mode: {mode:<49}│")
    print(f"│  dashboard: {url:<44}│")
    if mode == "demo":
        print(f"│  (offline synthetic stream — use --live for real logs)   │")
    print(f"└{line}┘\n")


if __name__ == "__main__":
    sys.exit(main())
