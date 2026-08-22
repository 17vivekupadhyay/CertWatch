"""Flask + Flask-SocketIO server.

Backpressure is the whole game here: we may ingest hundreds of certs per second
and no browser wants that as individual frames. Alerts are emitted immediately;
the raw cert ticker is sampled and batched into one frame every 250ms carrying
at most ~40 items. Server-side counters stay exact regardless.
"""

import json
import logging

from flask import Flask, jsonify, request, Response, render_template

try:
    from flask_socketio import SocketIO
except ImportError:  # pragma: no cover
    SocketIO = None

log = logging.getLogger("certwatch.server")

CERT_EMIT_INTERVAL = 0.25   # seconds between sampled cert batches
CERT_EMIT_MAX = 40          # max cert summaries per batch
STATS_EMIT_INTERVAL = 1.0


def create_app(stats, buffers, pipeline_ref, meta):
    app = Flask(__name__, template_folder="templates", static_folder="static")
    app.config["SECRET_KEY"] = "certwatch-local"

    socketio = SocketIO(app, async_mode="threading", cors_allowed_origins="*",
                        logger=False, engineio_logger=False)

    # -- HTTP routes ------------------------------------------------------
    @app.route("/")
    def index():
        return render_template("index.html", meta=meta)

    @app.route("/api/stats")
    def api_stats():
        snap = stats.snapshot()
        snap["mode"] = meta.get("mode")
        snap["min_score"] = meta.get("min_score")
        return jsonify(snap)

    @app.route("/api/alerts")
    def api_alerts():
        since = int(request.args.get("since", 0))
        min_score = int(request.args.get("min_score", 0))
        return jsonify(buffers.recent_alerts(since=since, min_score=min_score))

    @app.route("/api/alerts.jsonl")
    def api_alerts_jsonl():
        lines = "\n".join(json.dumps(a, default=str) for a in buffers.all_alerts())
        return Response(lines + "\n", mimetype="application/x-ndjson",
                        headers={"Content-Disposition": "attachment; filename=certwatch-alerts.jsonl"})

    @app.route("/api/assets")
    def api_assets():
        since = int(request.args.get("since", 0))
        return jsonify(buffers.recent_assets(since=since))

    @app.route("/api/assets.jsonl")
    def api_assets_jsonl():
        lines = "\n".join(json.dumps(a, default=str) for a in buffers.all_assets())
        return Response(lines + "\n", mimetype="application/x-ndjson",
                        headers={"Content-Disposition": "attachment; filename=certwatch-assets.jsonl"})

    @app.route("/api/assets.txt")
    def api_assets_txt():
        # Plain hostname list — the recon deliverable. Deduped, highest recon
        # value first. Passive output; connecting to these is out of scope here.
        seen, rows = set(), []
        for a in sorted(buffers.all_assets(), key=lambda x: x.get("score", 0), reverse=True):
            d = a.get("domain")
            if d and d not in seen:
                seen.add(d)
                rows.append(d)
        return Response("\n".join(rows) + "\n", mimetype="text/plain",
                        headers={"Content-Disposition": "attachment; filename=certwatch-hosts.txt"})

    @app.route("/api/meta")
    def api_meta():
        return jsonify(meta)

    # -- Socket.IO --------------------------------------------------------
    @socketio.on("connect")
    def on_connect():
        # Send the current snapshot so a fresh client isn't staring at nothing.
        snap = stats.snapshot()
        snap["mode"] = meta.get("mode")
        snap["min_score"] = meta.get("min_score")
        socketio.emit("stats", snap)
        socketio.emit("snapshot", {
            "alerts": buffers.recent_alerts(min_score=0, limit=200),
            "assets": buffers.recent_assets(limit=200) if meta.get("discovery") else [],
            "meta": meta,
        })

    # -- Emitters (background tasks) --------------------------------------
    def cert_emitter():
        while True:
            socketio.sleep(CERT_EMIT_INTERVAL)
            pipeline = pipeline_ref[0]
            if pipeline is None:
                continue
            batch = pipeline.drain_cert_samples(CERT_EMIT_MAX)
            if batch:
                socketio.emit("cert", batch)

    def stats_emitter():
        while True:
            socketio.sleep(STATS_EMIT_INTERVAL)
            snap = stats.snapshot()
            snap["mode"] = meta.get("mode")
            snap["min_score"] = meta.get("min_score")
            socketio.emit("stats", snap)

    def alert_emitter(alert):
        # Called from the pipeline thread; SocketIO.emit is thread-safe.
        socketio.emit("alert", alert)

    def asset_emitter(asset):
        socketio.emit("asset", asset)

    def start_background():
        socketio.start_background_task(cert_emitter)
        socketio.start_background_task(stats_emitter)

    return app, socketio, start_background, alert_emitter, asset_emitter
