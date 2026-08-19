/* CertWatch dashboard client.
 *
 * Alerts arrive one at a time and print immediately (the loud moment). The raw
 * cert stream arrives pre-sampled in ~4/sec batches and scrolls the thermal
 * tape. Everything is filterable client-side; the server only withholds
 * sub-threshold alerts.
 */
(function () {
  "use strict";

  var META = window.CERTWATCH_META || {};
  var REDUCED = window.matchMedia("(prefers-reduced-motion: reduce)").matches;

  var socket = io({ transports: ["websocket", "polling"] });

  // --- client state ---
  var alerts = new Map();      // seq -> alert
  var order = [];              // seqs, newest first
  var paused = false;
  var alertBacklog = [];       // buffered while paused
  var tickerBacklog = [];
  var minScore = 30;
  var sevFloor = 0;
  var brandQuery = "";
  var markers = new Map();     // seq -> leaflet marker
  var MAX_ALERTS = 600;

  // --- elements ---
  var feed = document.getElementById("alertFeed");
  var emptyState = document.getElementById("emptyState");
  var ticker = document.getElementById("ticker");
  var stagedTray = document.getElementById("stagedTray");
  var stagedCount = document.getElementById("stagedCount");

  // ---------------------------------------------------------------------
  // Map (offline vector world — no raster tiles)
  // ---------------------------------------------------------------------
  var map, markerLayer;
  function initMap() {
    map = L.map("map", {
      attributionControl: false, zoomControl: false,
      worldCopyJump: true, minZoom: 1, maxZoom: 6,
    }).setView([25, 5], 1);
    markerLayer = L.layerGroup().addTo(map);
    fetch(STATIC + "vendor/world-110m.geojson")
      .then(function (r) { return r.json(); })
      .then(function (geo) {
        L.geoJSON(geo, {
          style: { color: "#2b3745", weight: 0.7, fillColor: "#141a22",
                   fillOpacity: 1, opacity: 1 },
          interactive: false,
        }).addTo(map);
      })
      .catch(function () {});
  }
  var STATIC = "/static/";

  function plot(alert) {
    var e = alert.enrichment;
    if (!e || !e.geo || !e.geo.lat) return;
    if (markers.has(alert.seq)) return;
    var color = SEV_COLOR[alert.severity] || "#e0464b";
    var m = L.circleMarker([e.geo.lat, e.geo.lon], {
      radius: 5, color: color, weight: 1.5, fillColor: color, fillOpacity: 0.55,
    });
    m.bindTooltip(alert.domain + " · " + (e.geo.country || ""), { direction: "top" });
    m.on("click", function () { openDrawer(alert.seq); });
    m.addTo(markerLayer);
    markers.set(alert.seq, m);
  }

  var SEV_COLOR = { critical: "#e0464b", high: "#e0902f", medium: "#6f7c8f", low: "#4d5768" };

  // ---------------------------------------------------------------------
  // Rendering helpers
  // ---------------------------------------------------------------------
  function esc(s) {
    return String(s == null ? "" : s).replace(/[&<>"]/g, function (c) {
      return { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c];
    });
  }

  function ageString(alert) {
    var e = alert.enrichment;
    if (e && e.resolves === false) {
      return '<span class="live">staged — cert exists, host doesn\'t resolve</span>';
    }
    var nb = alert.not_before;
    if (!nb) return "";
    var secs = Math.max(0, Math.floor(Date.now() / 1000 - nb));
    var s = secs < 90 ? secs + "s" :
            secs < 5400 ? Math.floor(secs / 60) + "m" :
            Math.floor(secs / 3600) + "h";
    var live = e && e.resolves ? ' · <span class="live">live now</span>' : "";
    return "issued " + s + " ago" + live;
  }

  function padSeq(n) {
    var s = String(n || 0);
    while (s.length < 7) s = "0" + s;
    return s;
  }

  // Mark the suspicious parts of a domain: matched-brand tokens, lure words,
  // and punycode labels.
  var LURES = ["login","signin","secure","verify","account","update","confirm",
    "billing","invoice","support","recover","unlock","wallet","seed","airdrop",
    "auth","sso","password","reset"];
  function highlightDomain(alert) {
    var d = alert.domain || "";
    var marks = [];
    if (alert.matched_brand) marks.push(alert.matched_brand);
    // pull brand tokens named in the signal detail strings
    (alert.signals || []).forEach(function (s) {
      var m = /brand '([^']+)'/.exec(s.detail || "");
      if (m) marks.push(m[1]);
    });
    LURES.forEach(function (l) { if (d.indexOf(l) >= 0) marks.push(l); });
    d.split(".").forEach(function (lab) { if (lab.indexOf("xn--") === 0) marks.push(lab); });

    // Wrap matches with sentinels, then HTML-escape, then swap sentinels for
    // real markup so we never escape our own tags.
    var uniq = Array.from(new Set(marks)).filter(Boolean)
                    .sort(function (a, b) { return b.length - a.length; });
    var work = d, OPEN = "\u0001", CLOSE = "\u0002";
    uniq.forEach(function (tok) {
      var re = new RegExp(tok.replace(/[.*+?^${}()|[\]\\]/g, "\\$&"), "gi");
      work = work.replace(re, function (m2) { return OPEN + m2 + CLOSE; });
    });
    return esc(work)
      .split(OPEN).join('<span class="hit">')
      .split(CLOSE).join("</span>");
  }

  function slipHTML(alert) {
    var items = (alert.signals || []).map(function (s) {
      return '<div class="li"><span class="nm">' + esc(s.name) + "</span>" +
             '<span class="lead"></span><span class="pt">+' + s.points + "</span></div>";
    }).join("");
    var repeat = alert.repeat_count > 1 ? "  seen ×" + alert.repeat_count : "";
    return '' +
      '<span class="stamp">' + esc(alert.severity) + " " + alert.score + "</span>" +
      '<div class="slip-hd"><span>entry ' + padSeq(alert.seq) + repeat + "</span>" +
        "<span>" + esc(alert.log || "") + (alert.is_precert ? " · precert" : "") + "</span></div>" +
      '<div class="domain">' + highlightDomain(alert) + "</div>" +
      '<div class="subline">brand <b>' + esc(alert.matched_brand || "none") + "</b>  ·  " +
        esc(alert.issuer || "unknown issuer") + "  ·  " + ageString(alert) + "</div>" +
      '<div class="items">' + items + "</div>" +
      '<div class="total"><span>impersonation score</span><span>' + alert.score + " / 100</span></div>" +
      '<div class="foot">heuristic signal — a legitimate site can look like this. not an accusation.</div>';
  }

  function passesFilter(alert) {
    if (alert.score < minScore) return false;
    if (alert.score < sevFloor) return false;
    if (brandQuery) {
      var hay = (alert.domain + " " + (alert.matched_brand || "")).toLowerCase();
      if (hay.indexOf(brandQuery) < 0) return false;
    }
    return true;
  }

  function renderNewAlert(alert, animate) {
    if (!passesFilter(alert)) return;
    if (emptyState) { emptyState.remove(); emptyState = null; }
    var el = document.createElement("article");
    el.className = "slip" + (animate && !REDUCED ? " new" : "");
    el.setAttribute("data-sev", alert.severity);
    el.setAttribute("data-seq", alert.seq);
    el.setAttribute("tabindex", "0");
    el.setAttribute("role", "button");
    el.innerHTML = slipHTML(alert);
    el.addEventListener("click", function () { openDrawer(alert.seq); });
    el.addEventListener("keydown", function (e) {
      if (e.key === "Enter" || e.key === " ") { e.preventDefault(); openDrawer(alert.seq); }
    });
    feed.insertBefore(el, feed.firstChild);
    // cap DOM
    while (feed.children.length > 120) feed.removeChild(feed.lastChild);
  }

  function updateAlertEl(alert) {
    var el = feed.querySelector('.slip[data-seq="' + alert.seq + '"]');
    if (el) {
      el.innerHTML = slipHTML(alert);
      el.addEventListener("click", function () { openDrawer(alert.seq); });
    }
    updateStaged();
  }

  // ---------------------------------------------------------------------
  // Staged tray
  // ---------------------------------------------------------------------
  function updateStaged() {
    var staged = [];
    order.forEach(function (seq) {
      var a = alerts.get(seq);
      if (a && a.enrichment && a.enrichment.resolves === false && passesFilter(a)) staged.push(a);
    });
    stagedCount.textContent = staged.length;
    if (!staged.length) {
      stagedTray.innerHTML = '<div class="staged-empty">nothing staged right now — domains whose certificate exists but which don\'t resolve yet land here</div>';
      return;
    }
    stagedTray.innerHTML = staged.slice(0, 40).map(function (a) {
      return '<div class="staged-item" data-seq="' + a.seq + '">' +
        '<span class="sd">' + esc(a.domain) + "</span>" +
        '<span class="stag">no A record</span></div>';
    }).join("");
    Array.prototype.forEach.call(stagedTray.querySelectorAll(".staged-item"), function (it) {
      it.addEventListener("click", function () { openDrawer(+it.getAttribute("data-seq")); });
    });
  }

  // ---------------------------------------------------------------------
  // Ticker
  // ---------------------------------------------------------------------
  function renderTicks(batch) {
    if (REDUCED) {
      // no scroll: just show the latest handful, replace in place
      ticker.innerHTML = batch.slice(-12).map(tickHTML).join("");
      return;
    }
    var frag = document.createDocumentFragment();
    batch.forEach(function (c) {
      var div = document.createElement("div");
      div.className = "tick" + (c.severity ? " hit" : "");
      div.innerHTML = tickInner(c);
      frag.appendChild(div);
    });
    ticker.insertBefore(frag, ticker.firstChild);
    while (ticker.children.length > 60) ticker.removeChild(ticker.lastChild);
  }
  function tickInner(c) {
    var t = new Date().toLocaleTimeString("en-GB");
    return '<span class="tk-t">' + t + "</span>" +
           '<span class="tk-lg">' + esc((c.log || "").slice(0, 12)) + "</span>" +
           '<span class="tk-d">' + esc(c.domain) + "</span>";
  }
  function tickHTML(c) { return '<div class="tick' + (c.severity ? " hit" : "") + '">' + tickInner(c) + "</div>"; }

  // ---------------------------------------------------------------------
  // Detail drawer
  // ---------------------------------------------------------------------
  var drawer = document.getElementById("detailDrawer");
  var drawerBody = document.getElementById("drawerBody");
  var scrim = document.getElementById("drawerScrim");

  function openDrawer(seq) {
    var a = alerts.get(seq);
    if (!a) return;
    drawerBody.innerHTML = drawerHTML(a);
    drawer.classList.add("open");
    drawer.setAttribute("aria-hidden", "false");
    scrim.hidden = false;
    var cb = drawerBody.querySelector(".copy-btn");
    if (cb) cb.addEventListener("click", function () {
      navigator.clipboard && navigator.clipboard.writeText(JSON.stringify(a, null, 2));
      cb.textContent = "copied";
    });
    document.getElementById("drawerClose").focus();
  }
  function closeDrawer() {
    drawer.classList.remove("open");
    drawer.setAttribute("aria-hidden", "true");
    scrim.hidden = true;
  }
  document.getElementById("drawerClose").addEventListener("click", closeDrawer);
  scrim.addEventListener("click", closeDrawer);
  document.addEventListener("keydown", function (e) { if (e.key === "Escape") closeDrawer(); });

  function drawerHTML(a) {
    var e = a.enrichment || {};
    var geo = e.geo || {};
    var signals = (a.signals || []).map(function (s) {
      return '<div class="signal"><div><div class="s-name">' + esc(s.name) +
        '</div><div class="s-detail">' + esc(s.detail) + "</div></div>" +
        '<div class="s-pts">+' + s.points + "</div></div>";
    }).join("");
    var sans = (a.all_domains || []).map(function (d) { return "<div>" + esc(d) + "</div>"; }).join("");
    var dnsLine = e.resolves === false ? "does not resolve (staged)"
      : e.resolves ? (e.ips || []).join(", ") : "checking…";
    var geoLine = geo.country ? esc(geo.city ? geo.city + ", " : "") + esc(geo.country) +
      " · " + esc(geo.isp || "") : "—";
    return '' +
      '<div class="dk">flagged domain</div>' +
      '<div class="d-domain">' + esc(a.domain) + "</div>" +
      '<div class="d-score-row"><span class="d-score" style="color:' + (SEV_COLOR[a.severity]) + '">' +
        a.score + '</span><span class="d-sev ' + a.severity + '">' + esc(a.severity) + "</span></div>" +
      '<div class="d-note">A high score is a heuristic signal, not proof of malice. False positives happen — a real company can register a scary-looking domain. Verify before acting; CertWatch never contacts or probes the site.</div>' +
      '<div class="dk">why it fired</div>' + signals +
      '<div class="dk">enrichment</div><div class="kv">' +
        '<div class="k">resolves</div><div class="v">' + esc(dnsLine) + "</div>" +
        '<div class="k">hosting</div><div class="v">' + geoLine + "</div>" +
        '<div class="k">ASN</div><div class="v">' + esc(geo.asn || "—") + "</div>" +
        '<div class="k">issued</div><div class="v">' + esc(ageString(a).replace(/<[^>]+>/g, "")) + "</div>" +
      "</div>" +
      '<div class="dk">certificate</div><div class="kv">' +
        '<div class="k">issuer</div><div class="v">' + esc(a.issuer || "—") + "</div>" +
        '<div class="k">source log</div><div class="v">' + esc(a.log || "—") + "</div>" +
        '<div class="k">type</div><div class="v">' + (a.is_precert ? "precertificate" : "final cert") + "</div>" +
        '<div class="k">SAN count</div><div class="v">' + (a.n_sans || (a.all_domains||[]).length) + "</div>" +
      "</div>" +
      '<div class="dk">subject alternative names</div><div class="san-list">' + (sans || "<div>—</div>") + "</div>" +
      '<div class="dk">raw record</div><div class="raw">' + esc(JSON.stringify(a, null, 2)) + "</div>" +
      '<button class="ctrl copy-btn">copy json</button>';
  }

  // ---------------------------------------------------------------------
  // Ingest alert (upsert by seq)
  // ---------------------------------------------------------------------
  function ingestAlert(alert, isNew) {
    var existed = alerts.has(alert.seq);
    alerts.set(alert.seq, alert);
    if (!existed) {
      order.unshift(alert.seq);
      if (order.length > MAX_ALERTS) {
        var drop = order.pop();
        alerts.delete(drop);
        if (markers.has(drop)) { markerLayer.removeLayer(markers.get(drop)); markers.delete(drop); }
      }
      renderNewAlert(alert, isNew);
    } else {
      updateAlertEl(alert);
    }
    plot(alert);
    updateStaged();
  }

  // ---------------------------------------------------------------------
  // Socket wiring
  // ---------------------------------------------------------------------
  socket.on("connect", function () {});
  socket.on("snapshot", function (data) {
    (data.alerts || []).forEach(function (a) { ingestAlert(a, false); });
  });
  socket.on("stats", function (s) { renderStats(s); });
  socket.on("cert", function (batch) {
    if (paused) { tickerBacklog = tickerBacklog.concat(batch).slice(-200); return; }
    renderTicks(batch);
  });
  socket.on("alert", function (alert) {
    var isEnrichUpdate = alert._enriched;
    if (paused && !isEnrichUpdate) { alertBacklog.push(alert); return; }
    ingestAlert(alert, !isEnrichUpdate);
  });

  // ---------------------------------------------------------------------
  // Stats
  // ---------------------------------------------------------------------
  function renderStats(s) {
    setText("statRate", s.rate);
    setText("statSeen", fmt(s.total_seen));
    setText("statFlagged", fmt(s.total_flagged));
    setText("statCrit", (s.severity && s.severity.critical) || 0);
    var brand = (s.top_brands && s.top_brands[0]) ? s.top_brands[0][0] : "—";
    setText("statBrand", brand);
    var badge = document.getElementById("modeBadge");
    if (s.mode) {
      var isLive = s.mode.indexOf("live") === 0 || s.mode.indexOf("certstream") === 0;
      badge.textContent = isLive ? "live" : s.mode.indexOf("demo") === 0 ? "demo"
        : s.mode.split(":")[0];
      badge.title = isLive ? "polling real Certificate Transparency logs"
        : s.mode.indexOf("demo") === 0 ? "synthetic offline stream" : s.mode;
      badge.classList.toggle("live", isLive);
    }
    if (s.uptime != null) setText("uptime", "uptime " + fmtDur(s.uptime));
  }
  function fmt(n) { return (n || 0).toLocaleString("en-US"); }
  function fmtDur(sec) {
    sec = Math.floor(sec);
    if (sec < 60) return sec + "s";
    if (sec < 3600) return Math.floor(sec / 60) + "m " + (sec % 60) + "s";
    return Math.floor(sec / 3600) + "h " + Math.floor((sec % 3600) / 60) + "m";
  }
  function setText(id, v) { var el = document.getElementById(id); if (el) el.textContent = v; }

  // ---------------------------------------------------------------------
  // Controls
  // ---------------------------------------------------------------------
  var pauseBtn = document.getElementById("pauseBtn");
  pauseBtn.addEventListener("click", function () {
    paused = !paused;
    pauseBtn.setAttribute("aria-pressed", paused ? "true" : "false");
    pauseBtn.textContent = paused ? "resume" : "pause";
    if (!paused) {
      alertBacklog.forEach(function (a) { ingestAlert(a, true); });
      alertBacklog = [];
      if (tickerBacklog.length) { renderTicks(tickerBacklog); tickerBacklog = []; }
    }
  });

  var minScoreEl = document.getElementById("minScore");
  minScoreEl.addEventListener("input", function () {
    minScore = +minScoreEl.value;
    document.getElementById("minScoreVal").textContent = minScore;
    rerenderFeed();
  });
  document.getElementById("sevFilter").addEventListener("change", function (e) {
    sevFloor = +e.target.value; rerenderFeed();
  });
  document.getElementById("brandFilter").addEventListener("input", function (e) {
    brandQuery = e.target.value.trim().toLowerCase(); rerenderFeed();
  });

  function rerenderFeed() {
    feed.innerHTML = "";
    var any = false;
    order.forEach(function (seq) {
      var a = alerts.get(seq);
      if (a && passesFilter(a)) { renderNewAlert(a, false); any = true; }
    });
    if (!any) {
      feed.innerHTML = '<div class="empty"><p class="muted">No alerts match the current filters.</p></div>';
    }
    updateStaged();
  }

  // ---------------------------------------------------------------------
  initMap();
  updateStaged();
})();
