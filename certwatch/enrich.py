"""Best-effort enrichment for flagged domains: DNS resolution + IP geolocation.

Runs on a bounded thread pool so a slow lookup can never stall ingest. Every
lookup has a hard timeout, and any failure degrades gracefully — the alert is
already recorded before enrichment starts; this only fills in extra fields.

The most interesting field is *whether the domain resolves at all*: a cert that
exists for a host with no A record is a campaign still being staged.

The geolocation approach mirrors PinPointer's ``geolocate.py`` so the two
projects read as a pair — an mtime-bounded in-memory cache over ip-api.com's
free, keyless tier.
"""

import socket
import threading
import time
from collections import OrderedDict
from concurrent.futures import ThreadPoolExecutor

import requests

_geo_cache = OrderedDict()
_geo_lock = threading.Lock()
_MAX_GEO_CACHE = 4096
_last_geo_call = [0.0]
_geo_rate_lock = threading.Lock()


def resolve(hostname, timeout=3.0):
    """Resolve A/AAAA records. Returns {'resolves': bool, 'ips': [...], 'ip': first}.

    A leading ``*.`` wildcard is stripped and the apex is tried.
    """
    host = hostname.lstrip("*.").strip(".")
    result = {"resolves": False, "ips": [], "ip": None}
    if not host:
        return result
    old = socket.getdefaulttimeout()
    socket.setdefaulttimeout(timeout)
    try:
        infos = socket.getaddrinfo(host, None)
        ips = []
        for info in infos:
            ip = info[4][0]
            if ip not in ips:
                ips.append(ip)
        result["ips"] = ips
        if ips:
            result["resolves"] = True
            # Prefer an IPv4 address for geolocation.
            v4 = [i for i in ips if ":" not in i]
            result["ip"] = v4[0] if v4 else ips[0]
    except (socket.gaierror, socket.timeout, UnicodeError, OSError):
        pass
    finally:
        socket.setdefaulttimeout(old)
    return result


def geolocate(ip, timeout=4.0):
    """Geolocate an IP via ip-api.com (free, keyless). Cached by IP."""
    if not ip:
        return None
    with _geo_lock:
        if ip in _geo_cache:
            _geo_cache.move_to_end(ip)
            return _geo_cache[ip]

    result = None
    try:
        # ip-api free tier allows ~45 req/min; keep a minimum spacing.
        with _geo_rate_lock:
            gap = time.time() - _last_geo_call[0]
            if gap < 0.4:
                time.sleep(0.4 - gap)
            _last_geo_call[0] = time.time()
        r = requests.get(
            f"http://ip-api.com/json/{ip}",
            params={"fields": "status,country,countryCode,city,lat,lon,isp,org,as"},
            timeout=timeout,
        )
        data = r.json()
        if data.get("status") == "success":
            result = {
                "ip": ip,
                "country": data.get("country", "Unknown"),
                "countryCode": data.get("countryCode", "??"),
                "city": data.get("city", ""),
                "lat": data.get("lat", 0.0),
                "lon": data.get("lon", 0.0),
                "isp": data.get("isp", ""),
                "org": data.get("org", ""),
                "asn": data.get("as", ""),
            }
    except Exception:
        result = None

    with _geo_lock:
        if len(_geo_cache) >= _MAX_GEO_CACHE:
            _geo_cache.popitem(last=False)
        _geo_cache[ip] = result
    return result


class Enricher:
    """Async enrichment dispatcher. Submit an alert + callback; the callback is
    invoked (from a worker thread) with the enrichment dict when done."""

    def __init__(self, max_workers=8, enable_geo=True):
        self._pool = ThreadPoolExecutor(max_workers=max_workers,
                                        thread_name_prefix="enrich")
        self.enable_geo = enable_geo

    def submit(self, hostname, callback):
        self._pool.submit(self._run, hostname, callback)

    def submit_precomputed(self, enrichment, callback, delay=0.6):
        """Deliver a pre-computed enrichment (demo mode) after a small delay so
        it still arrives asynchronously, the way a real lookup would."""
        def _run():
            time.sleep(delay)
            e = dict(enrichment)
            e["checked_at"] = time.time()
            try:
                callback(e)
            except Exception:
                pass
        self._pool.submit(_run)

    def _run(self, hostname, callback):
        enrichment = {"resolves": False, "ips": [], "ip": None, "geo": None,
                      "checked_at": time.time()}
        try:
            dns = resolve(hostname)
            enrichment.update(dns)
            if self.enable_geo and dns.get("ip"):
                enrichment["geo"] = geolocate(dns["ip"])
        except Exception:
            pass
        try:
            callback(enrichment)
        except Exception:
            pass

    def shutdown(self):
        self._pool.shutdown(wait=False)
