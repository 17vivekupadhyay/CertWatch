"""Direct RFC 6962 Certificate Transparency log polling.

This is the primary real-data path — it talks to CT logs directly and does not
depend on any third-party aggregator.

The tricky part is parsing the ``MerkleTreeLeaf`` that each log entry carries.
Roughly half of all entries are *precerts*, whose leaf holds a bare
``TBSCertificate`` that ``cryptography`` cannot load. For those we parse the
first certificate out of ``extra_data`` instead. Getting this wrong silently
drops half the feed, so :func:`parse_entry` handles both and the test suite
pins a real precert fixture.
"""

import base64
import struct
import threading
import time
import logging

import requests
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.x509.oid import NameOID, ExtensionOID

log = logging.getLogger("certwatch.ctlog")

LOG_LIST_URL = "https://www.gstatic.com/ct/log_list/v3/log_list.json"

# Logs known to be high-volume and RFC-6962 (non-tiled). Used to prefer good
# defaults when auto-selecting; anything not responding to get-sth is skipped.
_PREFERRED_HINTS = ("argon", "xenon", "nimbus", "sabre", "yeti", "nessie",
                    "oak", "sphinx")


# ---------------------------------------------------------------------------
# Leaf / cert parsing
# ---------------------------------------------------------------------------

def _read_u24_prefixed(buf, offset):
    """Read a 3-byte-length-prefixed opaque field. Returns (data, new_offset)."""
    if offset + 3 > len(buf):
        raise ValueError("truncated length prefix")
    length = (buf[offset] << 16) | (buf[offset + 1] << 8) | buf[offset + 2]
    offset += 3
    if offset + length > len(buf):
        raise ValueError("truncated opaque field")
    return buf[offset:offset + length], offset + length


def _load_cert(der):
    return x509.load_der_x509_certificate(der, default_backend())


def extract_domains(cert):
    """Return the deduped lowercase set of names on a cert: CN + all DNS SANs."""
    names = []
    try:
        cn = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
        for attr in cn:
            if attr.value:
                names.append(attr.value)
    except Exception:
        pass
    try:
        ext = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
        for name in ext.value.get_values_for_type(x509.DNSName):
            names.append(name)
    except x509.ExtensionNotFound:
        pass
    except Exception:
        pass
    seen = []
    lowered = set()
    for n in names:
        nl = n.lower().strip()
        if nl and nl not in lowered:
            lowered.add(nl)
            seen.append(nl)
    return seen


def parse_leaf_input(leaf_input):
    """Parse a MerkleTreeLeaf. Returns (timestamp_ms, entry_type, cert_der_or_None).

    For x509 entries the DER certificate is returned directly. For precert
    entries ``cert_der_or_None`` is None (the caller must use ``extra_data``).
    """
    if len(leaf_input) < 12:
        raise ValueError("leaf too short")
    # version(1) leaf_type(1) timestamp(8) entry_type(2)
    _version = leaf_input[0]
    _leaf_type = leaf_input[1]
    timestamp = struct.unpack(">Q", leaf_input[2:10])[0]
    entry_type = struct.unpack(">H", leaf_input[10:12])[0]
    offset = 12

    if entry_type == 0:  # x509_entry: opaque ASN.1Cert <1..2^24-1>
        cert_der, _ = _read_u24_prefixed(leaf_input, offset)
        return timestamp, entry_type, cert_der
    elif entry_type == 1:  # precert_entry: issuer_key_hash[32] + TBSCertificate
        # We can't load a bare TBSCertificate; signal the caller.
        return timestamp, entry_type, None
    else:
        raise ValueError(f"unknown entry_type {entry_type}")


def parse_extra_data_first_cert(extra_data, entry_type):
    """Extract the first full DER certificate from ``extra_data``.

    * precert_entry: extra_data is ``PrecertChainEntry`` — a
      3-byte-length-prefixed leaf certificate followed by the chain. The first
      field is the full (signed) precertificate we want.
    * x509_entry: extra_data is ``CertificateChain`` — a 3-byte-length-prefixed
      list; the leaf cert already came from leaf_input, so this is only used as
      a fallback.
    """
    if entry_type == 1:
        cert_der, _ = _read_u24_prefixed(extra_data, 0)
        return cert_der
    # x509 fallback: outer 3-byte list length, then first cert
    _list, _ = _read_u24_prefixed(extra_data, 0)
    cert_der, _ = _read_u24_prefixed(_list, 0)
    return cert_der


def parse_entry(leaf_input_b64, extra_data_b64, log_name=""):
    """Parse one get-entries item into a normalized record, or None on failure.

    Handles both x509 and precert entries. Never raises — a single malformed
    entry must not stall a log.
    """
    try:
        leaf_input = base64.b64decode(leaf_input_b64)
        timestamp_ms, entry_type, cert_der = parse_leaf_input(leaf_input)
        if cert_der is None:  # precert: pull the full cert from extra_data
            extra = base64.b64decode(extra_data_b64)
            cert_der = parse_extra_data_first_cert(extra, entry_type)
        cert = _load_cert(cert_der)
        domains = extract_domains(cert)
        if not domains:
            return None
        try:
            issuer_cn = cert.issuer.get_attributes_for_oid(NameOID.ORGANIZATION_NAME)
            issuer = issuer_cn[0].value if issuer_cn else ""
        except Exception:
            issuer = ""
        if not issuer:
            try:
                cn = cert.issuer.get_attributes_for_oid(NameOID.COMMON_NAME)
                issuer = cn[0].value if cn else ""
            except Exception:
                issuer = ""
        not_before = cert.not_valid_before_utc.timestamp()
        return {
            "seen_at": time.time(),
            "not_before": not_before,
            "issuer": issuer,
            "domains": domains,
            "log": log_name,
            "is_precert": entry_type == 1,
        }
    except Exception as e:
        log.debug("entry parse failed on %s: %s", log_name, e)
        return None


# ---------------------------------------------------------------------------
# Log list + polling
# ---------------------------------------------------------------------------

def get_log_list(timeout=15):
    r = requests.get(LOG_LIST_URL, timeout=timeout)
    r.raise_for_status()
    return r.json()


def select_logs(log_list, wanted_names=None, limit=3):
    """Return a list of (name, url) for currently-usable RFC-6962 logs.

    Picks logs whose temporal shard covers now and whose state is usable.
    Prefers well-known high-volume operators.
    """
    now = time.time()
    candidates = []
    for operator in log_list.get("operators", []):
        for lg in operator.get("logs", []):
            url = lg.get("url", "").rstrip("/")
            desc = lg.get("description", "")
            name = _slug(desc) or _slug(url)
            state = lg.get("state", {})
            if not state or "usable" not in state:
                # Only follow logs explicitly marked usable.
                if not any(k in state for k in ("usable",)):
                    continue
            # Temporal shard must cover now.
            interval = lg.get("temporal_interval")
            if interval:
                start = _parse_iso(interval.get("start_inclusive"))
                end = _parse_iso(interval.get("end_exclusive"))
                if start and now < start:
                    continue
                if end and now >= end:
                    continue
            pref = any(h in name for h in _PREFERRED_HINTS)
            candidates.append((not pref, name, url))  # not pref -> preferred sort first

    candidates.sort()
    selected = [(name, url) for _, name, url in candidates]

    if wanted_names:
        wanted = {w.strip().lower() for w in wanted_names}
        selected = [(n, u) for (n, u) in selected if n in wanted]
    else:
        selected = selected[:limit]
    return selected


def _slug(text):
    return "".join(c if c.isalnum() else "_" for c in text.lower()).strip("_")


def _parse_iso(s):
    if not s:
        return None
    try:
        from datetime import datetime
        return datetime.fromisoformat(s.replace("Z", "+00:00")).timestamp()
    except Exception:
        return None


class CTLogPoller(threading.Thread):
    """Polls a single CT log and pushes normalized records onto ``out_queue``."""

    def __init__(self, name, url, out_queue, stop_event, session=None,
                 batch=256, poll_interval=2.0, stats=None):
        super().__init__(daemon=True, name=f"ctpoll-{name}")
        self.name_ = name
        self.url = url
        self.out_queue = out_queue
        self.stop_event = stop_event
        self.session = session or requests.Session()
        self.batch = batch
        self.poll_interval = poll_interval
        self.stats = stats
        self.tree_size = None
        self.cursor = None
        self._backoff = poll_interval

    def _get(self, path, **params):
        r = self.session.get(f"{self.url}/ct/v1/{path}", params=params, timeout=20)
        r.raise_for_status()
        return r.json()

    def _get_sth(self):
        return self._get("get-sth")

    def run(self):
        # Establish the head. A log that doesn't answer get-sth is likely tiled
        # (static API) — skip it rather than crash. TODO: tile-based log support.
        try:
            sth = self._get_sth()
            self.tree_size = int(sth["tree_size"])
            self.cursor = self.tree_size  # start from the head, not from zero
            log.info("following %s (tree_size=%d)", self.name_, self.tree_size)
        except Exception as e:
            log.warning("skipping %s (no get-sth / possibly tiled): %s", self.name_, e)
            return

        while not self.stop_event.is_set():
            try:
                sth = self._get_sth()
                new_size = int(sth["tree_size"])
                if new_size <= self.cursor:
                    self._sleep(self.poll_interval)
                    continue
                start = self.cursor
                end = min(start + self.batch, new_size) - 1
                data = self._get("get-entries", start=start, end=end)
                entries = data.get("entries", [])
                if not entries:
                    self._sleep(self.poll_interval)
                    continue
                for entry in entries:
                    rec = parse_entry(entry.get("leaf_input", ""),
                                      entry.get("extra_data", ""),
                                      self.name_)
                    if rec:
                        self.out_queue.put(rec)
                    if self.stats is not None:
                        self.stats.note_seen()
                # Advance by what we actually received, not what we asked for.
                self.cursor = start + len(entries)
                self._backoff = self.poll_interval  # reset on success
            except requests.HTTPError as e:
                code = e.response.status_code if e.response is not None else 0
                if code in (429, 500, 502, 503, 504):
                    self._backoff = min(self._backoff * 2, 60)
                    log.info("%s backing off %.0fs (HTTP %s)", self.name_,
                             self._backoff, code)
                    self._sleep(self._backoff)
                else:
                    log.warning("%s HTTP error %s", self.name_, code)
                    self._sleep(self.poll_interval)
            except Exception as e:
                log.debug("%s poll error: %s", self.name_, e)
                self._sleep(min(self._backoff * 2, 30))

    def _sleep(self, seconds):
        # Interruptible sleep.
        self.stop_event.wait(seconds)


def start_polling(out_queue, stop_event, wanted_names=None, limit=3, stats=None):
    """Fetch the log list, select logs, and start one poller thread per log.

    Returns the list of started threads. Raises if the log list is unreachable.
    """
    log_list = get_log_list()
    selected = select_logs(log_list, wanted_names=wanted_names, limit=limit)
    if not selected:
        raise RuntimeError("no usable CT logs selected")
    session = requests.Session()
    session.headers.update({"User-Agent": "CertWatch/1.0 (+passive CT monitor)"})
    threads = []
    for name, url in selected:
        poller = CTLogPoller(name, url, out_queue, stop_event, session=session,
                             stats=stats)
        poller.start()
        threads.append(poller)
    return threads
