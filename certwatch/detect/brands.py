"""Brand watchlist: loading, allowlists, and hot-reload.

A ``Watchlist`` holds the set of brands to defend, each with:
  * ``tokens``     — strings we treat as the brand's name for matching
  * ``legitimate`` — registrable domains (and ``*.`` patterns) that are the real
                     brand and must never fire
  * ``weight``     — multiplies brand-dependent signal points

The file is watched by mtime; :meth:`Watchlist.maybe_reload` re-reads it when it
changes on disk so an analyst can edit ``brands.json`` while CertWatch runs.
"""

import json
import os
import threading
import fnmatch

import tldextract

# Use a bundled/offline-friendly extractor. tldextract caches the PSL; we allow
# it to fall back to its bundled snapshot so the tool works with no network.
_EXTRACT = tldextract.TLDExtract(suffix_list_urls=())


def registrable(domain: str) -> str:
    """Return the registrable domain (eTLD+1), e.g. ``a.b.paypal.co.uk`` ->
    ``paypal.co.uk``. Empty string if there is no valid suffix."""
    ext = _EXTRACT(domain)
    if ext.domain and ext.suffix:
        return f"{ext.domain}.{ext.suffix}".lower()
    return ""


def split_domain(domain: str):
    """Return (subdomain, main_label, suffix) for a domain."""
    ext = _EXTRACT(domain)
    return ext.subdomain.lower(), ext.domain.lower(), ext.suffix.lower()


class Brand:
    __slots__ = ("name", "tokens", "legitimate", "legit_registrable",
                 "legit_patterns", "weight", "match_labels")

    def __init__(self, name, tokens, legitimate, weight):
        self.name = name
        self.tokens = [t.lower() for t in tokens]
        self.legitimate = [d.lower() for d in legitimate]
        self.weight = float(weight)
        # Precompute registrable forms of the legit domains for O(1) lookup, and
        # keep wildcard patterns separate for fnmatch.
        self.legit_registrable = set()
        self.legit_patterns = []
        # Labels used as lookalike/homoglyph comparison targets: the brand
        # tokens plus the main label of each legitimate domain (so a squat of
        # the real login domain, e.g. `microsoft0nline`, is caught too).
        self.match_labels = set(t for t in self.tokens if len(t) >= 4)
        for d in self.legitimate:
            if "*" in d:
                self.legit_patterns.append(d)
            else:
                self.legit_registrable.add(d)
                r = registrable(d)
                if r:
                    self.legit_registrable.add(r)
                _, main, _ = split_domain(d)
                if main and len(main) >= 5:
                    self.match_labels.add(main)


class Watchlist:
    def __init__(self, path):
        self.path = path
        self._lock = threading.Lock()
        self._mtime = 0.0
        self.brands = {}
        # token -> brand name, for fast substring/equality scanning
        self.token_index = {}
        self.load()

    def load(self):
        with open(self.path, "r", encoding="utf-8") as f:
            data = json.load(f)
        brands = {}
        token_index = {}
        for name, cfg in data.items():
            brand = Brand(
                name=name,
                tokens=cfg.get("tokens", [name]),
                legitimate=cfg.get("legitimate", []),
                weight=cfg.get("weight", 1.0),
            )
            brands[name] = brand
            for tok in brand.tokens:
                token_index[tok] = name
        with self._lock:
            self.brands = brands
            self.token_index = token_index
            try:
                self._mtime = os.path.getmtime(self.path)
            except OSError:
                self._mtime = 0.0

    def maybe_reload(self):
        """Reload if the file changed on disk. Returns True if reloaded."""
        try:
            mtime = os.path.getmtime(self.path)
        except OSError:
            return False
        if mtime > self._mtime:
            try:
                self.load()
                return True
            except (json.JSONDecodeError, OSError):
                # Bad edit mid-save: keep the old watchlist, try again next tick.
                return False
        return False

    def is_legit(self, reg_domain: str) -> bool:
        """True if the registrable domain belongs to any watched brand."""
        reg_domain = reg_domain.lower()
        with self._lock:
            brands = list(self.brands.values())
        for brand in brands:
            if reg_domain in brand.legit_registrable:
                return True
            for pat in brand.legit_patterns:
                # match against registrable and any label depth
                if fnmatch.fnmatch(reg_domain, pat) or fnmatch.fnmatch(reg_domain, pat.lstrip("*.")):
                    return True
        return False

    def all_brands(self):
        with self._lock:
            return list(self.brands.values())
