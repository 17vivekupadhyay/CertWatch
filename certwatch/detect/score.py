"""The CertWatch scoring engine.

Given a normalized certificate record, produce a phishing/impersonation score
(0-100), a severity band, and the list of signals that fired with their points.

Design rules that keep this from flagging the whole internet:
  * A registrable domain that *is* brand-owned short-circuits to score 0.
  * "Issued by a free CA" is never a signal on its own (signal 10 requires two
    other signals to already have fired).
  * Brand-lookalike distance checks are length-guarded so short brand tokens
    (``ups``, ``aws``) can't collide with unrelated words.
  * Punycode is decoded and folded through the confusables skeleton *before*
    comparison, so Unicode homoglyph attacks fold onto the brand they mimic.
"""

import idna

from . import confusables
from .brands import registrable, split_domain
from .entropy import dga_score, is_common_word

# ---------------------------------------------------------------------------
# Configuration defaults
# ---------------------------------------------------------------------------

LURE_KEYWORDS = {
    "login", "signin", "secure", "verify", "account", "update", "confirm",
    "billing", "invoice", "support", "recover", "unlock", "wallet", "seed",
    "airdrop", "mfa", "sso", "auth", "id", "password", "reset", "validation",
}

ABUSE_TLDS = {
    "zip", "mov", "top", "tk", "cf", "gq", "ml", "click", "rest", "cam",
    "quest", "sbs", "xyz", "work", "support", "country", "kim", "loan",
}

# Free / DV-only issuers. Used ONLY for the combination bonus (signal 10),
# never as a standalone signal.
FREE_ISSUERS = (
    "let's encrypt", "lets encrypt", "zerossl", "google trust services",
    "buypass", "actalis", "ssl.com free", "cloudflare",
)

SEVERITY_BANDS = (
    (70, "critical"),
    (50, "high"),
    (30, "medium"),
    (0, "low"),
)


def severity_for(score: int) -> str:
    for threshold, name in SEVERITY_BANDS:
        if score >= threshold:
            return name
    return "low"


# ---------------------------------------------------------------------------
# String helpers
# ---------------------------------------------------------------------------

def damerau_levenshtein(a: str, b: str) -> int:
    """Optimal string alignment distance (Damerau-Levenshtein with adjacent
    transpositions)."""
    la, lb = len(a), len(b)
    if la == 0:
        return lb
    if lb == 0:
        return la
    prev2 = None
    prev = list(range(lb + 1))
    for i in range(1, la + 1):
        cur = [i] + [0] * lb
        for j in range(1, lb + 1):
            cost = 0 if a[i - 1] == b[j - 1] else 1
            cur[j] = min(
                prev[j] + 1,        # deletion
                cur[j - 1] + 1,     # insertion
                prev[j - 1] + cost,  # substitution
            )
            if (i > 1 and j > 1 and a[i - 1] == b[j - 2]
                    and a[i - 2] == b[j - 1]):
                cur[j] = min(cur[j], prev2[j - 2] + 1)
        prev2, prev = prev, cur
    return prev[lb]


def decode_puny(label: str) -> str:
    """Decode a single ``xn--`` label to Unicode; return unchanged on failure."""
    try:
        if label.startswith("xn--"):
            return idna.decode(label)
    except Exception:
        try:
            return label.encode("ascii").decode("idna")
        except Exception:
            return label
    return label


def _components(domain: str):
    """Split a domain into hyphen/dot-delimited components (lowercased)."""
    parts = []
    for chunk in domain.lower().replace(".", "-").split("-"):
        if chunk:
            parts.append(chunk)
    return parts


# ---------------------------------------------------------------------------
# Signal definitions
# ---------------------------------------------------------------------------

class Signal:
    __slots__ = ("id", "name", "detail", "points")

    def __init__(self, sid, name, detail, points):
        self.id = sid
        self.name = name
        self.detail = detail
        self.points = points

    def as_dict(self):
        return {"id": self.id, "name": self.name,
                "detail": self.detail, "points": self.points}


class Scorer:
    def __init__(self, watchlist, lure_keywords=None, abuse_tlds=None):
        self.watchlist = watchlist
        self.lure = set(lure_keywords) if lure_keywords else set(LURE_KEYWORDS)
        self.abuse_tlds = set(abuse_tlds) if abuse_tlds else set(ABUSE_TLDS)

    # -- per single domain ------------------------------------------------
    def _score_one(self, domain: str) -> dict:
        domain = domain.lower().lstrip(".")
        if domain.startswith("*."):
            domain = domain[2:]

        reg = registrable(domain)
        if not reg:
            return {"registrable": domain, "domain": domain, "score": 0,
                    "signals": [], "matched_brand": None}

        # Suppression: registrable domain is brand-owned -> stop scoring.
        if self.watchlist.is_legit(reg):
            return {"registrable": reg, "domain": domain, "score": 0,
                    "signals": [], "matched_brand": None, "legit": True}

        sub, main, suffix = split_domain(domain)
        # Decode any punycode labels, keep both forms.
        raw_labels = domain.split(".")
        decoded_labels = [decode_puny(l) for l in raw_labels]
        decoded_domain = ".".join(decoded_labels)
        decoded_main = decode_puny(main)

        signals = []
        matched_brand = None
        brands = self.watchlist.all_brands()

        # Skeletons for homoglyph comparison
        main_skel = confusables.skeleton(decoded_main)
        components = _components(domain)
        decoded_components = _components(decoded_domain)
        sub_labels = [l for l in sub.split(".") if l]

        # --- Signal 1: brand lookalike (registrable main label ~ brand token)
        best_l1 = None  # (points, brand, detail)
        # A plain dictionary word (`cloud`) is not a lookalike of `gcloud`.
        main_is_word = is_common_word(decoded_main)
        for brand in brands:
            w = brand.weight
            for tok in brand.match_labels:
                if len(tok) < 4:
                    continue
                if main_is_word and decoded_main != tok:
                    continue
                d = damerau_levenshtein(decoded_main, tok)
                if d == 0 and decoded_main == tok:
                    pts = int(round(45 * w))
                    cand = (pts, brand.name,
                            f"registrable label '{main}' is exactly brand "
                            f"'{tok}' on an unaffiliated domain")
                    if best_l1 is None or cand[0] > best_l1[0]:
                        best_l1 = cand
                elif d == 1 and abs(len(decoded_main) - len(tok)) <= 2:
                    pts = int(round(45 * w))
                    cand = (pts, brand.name,
                            f"'{decoded_main}' is 1 edit from brand '{tok}'")
                    if best_l1 is None or cand[0] > best_l1[0]:
                        best_l1 = cand
                elif d == 2 and len(tok) >= 6 and abs(len(decoded_main) - len(tok)) <= 2:
                    pts = int(round(30 * w))
                    cand = (pts, brand.name,
                            f"'{decoded_main}' is 2 edits from brand '{tok}'")
                    if best_l1 is None or cand[0] > best_l1[0]:
                        best_l1 = cand
        if best_l1:
            signals.append(Signal(1, "Brand lookalike", best_l1[2], best_l1[0]))
            matched_brand = best_l1[1]

        # --- Signal 3: homoglyph substitution (skeleton folds onto a brand)
        # Only meaningful when the raw label actually differs from the token
        # (i.e. a substitution was applied) — otherwise it's the exact brand.
        # We test the whole registrable label (fuzzy, d<=1) AND each hyphenated
        # component (exact skeleton only) so `paypa1-secure` folds `paypa1`
        # onto `paypal` while `apply-now` does not collide with `apple`.
        best_l3 = None
        hyphen_parts = decoded_main.split("-")
        candidates = [(decoded_main, 1)]
        if len(hyphen_parts) > 1:
            candidates += [(p, 0) for p in hyphen_parts if len(p) >= 4]
        for cand_label, max_d in candidates:
            if is_common_word(cand_label):
                continue
            cand_skel = confusables.skeleton(cand_label)
            applied = (
                confusables.has_confusable(cand_label)
                or confusables.is_non_ascii(cand_label)
                or cand_skel != cand_label
            )
            if not applied:
                continue
            for brand in brands:
                w = brand.weight
                for tok in brand.match_labels:
                    if len(tok) < 4:
                        continue
                    tok_skel = confusables.skeleton(tok)
                    d = damerau_levenshtein(cand_skel, tok_skel)
                    if d <= max_d and cand_label != tok:
                        pts = int(round(40 * w))
                        c = (pts, brand.name,
                             f"'{cand_label}' folds to '{cand_skel}' ≈ brand '{tok}'")
                        if best_l3 is None or c[0] > best_l3[0]:
                            best_l3 = c
        if best_l3:
            signals.append(Signal(3, "Homoglyph substitution", best_l3[2], best_l3[0]))
            if matched_brand is None:
                matched_brand = best_l3[1]

        # --- Signal 2: brand token in the wrong position -------------------
        # Token appears as a subdomain label or a hyphenated component of the
        # registrable label, but the registrable label is not itself the brand.
        best_l2 = None
        for brand in brands:
            w = brand.weight
            for tok in brand.tokens:
                if len(tok) < 3:  # exact-component match is safe for short tokens
                    continue
                in_sub = tok in sub_labels
                in_hyphen = (tok in components and main != tok
                             and "-" in main and tok in main.split("-"))
                if in_sub or in_hyphen:
                    where = "subdomain" if in_sub else "hyphenated label"
                    pts = int(round(40 * w))
                    cand = (pts, brand.name,
                            f"brand '{tok}' used in {where} of '{domain}'")
                    if best_l2 is None or cand[0] > best_l2[0]:
                        best_l2 = cand
        if best_l2:
            signals.append(Signal(2, "Brand in wrong position", best_l2[2], best_l2[0]))
            if matched_brand is None:
                matched_brand = best_l2[1]

        # --- Signal 4: punycode present ------------------------------------
        puny_labels = [l for l in raw_labels if l.startswith("xn--")]
        if puny_labels:
            # Did the decoded form fold onto a brand?
            puny_hits_brand = False
            if best_l3 and any(confusables.is_non_ascii(decode_puny(l)) for l in puny_labels):
                puny_hits_brand = True
            else:
                for brand in brands:
                    for tok in brand.match_labels:
                        if len(tok) < 4:
                            continue
                        if damerau_levenshtein(main_skel, confusables.skeleton(tok)) <= 1:
                            puny_hits_brand = True
                            break
                    if puny_hits_brand:
                        break
            if puny_hits_brand:
                signals.append(Signal(4, "Punycode present",
                                      f"punycode label(s) {puny_labels} decode toward a brand",
                                      35))
            else:
                signals.append(Signal(4, "Punycode present",
                                      f"punycode label(s) {puny_labels} → '{decoded_domain}'",
                                      25))

        # --- Signals 5/6: phishing keywords --------------------------------
        lure_hits = [c for c in decoded_components if c in self.lure]
        brand_present = matched_brand is not None
        if not brand_present:
            # Also treat a bare brand token appearing anywhere as "brand present"
            for brand in brands:
                if any(t in decoded_components for t in brand.tokens if len(t) >= 4):
                    brand_present = True
                    matched_brand = matched_brand or brand.name
                    break
        if lure_hits and brand_present:
            signals.append(Signal(5, "Phishing keyword + brand",
                                  f"lure term(s) {sorted(set(lure_hits))} alongside a brand",
                                  25))
        elif lure_hits:
            signals.append(Signal(6, "Phishing keyword",
                                  f"lure term(s) {sorted(set(lure_hits))}",
                                  10))

        # --- Signal 7: high-abuse TLD --------------------------------------
        top_tld = suffix.split(".")[-1] if suffix else ""
        if top_tld in self.abuse_tlds:
            signals.append(Signal(7, "High-abuse TLD",
                                  f".{top_tld} is a frequently-abused TLD", 15))

        # --- Signal 8: DGA-like label --------------------------------------
        dga = dga_score(main)
        if dga["looks_dga"]:
            signals.append(Signal(8, "DGA-like label",
                                  f"entropy {dga['entropy']} bits, word-coverage "
                                  f"{dga['coverage']}, consonant run "
                                  f"{dga['consonant_run']}", 15))

        score = min(100, sum(s.points for s in signals))
        return {
            "registrable": reg,
            "domain": domain,
            "score": score,
            "signals": [s.as_dict() for s in signals],
            "matched_brand": matched_brand,
            "_dga": dga["looks_dga"],
        }

    # -- whole certificate ------------------------------------------------
    def score_cert(self, record: dict) -> dict:
        domains = record.get("domains", [])
        issuer = (record.get("issuer") or "").lower()

        best = None
        per_reg = {}
        registrables = set()
        for dom in domains:
            res = self._score_one(dom)
            registrables.add(res["registrable"])
            prev = per_reg.get(res["registrable"])
            if prev is None or res["score"] > prev["score"]:
                per_reg[res["registrable"]] = res
            if best is None or res["score"] > best["score"]:
                best = res

        if best is None:
            best = {"registrable": "", "domain": "", "score": 0,
                    "signals": [], "matched_brand": None}

        signals = [Signal(s["id"], s["name"], s["detail"], s["points"])
                   for s in best["signals"]]

        # --- Signal 9: SAN sprawl (cert-level) -----------------------------
        n_sans = len(domains)
        n_reg = len(registrables)
        if n_sans > 30 or (n_reg > 15 and n_sans > 15):
            signals.append(Signal(9, "SAN sprawl",
                                  f"{n_sans} SANs spanning {n_reg} registrable domains",
                                  10))

        # --- Signal 10: combination bonus (free DV issuer + 2+ signals) ----
        is_free = any(fi in issuer for fi in FREE_ISSUERS)
        if is_free and len(signals) >= 2 and best["score"] > 0:
            signals.append(Signal(10, "Free-DV + multi-signal",
                                  f"DV cert from free issuer '{record.get('issuer')}' "
                                  f"with {len(signals)} other signals", 5))

        score = min(100, sum(s.points for s in signals))
        return {
            "score": score,
            "severity": severity_for(score),
            "signals": [s.as_dict() for s in signals],
            "matched_brand": best["matched_brand"],
            "registrable": best["registrable"],
            "domain": best["domain"],
            "n_sans": n_sans,
            "n_registrable": n_reg,
        }


# ---------------------------------------------------------------------------
# Tiny CLI: read demo JSONL on stdin, print colored hits (milestone 1)
# ---------------------------------------------------------------------------

def _main():
    import sys
    import json
    from .brands import Watchlist
    import os

    brands_path = os.environ.get("CERTWATCH_BRANDS", "brands.json")
    wl = Watchlist(brands_path)
    scorer = Scorer(wl)

    RESET = "\033[0m"
    COLORS = {"critical": "\033[41;97m", "high": "\033[91m",
              "medium": "\033[93m", "low": "\033[90m"}

    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            rec = json.loads(line)
        except json.JSONDecodeError:
            continue
        result = scorer.score_cert(rec)
        if result["score"] < 30:
            continue
        c = COLORS.get(result["severity"], "")
        names = ",".join(s["name"] for s in result["signals"])
        print(f"{c}[{result['score']:3d} {result['severity']:8s}]{RESET} "
              f"{result['domain']:40s} brand={result['matched_brand']} "
              f"({names})")


if __name__ == "__main__":
    _main()
