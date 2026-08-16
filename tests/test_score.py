"""Table-driven scoring tests.

Each row is (domain, should_fire, note). ``should_fire`` means score >= 30 (the
default alert threshold). Roughly half the table is legitimate/near-miss traffic
that must NOT fire, so the suite pins precision as well as recall.

Some rows additionally assert the matched brand or a specific signal id.
"""

import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from certwatch.detect.brands import Watchlist
from certwatch.detect.score import Scorer

BRANDS = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "brands.json")


@pytest.fixture(scope="module")
def scorer():
    return Scorer(Watchlist(BRANDS))


def _score(scorer, domain, issuer="Let's Encrypt"):
    return scorer.score_cert({"domains": [domain], "issuer": issuer, "is_precert": True})


# (domain, should_fire, expected_brand_or_None)
CASES = [
    # --- true positives: brand lookalikes ---
    ("paypa1.com", True, "paypal"),
    ("paypa1-secure.com", True, "paypal"),
    ("paypaii.com", True, "paypal"),
    ("micros0ft.com", True, "microsoft"),
    ("rnicrosoft.com", True, "microsoft"),
    ("microsoft0nline.com", True, "microsoft"),
    ("g00gle.com", True, "google"),
    ("goog1e-login.com", True, "google"),
    ("app1e.com", True, "apple"),
    ("appie-id.com", True, "apple"),
    ("amaz0n.com", True, "amazon"),
    ("arnazon.com", True, "amazon"),
    ("netfllx.com", True, "netflix"),
    ("c0inbase.com", True, "coinbase"),
    ("faceb00k.com", True, "meta"),
    ("0kta.com", True, "okta"),
    # --- true positives: brand in wrong position ---
    ("paypal.account-verify.com", True, "paypal"),
    ("login-paypal.co", True, "paypal"),
    ("microsoft.secure-update.top", True, "microsoft"),
    ("appleid.confirm-billing.xyz", True, "apple"),
    ("coinbase.wallet-recover.sbs", True, "coinbase"),
    ("okta-sso-login.click", True, "okta"),
    ("chase.online-verify.cf", True, "chase"),
    # --- true positives: keyword + brand ---
    ("secure-paypal-login.com", True, "paypal"),
    ("amazon-billing-update.net", True, "amazon"),
    ("verify-coinbase-account.io", True, "coinbase"),
    # --- true positives: punycode homoglyph ---
    ("xn--pypal-4ve.com", True, "paypal"),
    ("xn--microsft-q9a.com", True, "microsoft"),
    # --- true positives: DGA + abuse TLD ---
    ("x7fj29dkq2.top", True, None),
    ("q9z2xk7bvn4.click", True, None),
    # --- true positives via combination ---
    ("dhl-express-tracking.sbs", True, "dhl"),
    ("wellsfargo-secure.top", True, "wellsfargo"),
    # --- near misses / legitimate: must NOT fire ---
    ("paypal.com", False, None),
    ("paypalobjects.com", False, None),
    ("microsoft.com", False, None),
    ("microsoftonline.com", False, None),
    ("office.com", False, None),
    ("google.com", False, None),
    ("googleusercontent.com", False, None),
    ("apple.com", False, None),
    ("icloud.com", False, None),
    ("amazon.co.uk", False, None),
    ("amazonaws.com", False, None),
    ("netflix.com", False, None),
    ("nflxvideo.net", False, None),
    ("coinbase.com", False, None),
    ("chase.com", False, None),
    ("apply-now.com", False, None),
    ("applesupplies.com", False, None),
    ("appleton-dental.com", False, None),
    ("metadata-labs.io", False, None),
    ("metaphor-media.com", False, None),
    ("chaselodge.co.uk", False, None),
    ("oktoberfest-munich.de", False, None),
    ("mynetflixreview.blog", False, None),
    ("thegoogleplex-tour.net", False, None),
    ("northwind-supplies.com", False, None),
    ("bluecedar-labs.com", False, None),
    ("swiftlogistics.co", False, None),
    ("summit-capital.com", False, None),
    ("github.io", False, None),
    ("myproject.github.io", False, None),
    ("api.stripe.com", False, None),
    ("support.zendesk.com", False, None),
    ("www.bbc.co.uk", False, None),
    ("secure.example.org", False, None),
    ("identity-design.studio", False, None),
    ("visahq-travel.com", False, None),
]


@pytest.mark.parametrize("domain,should_fire,brand", CASES)
def test_scoring(scorer, domain, should_fire, brand):
    result = _score(scorer, domain)
    fired = result["score"] >= 30
    assert fired == should_fire, (
        f"{domain}: score={result['score']} sev={result['severity']} "
        f"signals={[s['name'] for s in result['signals']]}"
    )
    if should_fire and brand is not None:
        assert result["matched_brand"] == brand, (
            f"{domain}: expected brand {brand}, got {result['matched_brand']}"
        )


def test_precision_ratio():
    """At least half the table is negatives, and none of them fire."""
    negatives = [c for c in CASES if not c[1]]
    assert len(negatives) >= len(CASES) / 2


def test_free_issuer_alone_is_not_a_signal(scorer):
    """A plain domain on a free CA must score 0 — issuance is never a signal."""
    result = _score(scorer, "ordinary-small-business.com", issuer="Let's Encrypt")
    assert result["score"] == 0


def test_registrable_match_wins(scorer):
    """A legitimate brand domain short-circuits even with a scary subdomain."""
    result = scorer.score_cert({
        "domains": ["login.secure.verify.paypal.com"],
        "issuer": "DigiCert Inc", "is_precert": False,
    })
    assert result["score"] == 0


def test_severity_bands(scorer):
    from certwatch.detect.score import severity_for
    assert severity_for(70) == "critical"
    assert severity_for(69) == "high"
    assert severity_for(50) == "high"
    assert severity_for(49) == "medium"
    assert severity_for(30) == "medium"
    assert severity_for(29) == "low"


def test_san_sprawl(scorer):
    domains = [f"host{i}-unrelated{i}.com" for i in range(40)]
    result = scorer.score_cert({"domains": domains, "issuer": "Let's Encrypt",
                                "is_precert": True})
    assert any(s["id"] == 9 for s in result["signals"])


def test_cap_at_100(scorer):
    result = scorer.score_cert({
        "domains": ["xn--pypal-4ve-secure-login-verify.top"],
        "issuer": "Let's Encrypt", "is_precert": True,
    })
    assert result["score"] <= 100
