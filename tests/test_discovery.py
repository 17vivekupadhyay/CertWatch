"""Discovery-mode scoring tests.

Discovery watches domains you OWN and surfaces new subdomains, ranked by how
sensitive the name looks. Like the phishing suite, roughly half the table is
routine traffic that should stay low, and domains you don't own must never
appear at all.
"""

import json
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from certwatch.detect.discovery import AssetWatch, DiscoveryScorer, discovery_severity

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


@pytest.fixture(scope="module")
def scorer(tmp_path_factory):
    p = tmp_path_factory.mktemp("assets") / "assets.json"
    p.write_text(json.dumps({"targets": ["acme-labs.io", "northwind-corp.com"]}))
    return DiscoveryScorer(AssetWatch(str(p)))


def _one(scorer, domain):
    fs = scorer.score_cert({"domains": [domain], "issuer": "Let's Encrypt"})
    return fs[0] if fs else None


# (domain, expected_owned, min_expected_score)
CASES = [
    # sensitive owned subdomains — should score high
    ("vault.internal.acme-labs.io", True, 60),
    ("grafana.staging.acme-labs.io", True, 60),
    ("jenkins.dev.northwind-corp.com", True, 60),
    ("clickhouse-dev.aws.acme-labs.io", True, 60),
    ("admin.uat.northwind-corp.com", True, 60),
    ("kibana.prod.acme-labs.io", True, 30),
    ("vpn.corp.northwind-corp.com", True, 40),
    ("postgres.staging.acme-labs.io", True, 60),
    # routine owned subdomains — owned, but should stay low
    ("www.acme-labs.io", None, 0),        # www is skipped entirely
    ("api.acme-labs.io", True, 0),
    ("cdn.northwind-corp.com", True, 0),
    ("mail.acme-labs.io", True, 0),
    ("blog.northwind-corp.com", True, 0),
    # not owned — must not surface at all
    ("grafana.staging.someone-else.com", None, 0),
    ("vault.internal.evil-corp.net", None, 0),
    ("acme-labs.io", None, 0),            # apex is skipped
    ("northwind-corp.com", None, 0),
]


@pytest.mark.parametrize("domain,owned,min_score", CASES)
def test_discovery(scorer, domain, owned, min_score):
    f = _one(scorer, domain)
    if owned is None:
        assert f is None, f"{domain}: unexpectedly surfaced {f}"
        return
    assert f is not None, f"{domain}: expected to be surfaced"
    assert f["score"] >= min_score, f"{domain}: score {f['score']} < {min_score}"


def test_not_owned_never_fires(scorer):
    for d in ["dev.google.com", "internal.microsoft.com", "vault.paypal.com"]:
        assert scorer.score_cert({"domains": [d]}) == []


def test_tech_is_detected(scorer):
    f = _one(scorer, "clickhouse-dev.aws.acme-labs.io")
    assert "ClickHouse" in f["tech"]
    assert "infra/tooling" in f["tags"]
    assert "non-production" in f["tags"]


def test_wildcard_flagged(scorer):
    fs = scorer.score_cert({"domains": ["*.internal.acme-labs.io"]})
    assert fs and fs[0]["is_wildcard"] is True


def test_entry_points_detected(scorer):
    f = _one(scorer, "portal.acme-labs.io")
    assert f is not None and "entry point" in f["tags"]
    f2 = _one(scorer, "sso.northwind-corp.com")
    assert f2 is not None and "entry point" in f2["tags"]


def test_severity_bands():
    assert discovery_severity(60) == "critical"
    assert discovery_severity(40) == "high"
    assert discovery_severity(20) == "medium"
    assert discovery_severity(10) == "routine"


def test_multiple_owned_in_one_cert(scorer):
    fs = scorer.score_cert({"domains": [
        "vault.internal.acme-labs.io", "grafana.dev.northwind-corp.com",
        "unrelated.example.com",
    ]})
    domains = {f["domain"] for f in fs}
    assert "vault.internal.acme-labs.io" in domains
    assert "grafana.dev.northwind-corp.com" in domains
    assert "unrelated.example.com" not in domains
    # highest-scoring first
    assert fs[0]["score"] >= fs[-1]["score"]
