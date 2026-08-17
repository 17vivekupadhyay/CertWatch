"""CT entry parsing tests, including a real precert fixture.

The fixtures in ``tests/fixtures/`` are genuine ``get-entries`` items captured
from public CT logs (Cloudflare Nimbus). ``precert_entry.json`` is an
``entry_type == 1`` precertificate — the case that must be parsed out of
``extra_data`` rather than the leaf. If precert handling regresses, this test
fails and we know half the live feed would have been silently dropped.
"""

import base64
import json
import os
import struct

import pytest

FIX = os.path.join(os.path.dirname(os.path.abspath(__file__)), "fixtures")

from certwatch.sources.ctlog import (
    parse_entry, parse_leaf_input, extract_domains, _read_u24_prefixed,
    parse_extra_data_first_cert,
)


def _load(name):
    with open(os.path.join(FIX, name)) as f:
        return json.load(f)


@pytest.fixture
def precert():
    return _load("precert_entry.json")


@pytest.fixture
def x509():
    return _load("x509_entry.json")


def test_precert_fixture_is_actually_a_precert(precert):
    leaf = base64.b64decode(precert["leaf_input"])
    entry_type = struct.unpack(">H", leaf[10:12])[0]
    assert entry_type == 1, "fixture is not a precert entry"


def test_precert_parses_from_extra_data(precert):
    """A precert leaf holds a bare TBSCertificate; the full cert must come from
    extra_data. This is the ~half-the-feed case."""
    rec = parse_entry(precert["leaf_input"], precert["extra_data"], "test")
    assert rec is not None
    assert rec["is_precert"] is True
    assert rec["domains"], "no domains extracted from precert"
    for expected in precert["expected_domains"]:
        assert expected in rec["domains"]


def test_x509_parses_from_leaf(x509):
    rec = parse_entry(x509["leaf_input"], x509["extra_data"], "test")
    assert rec is not None
    assert rec["is_precert"] is False
    assert rec["domains"]
    for expected in x509["expected_domains"]:
        assert expected in rec["domains"]


def test_leaf_entry_types(precert, x509):
    _, et_pre, der_pre = parse_leaf_input(base64.b64decode(precert["leaf_input"]))
    assert et_pre == 1
    assert der_pre is None  # precert leaf yields no loadable cert
    _, et_x509, der_x509 = parse_leaf_input(base64.b64decode(x509["leaf_input"]))
    assert et_x509 == 0
    assert der_x509 is not None  # x509 leaf yields the DER directly


def test_record_shape(precert):
    rec = parse_entry(precert["leaf_input"], precert["extra_data"], "mylog")
    assert set(rec) >= {"seen_at", "not_before", "issuer", "domains", "log", "is_precert"}
    assert rec["log"] == "mylog"
    assert isinstance(rec["not_before"], float)
    assert all(d == d.lower() for d in rec["domains"])


def test_malformed_entry_returns_none():
    assert parse_entry("!!!not-base64!!!", "", "test") is None
    assert parse_entry(base64.b64encode(b"\x00\x00").decode(), "", "test") is None


def test_u24_prefix_reader():
    payload = b"\x00\x00\x03abcXYZ"
    data, off = _read_u24_prefixed(payload, 0)
    assert data == b"abc"
    assert off == 6
    with pytest.raises(ValueError):
        _read_u24_prefixed(b"\x00\xff\xff", 0)  # claims 65535 bytes, has none


def test_extra_data_first_cert_precert(precert):
    extra = base64.b64decode(precert["extra_data"])
    der = parse_extra_data_first_cert(extra, 1)
    assert der and len(der) > 100
