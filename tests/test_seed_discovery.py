"""Tests for DNS-TXT seed discovery — never hits real DNS."""

from messagechain.network import seed_discovery


def test_parses_simple_record():
    out = seed_discovery._parse_txt_record("host=1.2.3.4 port=9333")
    assert out == [("1.2.3.4", 9333)]


def test_parses_quoted_record():
    out = seed_discovery._parse_txt_record('"host=1.2.3.4 port=9333"')
    assert out == [("1.2.3.4", 9333)]


def test_parses_multiple_pairs_per_record():
    out = seed_discovery._parse_txt_record(
        "host=1.2.3.4 port=9333 host=5.6.7.8 port=9335",
    )
    assert out == [("1.2.3.4", 9333), ("5.6.7.8", 9335)]


def test_malformed_records_ignored():
    out = seed_discovery._parse_txt_record("junk port=nope host=")
    assert out == []


def test_discover_deduplicates_across_domains():
    records = {
        "a.example": ["host=1.1.1.1 port=9333"],
        "b.example": ["host=1.1.1.1 port=9333", "host=2.2.2.2 port=9333"],
    }
    seeds = seed_discovery.discover_dns_seeds(
        ["a.example", "b.example"],
        resolver=lambda dom, t: records.get(dom, []),
    )
    assert seeds == [("1.1.1.1", 9333), ("2.2.2.2", 9333)]


def test_discover_empty_when_resolver_raises():
    def bad(dom, t):
        raise RuntimeError("boom")
    seeds = seed_discovery.discover_dns_seeds(
        ["a.example"],
        resolver=bad,
    )
    assert seeds == []


def test_discover_empty_list_when_no_domains():
    assert seed_discovery.discover_dns_seeds([]) == []
