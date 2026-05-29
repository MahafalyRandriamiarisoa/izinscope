"""
Tests ciblés du moteur de correspondance (checker.py).

Couvre match_ips (cas vides, chevauchements, non cross-match IPv4/IPv6),
single_check (IPv6 nue, hors scope, chaîne CIDR, multi-IP) et check_domains
(liste vide, filtrage in-scope, double match). Contient un test-bug ROUGE :
match_ips ne doit pas planter sur une IP malformée.
"""

from __future__ import annotations

import ipaddress
from pathlib import Path

import izinscope


def _net(cidr: str, fname: str = "scope.txt"):
    return (ipaddress.ip_network(cidr), cidr, fname)


# ---------------------------------------------------------------------------
# match_ips
# ---------------------------------------------------------------------------


def test_match_ips_empty_ip_list() -> None:
    assert izinscope.match_ips([], [_net("10.0.0.0/8")], {}) == []


def test_match_ips_empty_scope() -> None:
    assert izinscope.match_ips(["192.168.0.5"], [], {}) == []


def test_match_ips_overlapping_networks_and_ips_map() -> None:
    """Une IP dans deux réseaux qui se chevauchent ET ips_map -> 3 Match (non dédup)."""
    networks = [_net("10.0.0.0/8", "a.txt"), _net("10.1.0.0/16", "b.txt")]
    ips_map = {"10.1.2.3": [("host.example", "c.txt")]}

    matches = izinscope.match_ips(["10.1.2.3"], networks, ips_map)

    assert len(matches) == 3
    assert {m.entry for m in matches} == {"10.0.0.0/8", "10.1.0.0/16", "host.example"}


def test_match_ips_no_cross_family() -> None:
    """Une IPv4 ne matche pas un réseau IPv6 et inversement."""
    assert izinscope.match_ips(["1.2.3.4"], [_net("2001:db8::/32")], {}) == []
    assert izinscope.match_ips(["2001:db8::1"], [_net("10.0.0.0/8")], {}) == []


def test_match_ips_malformed_ip_returns_empty() -> None:
    """BUG #3 (ROUGE) : une IP malformée doit être ignorée, pas faire planter."""
    networks = [_net("10.0.0.0/8")]

    assert izinscope.match_ips(["invalid-ip"], networks, {}) == []


# ---------------------------------------------------------------------------
# single_check
# ---------------------------------------------------------------------------


def test_single_check_ipv6_in_scope() -> None:
    """Une IPv6 nue in-scope produit un Match (pas de DNS nécessaire)."""
    networks = [_net("2001:db8::/32")]

    result = izinscope.single_check("2001:db8::1", networks, ips_map={}, resolver=None)

    assert result["2001:db8::1"][0] == izinscope.Match(
        "2001:db8::1", "2001:db8::/32", "scope.txt"
    )


def test_single_check_ip_out_of_scope() -> None:
    """Une IP valide hors scope renvoie un dict vide."""
    networks = [_net("192.168.0.0/24")]

    assert izinscope.single_check("8.8.8.8", networks, {}, resolver=None) == {}


def test_single_check_cidr_string_treated_as_domain(fake_resolver) -> None:
    """Quirk documenté : une chaîne CIDR n'est pas une IP -> traitée en domaine -> {}."""
    networks = [_net("192.168.0.0/24")]

    result = izinscope.single_check(
        "192.168.0.0/24", networks, {}, resolver=fake_resolver({})
    )

    assert result == {}


def test_single_check_domain_multi_ip_partial_match(fake_resolver) -> None:
    """Domaine résolvant vers plusieurs IP : seules les in-scope sont retenues."""
    networks = [_net("10.0.0.0/8")]
    fake = fake_resolver({("mixed.example", "A"): ["10.1.1.1", "8.8.8.8"]})

    result = izinscope.single_check("mixed.example", networks, {}, resolver=fake)

    assert [m.ip for m in result["mixed.example"]] == ["10.1.1.1"]


# ---------------------------------------------------------------------------
# check_domains
# ---------------------------------------------------------------------------


def test_check_domains_empty_targets(fake_resolver) -> None:
    assert izinscope.check_domains([], [], {}, fake_resolver({})) == {}


def test_check_domains_only_inscope_returned(fake_resolver) -> None:
    """Seuls les domaines in-scope figurent dans le dict retourné."""
    networks = [_net("10.0.0.0/8")]
    fake = fake_resolver(
        {("a.example", "A"): ["10.1.1.1"], ("b.example", "A"): ["8.8.8.8"]}
    )

    result = izinscope.check_domains(["a.example", "b.example"], networks, {}, fake)

    assert list(result.keys()) == ["a.example"]


def test_check_domains_ip_in_network_and_ips_map(fake_resolver) -> None:
    """IP couverte à la fois par un réseau et par ips_map -> 2 Match (non dédup)."""
    networks = [_net("192.168.0.0/24", "net.txt")]
    ips_map = {"192.168.0.5": [("seed.example", "dom.txt")]}
    fake = fake_resolver({("dup.example", "A"): ["192.168.0.5"]})

    result = izinscope.check_domains(["dup.example"], networks, ips_map, fake)

    assert len(result["dup.example"]) == 2
    assert {m.entry for m in result["dup.example"]} == {
        "192.168.0.0/24",
        "seed.example",
    }


# ---------------------------------------------------------------------------
# intégration load_scope -> match_ips : un domaine du scope garde son nom
# ---------------------------------------------------------------------------


def test_domain_in_scope_preserves_name_on_match(tmp_path: Path, fake_resolver) -> None:
    """Un domaine du scope résolu en IP : interroger cette IP renvoie le domaine."""
    scope = tmp_path / "scope.txt"
    scope.write_text("example.com\n")
    fake = fake_resolver({("example.com", "A"): ["93.184.216.34"]})

    nets, ips_map = izinscope.load_scope(scope, fake)
    matches = izinscope.match_ips(["93.184.216.34"], nets, ips_map)

    assert matches[0].entry == "example.com"
