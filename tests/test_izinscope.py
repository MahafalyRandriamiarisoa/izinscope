"""
Tests unitaires pour le module izinscope.

Le réseau et le système de fichiers réels sont systématiquement
mockés pour garantir des tests rapides, reproductibles et hors‑ligne.
Les helpers DNS (_FakeResolver) et la fixture de reset du logger vivent
dans tests/conftest.py.
"""

from __future__ import annotations

import ipaddress
import logging
import textwrap
from pathlib import Path

import pytest

import izinscope


# ---------------------------------------------------------------------------
# resolve_domain
# ---------------------------------------------------------------------------


def test_resolve_domain_success(fake_resolver) -> None:
    """Le domaine retourne bien la liste des IP A et AAAA."""
    domain = "example.com"
    fake = fake_resolver(
        {
            (domain, "A"): ["1.2.3.4"],
            (domain, "AAAA"): ["2001:db8::1"],
        }
    )

    returned_domain, ips = izinscope.resolve_domain(domain, fake)

    assert returned_domain == domain
    assert set(ips) == {"1.2.3.4", "2001:db8::1"}


def test_resolve_domain_no_aaaa(fake_resolver) -> None:
    """Absence d'enregistrement AAAA ne doit pas lever d'erreur."""
    domain = "example.net"
    fake = fake_resolver({(domain, "A"): ["9.9.9.9"]})

    returned_domain, ips = izinscope.resolve_domain(domain, fake)

    assert returned_domain == domain
    assert ips == ["9.9.9.9"]


def test_resolve_domain_handles_dns_exception() -> None:
    """Une erreur DNS (timeout) est avalée sans lever, IP vide retournée (B15)."""
    import dns.exception

    class _Timeouter:
        def resolve(self, domain, record):
            raise dns.exception.Timeout()

    domain, ips = izinscope.resolve_domain("slow.example", _Timeouter())

    assert domain == "slow.example"
    assert ips == []


def test_resolve_domain_propagates_non_dns_errors() -> None:
    """Une exception non-DNS n'est PAS avalée silencieusement (B15)."""

    class _Boom:
        def resolve(self, domain, record):
            raise RuntimeError("boom")

    with pytest.raises(RuntimeError):
        izinscope.resolve_domain("x.example", _Boom())


# ---------------------------------------------------------------------------
# load_scope
# ---------------------------------------------------------------------------


def test_load_scope_mixed_entries(tmp_path: Path, fake_resolver) -> None:
    """
    Mélange CIDR + domaine dans le fichier de scope.

    On injecte un _FakeResolver pour renvoyer une IP prédictible.
    """
    scope_file = tmp_path / "scope.txt"
    scope_file.write_text(
        textwrap.dedent(
            """\
        10.0.0.0/8
        example.org
    """
        )
    )

    fake = fake_resolver({("example.org", "A"): ["93.184.216.34"]})

    nets, ip_map = izinscope.load_scope(scope_file, fake)

    # 1) réseau CIDR correctement interprété
    cidrs = {str(n[0]) for n in nets}
    assert "10.0.0.0/8" in cidrs

    # 2) domaine résolu stocké dans ip_map
    assert ip_map == {"93.184.216.34": [("example.org", str(scope_file))]}


def test_load_scope_aaaa_entry(tmp_path: Path, fake_resolver) -> None:
    """
    Un domaine AAAA-only dans le scope doit être chargé (B8 : IPv6).
    """
    scope_file = tmp_path / "scope.txt"
    scope_file.write_text("v6only.example\n")

    fake = fake_resolver({("v6only.example", "AAAA"): ["2001:db8::1"]})
    _, ip_map = izinscope.load_scope(scope_file, fake)

    assert ip_map == {"2001:db8::1": [("v6only.example", str(scope_file))]}


def test_load_scope_skips_comments(tmp_path: Path, fake_resolver) -> None:
    """
    Lignes de commentaire complètes et commentaires en fin de ligne ignorés (B13).
    """
    scope_file = tmp_path / "scope.txt"
    scope_file.write_text(
        textwrap.dedent(
            """\
        # commentaire d'entête
        10.0.0.0/8
        192.168.0.1  # commentaire inline
    """
        )
    )

    fake = fake_resolver({})
    nets, ip_map = izinscope.load_scope(scope_file, fake)

    cidrs = {str(n[0]) for n in nets}
    assert "10.0.0.0/8" in cidrs
    # le commentaire inline est tronqué, l'IP reste interprétée
    assert "192.168.0.1/32" in cidrs
    # le commentaire d'entête ne crée aucune entrée
    assert ip_map == {}


# ---------------------------------------------------------------------------
# single_check
# ---------------------------------------------------------------------------


def test_single_check_ip_match(caplog) -> None:
    """
    La cible est une IP appartenant au scope -> sortie avec préfixe [+]
    """
    networks = [(ipaddress.ip_network("192.168.0.0/24"), "192.168.0.0/24", "scope.txt")]

    with caplog.at_level(logging.INFO, logger="izinscope"):
        result = izinscope.single_check(
            "192.168.0.5", networks, ips_map={}, resolver=None
        )

    assert "[+]" in caplog.text
    assert "192.168.0.5" in caplog.text
    # renvoie des objets Match (A3)
    assert result["192.168.0.5"][0] == izinscope.Match(
        "192.168.0.5", "192.168.0.0/24", "scope.txt"
    )


def test_single_check_domain_hors_scope(fake_resolver, caplog) -> None:
    """
    Domaine résout, mais aucune IP in-scope -> message 'Hors scope' (B5).
    """
    fake = fake_resolver({("nocontent.example", "A"): ["8.8.8.8"]})

    with caplog.at_level(logging.INFO, logger="izinscope"):
        result = izinscope.single_check(
            "nocontent.example", networks=[], ips_map={}, resolver=fake
        )

    assert result == {}
    assert "Hors scope" in caplog.text
    assert "8.8.8.8" in caplog.text
    assert "[-]" in caplog.text


def test_single_check_domain_unresolvable(fake_resolver, caplog) -> None:
    """
    Domaine qui ne résout vers rien -> 'Aucune IP résolue.'
    """
    fake = fake_resolver({})

    with caplog.at_level(logging.INFO, logger="izinscope"):
        result = izinscope.single_check(
            "nxdomain.example", networks=[], ips_map={}, resolver=fake
        )

    assert result == {}
    assert "Aucune IP résolue." in caplog.text
    assert "[-]" in caplog.text


# ---------------------------------------------------------------------------
# write_output
# ---------------------------------------------------------------------------


def test_write_output_txt_and_csv(tmp_path: Path) -> None:
    """
    TXT : un domaine par ligne (B10). CSV : 4 colonnes domain,ip,entry,file (B11).
    """
    data = {"example.com": [izinscope.Match("93.184.216.34", "entry", "scope.txt")]}
    txt_file = tmp_path / "out.txt"
    csv_file = tmp_path / "out.csv"

    izinscope.write_output(txt_file, data, csv=False)
    izinscope.write_output(csv_file, data, csv=True)

    # TXT : un domaine par ligne, sans les IP
    assert txt_file.read_text().strip() == "example.com"

    # CSV : entête 4 colonnes + ligne détaillée
    csv_lines = csv_file.read_text().splitlines()
    assert csv_lines == [
        "domain,ip,entry,file",
        "example.com,93.184.216.34,entry,scope.txt",
    ]


def test_write_output_multiple_ips(tmp_path: Path) -> None:
    """
    Plusieurs IP pour un domaine : une seule ligne TXT (B10), une ligne CSV par IP.
    """
    data = {
        "example.net": [
            izinscope.Match("1.1.1.1", "entry", "scope1.txt"),
            izinscope.Match("2.2.2.2", "entry", "scope1.txt"),
        ]
    }
    txt_file = tmp_path / "out.txt"
    izinscope.write_output(txt_file, data, csv=False)

    assert txt_file.read_text().strip() == "example.net"

    # CSV
    csv_file = tmp_path / "out.csv"
    izinscope.write_output(csv_file, data, csv=True)

    csv_lines = csv_file.read_text().splitlines()
    assert csv_lines == [
        "domain,ip,entry,file",
        "example.net,1.1.1.1,entry,scope1.txt",
        "example.net,2.2.2.2,entry,scope1.txt",
    ]
