"""
Tests unitaires pour le module izinscope.

Le réseau et le système de fichiers réels sont systématiquement
mockés pour garantir des tests rapides, reproductibles et hors‑ligne.
"""
from __future__ import annotations

import ipaddress
import os
import textwrap
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

import pytest

import izinscope


# ---------------------------------------------------------------------------
# resolve_domain
# ---------------------------------------------------------------------------

class _FakeRdata:
    """Objet minimal possédant la méthode .to_text() attendue par resolve()."""
    def __init__(self, val: str) -> None:
        self._val = val

    def to_text(self) -> str:  # noqa: D401
        return self._val


class _FakeResolver:
    """Remplace dns.resolver.Resolver pour des tests déterministes."""
    def __init__(self, mapping: dict[tuple[str, str], list[str]]) -> None:
        # mapping : (domain, record) -> [ip, ...]
        self._mapping = mapping

    def resolve(self, domain: str, record: str):  # noqa: D401
        key = (domain, record)
        if key not in self._mapping:
            raise izinscope.dns.resolver.NoAnswer()
        return [_FakeRdata(ip) for ip in self._mapping[key]]


def test_resolve_domain_success() -> None:
    """Le domaine retourne bien la liste des IP A et AAAA."""
    domain = "example.com"
    fake = _FakeResolver(
        {
            (domain, "A"): ["1.2.3.4"],
            (domain, "AAAA"): ["2001:db8::1"],
        }
    )

    returned_domain, ips = izinscope.resolve_domain(domain, fake)

    assert returned_domain == domain
    assert set(ips) == {"1.2.3.4", "2001:db8::1"}


def test_resolve_domain_no_aaaa() -> None:
    """Absence d’enregistrement AAAA ne doit pas lever d’erreur."""
    domain = "example.net"
    fake = _FakeResolver({(domain, "A"): ["9.9.9.9"]})

    returned_domain, ips = izinscope.resolve_domain(domain, fake)

    assert returned_domain == domain
    assert ips == ["9.9.9.9"]


# ---------------------------------------------------------------------------
# load_scope
# ---------------------------------------------------------------------------

def test_load_scope_mixed_entries(tmp_path: Path) -> None:
    """
    Mélange CIDR + domaine dans le fichier de scope.

    On injecte un _FakeResolver pour renvoyer une IP prédictible.
    """
    scope_file = tmp_path / "scope.txt"
    scope_file.write_text(textwrap.dedent("""\
        10.0.0.0/8
        example.org
    """))

    fake = _FakeResolver({("example.org", "A"): ["93.184.216.34"]})

    nets, ip_map = izinscope.load_scope(scope_file, fake)

    # 1) réseau CIDR correctement interprété
    cidrs = {str(n[0]) for n in nets}
    assert "10.0.0.0/8" in cidrs

    # 2) domaine résolu stocké dans ip_map
    assert ip_map == {
        "93.184.216.34": [("example.org", str(scope_file))]
    }


def test_load_scope_aaaa_entry(tmp_path: Path) -> None:
    """
    Un domaine AAAA-only dans le scope doit être chargé (B8 : IPv6).
    """
    scope_file = tmp_path / "scope.txt"
    scope_file.write_text("v6only.example\n")

    fake = _FakeResolver({("v6only.example", "AAAA"): ["2001:db8::1"]})
    _, ip_map = izinscope.load_scope(scope_file, fake)

    assert ip_map == {
        "2001:db8::1": [("v6only.example", str(scope_file))]
    }


# ---------------------------------------------------------------------------
# single_check
# ---------------------------------------------------------------------------

def test_single_check_ip_match(capsys: pytest.CaptureFixture[str]) -> None:
    """
    La cible est une IP appartenant au scope -> sortie avec préfixe [+]
    """
    networks = [(ipaddress.ip_network("192.168.0.0/24"), "192.168.0.0/24", "scope.txt")]
    izinscope.ONLY_DOMAIN = False  # on veut que log() écrive sur stdout

    izinscope.single_check("192.168.0.5", networks, ips_map={}, resolver=None)

    out = capsys.readouterr().out
    assert "[+]" in out
    assert "192.168.0.5" in out


def test_single_check_domain_hors_scope(
    capsys: pytest.CaptureFixture[str],
) -> None:
    """
    Domaine résout, mais aucune IP in-scope -> message 'Hors scope' (B5).
    """
    fake = _FakeResolver({("nocontent.example", "A"): ["8.8.8.8"]})
    izinscope.ONLY_DOMAIN = False

    izinscope.single_check(
        "nocontent.example", networks=[], ips_map={}, resolver=fake
    )

    out = capsys.readouterr().out
    assert "Hors scope" in out
    assert "8.8.8.8" in out
    assert "[-]" in out


def test_single_check_domain_unresolvable(
    capsys: pytest.CaptureFixture[str],
) -> None:
    """
    Domaine qui ne résout vers rien -> 'Aucune IP résolue.'
    """
    fake = _FakeResolver({})
    izinscope.ONLY_DOMAIN = False

    izinscope.single_check(
        "nxdomain.example", networks=[], ips_map={}, resolver=fake
    )

    out = capsys.readouterr().out
    assert "Aucune IP résolue." in out
    assert "[-]" in out


def test_single_check_logfile_receives_output(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """
    Quand logfile est fourni, single_check y écrit aussi (B4).
    """
    networks = [(ipaddress.ip_network("192.168.0.0/24"), "192.168.0.0/24", "scope.txt")]
    izinscope.ONLY_DOMAIN = False
    log_path = tmp_path / "run.log"

    with open(log_path, "w", encoding="utf-8") as fh:
        izinscope.single_check(
            "192.168.0.5", networks, ips_map={}, resolver=None, logfile=fh
        )

    content = log_path.read_text()
    assert "192.168.0.5" in content
    assert "résout vers" in content


# ---------------------------------------------------------------------------
# write_output
# ---------------------------------------------------------------------------

def test_write_output_txt_and_csv(tmp_path: Path) -> None:
    """
    Vérifie la génération correcte des fichiers TXT et CSV (3 colonnes)
    pour un domaine avec une unique IP.
    """
    data = {
        "example.com": [("93.184.216.34", "entry", "scope.txt")]
    }
    txt_file = tmp_path / "out.txt"
    csv_file = tmp_path / "out.csv"

    izinscope.write_output(txt_file, data, csv=False)
    izinscope.write_output(csv_file, data, csv=True)

    # TXT : l'IP puis le domaine
    assert txt_file.read_text().strip() == "93.184.216.34\nexample.com"

    # CSV : entête + ligne détaillée (3 colonnes)
    csv_lines = csv_file.read_text().splitlines()
    assert csv_lines == [
        "target,entry,file",
        "93.184.216.34,entry,scope.txt",
    ]


def test_write_output_multiple_ips(tmp_path: Path) -> None:
    """
    Vérifie la génération correcte des fichiers TXT et CSV pour un domaine avec plusieurs IP.
    """
    data = {
        "example.net": [
            ("1.1.1.1", "entry", "scope1.txt"),
            ("2.2.2.2", "entry", "scope1.txt"),
        ]
    }
    txt_file = tmp_path / "out.txt"
    izinscope.write_output(txt_file, data, csv=False)

    assert txt_file.read_text().strip() == "1.1.1.1\n2.2.2.2\nexample.net"

    # CSV
    csv_file = tmp_path / "out.csv"
    izinscope.write_output(csv_file, data, csv=True)

    csv_lines = csv_file.read_text().splitlines()
    assert csv_lines == [
        "target,entry,file",
        "1.1.1.1,entry,scope1.txt",
        "2.2.2.2,entry,scope1.txt",
    ]
