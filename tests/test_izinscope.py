"""
Tests unitaires pour le module izinscope.

Le réseau et le système de fichiers réels sont systématiquement
mockés pour garantir des tests rapides, reproductibles et hors-ligne.
"""
from __future__ import annotations

import io
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
            # Simule l'exception NoAnswer du resolver réel
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

def test_load_scope_mixed_entries(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """
    Mélange CIDR + domaine dans le fichier de scope.

    On patch socket.gethostbyname_ex pour renvoyer une IP prédictible.
    """
    scope_file = tmp_path / "scope.txt"
    scope_file.write_text(textwrap.dedent("""\
        10.0.0.0/8
        example.org
    """))

    def fake_gethostbyname_ex(host: str):  # noqa: D401
        if host == "example.org":
            return ("example.org", [], ["93.184.216.34"])
        raise OSError  # n'est pas censé arriver dans ce test

    monkeypatch.setattr(izinscope.socket, "gethostbyname_ex", fake_gethostbyname_ex)

    nets, ip_map = izinscope.load_scope(scope_file)

    # 1) réseau CIDR correctement interprété
    cidrs = {str(n[0]) for n in nets}
    assert "10.0.0.0/8" in cidrs
    print("AAAA")
    print(scope_file)
    # 2) domaine résolu stocké dans ip_map
    assert ip_map == {
        "93.184.216.34": [("example.org", str(scope_file))]
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

    izinscope.single_check("192.168.0.5", networks, ips_map={})

    out = capsys.readouterr().out
    assert "[+]" in out
    assert "192.168.0.5" in out


def test_single_check_domain_no_match(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """
    Domaine résout hors scope -> préfixe [-] + 'Aucune IP résolue.'
    (cf. early return dans le code).
    """
    def fake_gethostbyname_ex(host: str):  # noqa: D401
        return (host, [], ["8.8.8.8"])

    monkeypatch.setattr(izinscope.socket, "gethostbyname_ex", fake_gethostbyname_ex)
    izinscope.ONLY_DOMAIN = False

    izinscope.single_check("nocontent.example", networks=[], ips_map={})

    out = capsys.readouterr().out
    assert "Aucune IP résolue." in out
    assert "[-]" in out


# ---------------------------------------------------------------------------
# write_output
# ---------------------------------------------------------------------------

def test_write_output_txt_and_csv(tmp_path: Path) -> None:
    """
    Vérifie la génération correcte des fichiers TXT et CSV.
    """
    data = {
        "example.com": [("93.184.216.34", "entry", "/dir/scope.txt")]
    }
    txt_file = tmp_path / "out.txt"
    csv_file = tmp_path / "out.csv"

    izinscope.write_output(txt_file, data, csv=False)
    izinscope.write_output(csv_file, data, csv=True)

    # TXT = un domaine par ligne
    assert txt_file.read_text().strip() == "example.com"

    # CSV = en-tête + ligne détaillée
    csv_lines = csv_file.read_text().splitlines()
    assert csv_lines[0] == "domain,ip,entry,file"
    assert csv_lines[1].split(",")[:2] == ["example.com", "93.184.216.34"]
    assert csv_lines[1].endswith("scope.txt")