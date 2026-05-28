"""Fixtures partagées pour la suite de tests izinscope."""
from __future__ import annotations

import sys

import pytest

import izinscope


@pytest.fixture(autouse=True)
def _reset_only_domain():
    """Isole le global ONLY_DOMAIN entre les tests (cf. B16)."""
    izinscope.ONLY_DOMAIN = False
    yield
    izinscope.ONLY_DOMAIN = False


class _FakeRdata:
    """Objet minimal possédant la méthode .to_text() attendue par resolve()."""

    def __init__(self, value: str) -> None:
        self._value = value

    def to_text(self) -> str:
        return self._value


class _FakeResolver:
    """Remplace dns.resolver.Resolver pour des tests déterministes."""

    def __init__(self, mapping: dict[tuple[str, str], list[str]] | None = None) -> None:
        # mapping : (domain, record) -> [ip, ...]
        self._mapping = mapping or {}

    def resolve(self, domain: str, record: str):
        key = (domain, record)
        if key not in self._mapping:
            raise izinscope.dns.resolver.NoAnswer()
        return [_FakeRdata(ip) for ip in self._mapping[key]]


@pytest.fixture
def fake_resolver():
    """Renvoie la classe _FakeResolver (factory à instancier avec un mapping)."""
    return _FakeResolver


@pytest.fixture
def invoke(monkeypatch, fake_resolver):
    """Invoque izinscope.main() avec sys.argv patché et un résolveur factice.

    `argv` est la liste d'arguments SANS le nom du programme.
    `mapping` alimente le _FakeResolver pour les chemins qui résolvent du DNS.
    """

    def _invoke(argv, mapping=None):
        fake = fake_resolver(mapping)
        monkeypatch.setattr(izinscope.dns.resolver, "Resolver", lambda: fake)
        monkeypatch.setattr(sys, "argv", ["izinscope", *argv])
        izinscope.main()

    return _invoke
