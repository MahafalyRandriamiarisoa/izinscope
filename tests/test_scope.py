"""
Tests ciblés du chargement de scope (scope.py) et de la résolution (resolver.py).

Complète test_izinscope.py : entrées IPv6 nues, CIDR invalide, fichiers vides,
fins de ligne CRLF, dédup A/AAAA, coupure NXDOMAIN, et expand_scope_paths.
Les fixtures (fake_resolver, _reset_logger) vivent dans conftest.py.
"""

from __future__ import annotations

from pathlib import Path

import izinscope


# ---------------------------------------------------------------------------
# load_scope — types d'entrées
# ---------------------------------------------------------------------------


def test_load_scope_bare_ipv6_becomes_128(tmp_path: Path, fake_resolver) -> None:
    """Une IPv6 nue dans le scope devient un réseau /128."""
    scope = tmp_path / "scope.txt"
    scope.write_text("2001:db8::1\n")

    nets, ip_map = izinscope.load_scope(scope, fake_resolver({}))

    assert "2001:db8::1/128" in {str(n[0]) for n in nets}
    assert ip_map == {}


def test_load_scope_invalid_cidr_is_ignored(tmp_path: Path, fake_resolver) -> None:
    """Un CIDR invalide (/33) échoue le parse réseau puis la résolution -> rien."""
    scope = tmp_path / "scope.txt"
    scope.write_text("192.168.0.1/33\n")

    nets, ip_map = izinscope.load_scope(scope, fake_resolver({}))

    assert nets == []
    assert ip_map == {}


def test_load_scope_empty_file(tmp_path: Path, fake_resolver) -> None:
    """Un fichier de scope vide donne ([], {})."""
    scope = tmp_path / "scope.txt"
    scope.write_text("")

    assert izinscope.load_scope(scope, fake_resolver({})) == ([], {})


def test_load_scope_all_comments(tmp_path: Path, fake_resolver) -> None:
    """Un fichier uniquement composé de commentaires ne crée aucune entrée."""
    scope = tmp_path / "scope.txt"
    scope.write_text("# entête\n   # indenté\n#collé\n")

    assert izinscope.load_scope(scope, fake_resolver({})) == ([], {})


def test_load_scope_crlf_line_endings(tmp_path: Path, fake_resolver) -> None:
    """Les fins de ligne Windows (CRLF) sont correctement nettoyées par strip()."""
    scope = tmp_path / "scope.txt"
    scope.write_bytes(b"10.0.0.0/8\r\n192.168.0.0/24\r\n")

    nets, _ = izinscope.load_scope(scope, fake_resolver({}))

    assert {str(n[0]) for n in nets} == {"10.0.0.0/8", "192.168.0.0/24"}


def test_load_scope_domain_multiple_ips(tmp_path: Path, fake_resolver) -> None:
    """Un domaine résolvant vers plusieurs IP les stocke toutes dans ips_map."""
    scope = tmp_path / "scope.txt"
    scope.write_text("multi.example\n")
    fake = fake_resolver({("multi.example", "A"): ["1.2.3.4", "1.2.3.5"]})

    _, ip_map = izinscope.load_scope(scope, fake)

    assert ip_map == {
        "1.2.3.4": [("multi.example", str(scope))],
        "1.2.3.5": [("multi.example", str(scope))],
    }


def test_load_scope_blank_and_whitespace_lines(tmp_path: Path, fake_resolver) -> None:
    """Lignes vides et purement blanches ignorées."""
    scope = tmp_path / "scope.txt"
    scope.write_text("\n   \n\t\n10.0.0.0/8\n")

    nets, ip_map = izinscope.load_scope(scope, fake_resolver({}))

    assert {str(n[0]) for n in nets} == {"10.0.0.0/8"}
    assert ip_map == {}


# ---------------------------------------------------------------------------
# resolve_domain
# ---------------------------------------------------------------------------


def test_resolve_domain_dedups_a_and_aaaa(fake_resolver) -> None:
    """A et AAAA pointant la même IP -> une seule occurrence (set interne)."""
    fake = fake_resolver(
        {("dup.example", "A"): ["1.2.3.4"], ("dup.example", "AAAA"): ["1.2.3.4"]}
    )

    _, ips = izinscope.resolve_domain("dup.example", fake)

    assert ips == ["1.2.3.4"]


def test_resolve_domain_nxdomain_skips_aaaa() -> None:
    """NXDOMAIN sur A coupe la boucle : la requête AAAA n'est jamais tentée."""
    import dns.resolver

    class _Counter:
        def __init__(self) -> None:
            self.calls: list[str] = []

        def resolve(self, domain, record):
            self.calls.append(record)
            raise dns.resolver.NXDOMAIN()

    counter = _Counter()
    domain, ips = izinscope.resolve_domain("nx.example", counter)

    assert domain == "nx.example"
    assert ips == []
    assert counter.calls == ["A"]


# ---------------------------------------------------------------------------
# expand_scope_paths
# ---------------------------------------------------------------------------


def test_expand_scope_paths_repeated_not_deduped(tmp_path: Path) -> None:
    """Un même chemin passé deux fois est ajouté deux fois (pas de dédup)."""
    f = tmp_path / "s.txt"
    f.write_text("10.0.0.0/8\n")

    assert izinscope.expand_scope_paths([str(f), str(f)]) == [str(f), str(f)]


def test_expand_scope_paths_skips_nested_hidden_dir(tmp_path: Path) -> None:
    """Un sous-dossier caché (.secret/) est entièrement ignoré lors du parcours."""
    root = tmp_path / "scopes"
    (root / "sub").mkdir(parents=True)
    (root / "a.txt").write_text("x")
    (root / ".secret").mkdir()
    (root / ".secret" / "b.txt").write_text("y")
    (root / "sub" / "c.txt").write_text("z")

    result = izinscope.expand_scope_paths([str(root)])

    assert sorted(Path(p).name for p in result) == ["a.txt", "c.txt"]


def test_expand_scope_paths_sorted_order(tmp_path: Path) -> None:
    """Le parcours d'un dossier renvoie les fichiers triés."""
    root = tmp_path / "scopes"
    root.mkdir()
    for name in ["c.txt", "a.txt", "b.txt"]:
        (root / name).write_text("x")

    result = izinscope.expand_scope_paths([str(root)])

    assert [Path(p).name for p in result] == ["a.txt", "b.txt", "c.txt"]
