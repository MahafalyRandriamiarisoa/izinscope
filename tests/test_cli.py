"""
Tests d'intégration de la CLI (izinscope.main()).

Chaque test invoque main() via la fixture `invoke` (cf. conftest.py), qui
patche sys.argv et dns.resolver.Resolver. Les bugs corrigés en P0/P1 ont
ici une régression nommée pour empêcher leur réintroduction.
"""
from __future__ import annotations

from importlib.metadata import version
from pathlib import Path

import pytest


def _write_scope(tmp_path: Path, content: str = "192.168.0.0/24\n") -> Path:
    scope = tmp_path / "scope.txt"
    scope.write_text(content)
    return scope


def test_cli_version_matches_package(invoke, capsys) -> None:
    """B6 : -V affiche la version réelle du paquet, pas une chaîne figée."""
    with pytest.raises(SystemExit) as exc:
        invoke(["-V"])

    assert exc.value.code == 0
    assert capsys.readouterr().out.strip() == f"izinscope {version('izinscope')}"


def test_cli_i_ip_match(invoke, tmp_path, capsys) -> None:
    """-i sur une IP in-scope affiche [+] et l'arbre de correspondance."""
    scope = _write_scope(tmp_path)

    invoke(["-s", str(scope), "-i", "192.168.0.5"])

    out = capsys.readouterr().out
    assert "[+]" in out
    assert "192.168.0.5" in out
    assert "192.168.0.0/24" in out


def test_cli_i_writes_output_files(invoke, tmp_path) -> None:
    """B2 : -i honore -oT et -oC (ignorés avant le fix)."""
    scope = _write_scope(tmp_path)
    txt = tmp_path / "out.txt"
    csv = tmp_path / "out.csv"

    invoke(["-s", str(scope), "-i", "192.168.0.5", "-oT", str(txt), "-oC", str(csv)])

    assert txt.exists()
    assert csv.exists()
    csv_text = csv.read_text()
    assert "192.168.0.5" in csv_text
    assert csv_text.splitlines()[0] == "domain,ip,entry,file"


def test_cli_i_od_prints_only_target(invoke, tmp_path, capsys) -> None:
    """B3 : -od combiné à -i n'affiche que la cible, sans l'arbre."""
    scope = _write_scope(tmp_path)

    invoke(["-s", str(scope), "-i", "192.168.0.5", "-od"])

    assert capsys.readouterr().out.strip() == "192.168.0.5"


def test_cli_i_hors_scope_message(invoke, tmp_path, capsys) -> None:
    """B5 : une IP résolue mais hors scope affiche 'Hors scope'."""
    scope = _write_scope(tmp_path)

    invoke(["-s", str(scope), "-i", "8.8.8.8"])

    out = capsys.readouterr().out
    assert "Hors scope" in out
    assert "8.8.8.8" in out


def test_cli_d_mixed(invoke, tmp_path, capsys) -> None:
    """Boucle -d : un domaine in-scope ([+]) et un hors scope ([-])."""
    scope = _write_scope(tmp_path)
    doms = tmp_path / "d.txt"
    doms.write_text("in.example\nout.example\n")

    invoke(
        ["-s", str(scope), "-d", str(doms)],
        {
            ("in.example", "A"): ["192.168.0.5"],
            ("out.example", "A"): ["8.8.8.8"],
        },
    )

    out = capsys.readouterr().out
    assert "[+]" in out
    assert "[-]" in out
    assert "in.example" in out
    assert "out.example" in out


def test_cli_d_out_of_scope_single_line(invoke, tmp_path, capsys) -> None:
    """B1 : un domaine hors scope ne doit produire qu'une seule ligne."""
    scope = _write_scope(tmp_path)
    doms = tmp_path / "d.txt"
    doms.write_text("oos.example\n")

    invoke(
        ["-s", str(scope), "-d", str(doms)],
        {("oos.example", "A"): ["8.8.8.8"]},
    )

    out = capsys.readouterr().out
    assert out.count("oos.example") == 1


def test_cli_d_unresolved_domain(invoke, tmp_path, capsys) -> None:
    """Un domaine sans résolution affiche 'Aucune IP résolue.'."""
    scope = _write_scope(tmp_path)
    doms = tmp_path / "d.txt"
    doms.write_text("nxdomain.example\n")

    invoke(["-s", str(scope), "-d", str(doms)], {})

    out = capsys.readouterr().out
    assert "Aucune IP résolue." in out
    assert "nxdomain.example" in out


def test_cli_debug_creates_logfile(invoke, tmp_path, monkeypatch) -> None:
    """B4 : --debug crée un fichier log non vide, sans codes couleur ANSI (B14)."""
    monkeypatch.chdir(tmp_path)
    scope = _write_scope(tmp_path)

    invoke(["-s", str(scope), "-i", "192.168.0.5", "--debug"])

    logs = list(tmp_path.glob("log_izinscope_*.log"))
    assert len(logs) == 1
    content = logs[0].read_text()
    assert content.strip()
    assert "192.168.0.5" in content
    assert "\x1b[" not in content


def test_cli_scope_directory_expansion(invoke, tmp_path, capsys) -> None:
    """-s sur un dossier charge bien tous les fichiers de scope qu'il contient."""
    scope_dir = tmp_path / "scopes"
    scope_dir.mkdir()
    (scope_dir / "a.txt").write_text("192.168.0.0/24\n")
    (scope_dir / "b.txt").write_text("10.0.0.0/8\n")

    invoke(["-s", str(scope_dir), "-i", "10.1.2.3"])

    out = capsys.readouterr().out
    assert "[+]" in out
    assert "10.0.0.0/8" in out


def test_cli_scope_directory_recursive(invoke, tmp_path, capsys) -> None:
    """B12 : les fichiers de scope dans un sous-dossier sont chargés."""
    scope_dir = tmp_path / "scopes"
    nested = scope_dir / "nested"
    nested.mkdir(parents=True)
    (nested / "b.txt").write_text("10.0.0.0/8\n")

    invoke(["-s", str(scope_dir), "-i", "10.1.2.3"])

    out = capsys.readouterr().out
    assert "[+]" in out
    assert "10.0.0.0/8" in out


def test_cli_scope_directory_ignores_dotfiles(invoke, tmp_path, capsys) -> None:
    """B12 : un fichier caché dans le dossier de scope n'est pas chargé."""
    scope_dir = tmp_path / "scopes"
    scope_dir.mkdir()
    (scope_dir / "a.txt").write_text("192.168.0.0/24\n")
    (scope_dir / ".secret.txt").write_text("10.0.0.0/8\n")

    # 10.1.2.3 n'existe que dans le dotfile -> doit rester hors scope
    invoke(["-s", str(scope_dir), "-i", "10.1.2.3"])

    out = capsys.readouterr().out
    assert "Hors scope" in out
