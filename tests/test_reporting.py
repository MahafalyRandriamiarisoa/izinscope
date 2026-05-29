"""
Tests des sorties (output.py) et de la configuration de logs (reporting.py).

Contient un test-bug ROUGE : le CSV doit rester parsable quand un champ
contient une virgule (échappement RFC 4180), ce que la concaténation manuelle
actuelle casse.
"""

from __future__ import annotations

import csv
import logging
from pathlib import Path

import izinscope
from izinscope.reporting import _PlainFormatter, configure_logging


# ---------------------------------------------------------------------------
# write_output — CSV / TXT
# ---------------------------------------------------------------------------


def test_write_csv_header_present_when_empty(tmp_path: Path) -> None:
    """Le header CSV est écrit même sans donnée."""
    out = tmp_path / "out.csv"
    izinscope.write_output(out, {}, csv=True)

    assert out.read_text().splitlines() == ["domain,ip,entry,file"]


def test_write_txt_empty_dict_empty_file(tmp_path: Path) -> None:
    """Un dict vide produit un fichier TXT vide."""
    out = tmp_path / "out.txt"
    izinscope.write_output(out, {}, csv=False)

    assert out.read_text() == ""


def test_write_csv_uses_basename(tmp_path: Path) -> None:
    """La colonne 'file' du CSV ne contient que le basename du fichier source."""
    out = tmp_path / "out.csv"
    data = {"ex.com": [izinscope.Match("1.1.1.1", "entry", "/abs/path/scope.txt")]}
    izinscope.write_output(out, data, csv=True)

    rows = list(csv.reader(out.read_text().splitlines()))
    assert rows[1] == ["ex.com", "1.1.1.1", "entry", "scope.txt"]


def test_write_csv_quotes_field_with_comma(tmp_path: Path) -> None:
    """BUG #1 (ROUGE) : un champ contenant une virgule doit rester un seul champ."""
    out = tmp_path / "out.csv"
    data = {"ex.com": [izinscope.Match("1.2.3.4", "entry", "/p/scope,with,comma.txt")]}
    izinscope.write_output(out, data, csv=True)

    rows = list(csv.reader(out.read_text().splitlines()))
    assert rows[1] == ["ex.com", "1.2.3.4", "entry", "scope,with,comma.txt"]


# ---------------------------------------------------------------------------
# configure_logging / _PlainFormatter
# ---------------------------------------------------------------------------


def test_configure_logging_quiet_no_stream_handler() -> None:
    """quiet=True (-od) ne pose aucun StreamHandler sur stdout."""
    configure_logging(debug=False, quiet=True)

    stream_handlers = [
        h
        for h in logging.getLogger("izinscope").handlers
        if isinstance(h, logging.StreamHandler)
        and not isinstance(h, logging.FileHandler)
    ]
    assert stream_handlers == []


def test_configure_logging_default_has_stream_handler() -> None:
    """Mode normal : un StreamHandler stdout est présent."""
    configure_logging(debug=False, quiet=False)

    stream_handlers = [
        h
        for h in logging.getLogger("izinscope").handlers
        if isinstance(h, logging.StreamHandler)
        and not isinstance(h, logging.FileHandler)
    ]
    assert len(stream_handlers) == 1


def test_plain_formatter_strips_ansi() -> None:
    """_PlainFormatter retire les codes couleur ANSI du message."""
    record = logging.LogRecord(
        name="izinscope",
        level=logging.INFO,
        pathname=__file__,
        lineno=1,
        msg=f"{izinscope.GREEN}[+]{izinscope.RESET} ok",
        args=(),
        exc_info=None,
    )

    assert _PlainFormatter().format(record) == "[+] ok"
