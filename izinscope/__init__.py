#!/usr/bin/env python3
"""izinscope : vérifie si des IP/domaines sont dans un scope défini."""
from importlib.metadata import version as _pkg_version, PackageNotFoundError

try:
    __version__ = _pkg_version("izinscope")
except PackageNotFoundError:
    __version__ = "unknown"

import dns.resolver  # exposé en izinscope.dns (monkeypatch dans les tests)

from .models import Match
from .reporting import GREEN, RED, RESET, configure_logging, logger
from .resolver import resolve_domain
from .scope import expand_scope_paths, load_scope
from .checker import check_domains, match_ips, single_check
from .output import write_output
from .cli import build_parser, main

__all__ = [
    "__version__",
    "Match",
    "configure_logging",
    "logger",
    "resolve_domain",
    "load_scope",
    "expand_scope_paths",
    "match_ips",
    "single_check",
    "check_domains",
    "write_output",
    "build_parser",
    "main",
    "GREEN",
    "RED",
    "RESET",
]
