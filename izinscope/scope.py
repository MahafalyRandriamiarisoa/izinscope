import ipaddress
import os
from pathlib import Path

from .reporting import logger
from .resolver import resolve_domain


def load_scope(scope_file, resolver):
    """Charge un fichier de scope -> (networks, ips_map).

    networks : liste de (network_obj, entry, filename)
    ips_map  : dict ip -> liste de (entry, filename)
    """
    scope_file_str = os.fspath(scope_file)
    networks = []
    ips_map = {}
    with open(scope_file_str, 'r') as f:
        for line in f:
            entry = line.split("#", 1)[0].strip()
            if not entry:
                continue
            try:
                net = ipaddress.ip_network(entry, strict=False)
                networks.append((net, entry, scope_file_str))
            except ValueError:
                _, resolved = resolve_domain(entry, resolver)
                if not resolved:
                    logger.warning(f"Erreur résolution '{entry}' dans {scope_file_str}")
                for ip in resolved:
                    ips_map.setdefault(ip, []).append((entry, scope_file_str))
    return networks, ips_map


def expand_scope_paths(paths):
    """Développe fichiers et dossiers de scope (récursif, fichiers cachés ignorés)."""
    scope_files = []
    for path in paths:
        p = Path(path)
        if p.is_dir():
            for entry in sorted(p.rglob("*")):
                if entry.is_file() and not any(
                    part.startswith(".") for part in entry.relative_to(p).parts
                ):
                    scope_files.append(str(entry))
        else:
            scope_files.append(path)
    return scope_files
