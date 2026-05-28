#!/usr/bin/env python3
import argparse
import ipaddress
import datetime
import logging
import os
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor
from importlib.metadata import version as _pkg_version, PackageNotFoundError
import dns.resolver

try:
    __version__ = _pkg_version("izinscope")
except PackageNotFoundError:
    __version__ = "unknown"

GREEN = "\033[92m"
RED = "\033[91m"
RESET = "\033[0m"

_ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")
logger = logging.getLogger("izinscope")


@dataclass(frozen=True)
class Match:
    """Une IP in-scope avec l'entrée de scope qui la couvre et son fichier."""
    ip: str
    entry: str
    source_file: str


class _PlainFormatter(logging.Formatter):
    """Formatter qui retire les couleurs ANSI (sortie fichier lisible, B14)."""

    def format(self, record):
        return _ANSI_RE.sub("", record.getMessage())


def configure_logging(debug=False, quiet=False):
    """Configure le logger 'izinscope'.

    quiet (-od) coupe la sortie stdout ; debug ajoute un fichier horodaté
    sans codes couleur.
    """
    logger.setLevel(logging.DEBUG)
    logger.handlers.clear()
    logger.propagate = False

    if not quiet:
        stream = logging.StreamHandler(sys.stdout)
        stream.setLevel(logging.INFO)
        stream.setFormatter(logging.Formatter("%(message)s"))
        logger.addHandler(stream)

    if debug:
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        file_handler = logging.FileHandler(
            f"log_izinscope_{timestamp}.log", encoding="utf-8"
        )
        file_handler.setLevel(logging.DEBUG)
        file_handler.setFormatter(_PlainFormatter())
        logger.addHandler(file_handler)


# Résout A/AAAA pour un domaine
def resolve_domain(domain, resolver):
    ips = set()
    for record in ['A', 'AAAA']:
        try:
            answers = resolver.resolve(domain, record)
            for rdata in answers:
                ips.add(rdata.to_text())
        except dns.resolver.NoAnswer:
            continue
        except Exception:
            continue
    return domain, list(ips)


# Charge un fichier de scope et renvoie (networks, ips_map):
# - networks : liste de tuples (network_obj, entry, filename)
# - ips_map  : dict ip -> liste de (entry, filename)
def load_scope(scope_file, resolver):
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


def match_ips(ips, networks, ips_map):
    """Retourne les Match des IP données contre le scope (networks + ips_map)."""
    matches = []
    for ip in ips:
        ip_obj = ipaddress.ip_address(ip)
        for net, entry, fname in networks:
            if ip_obj in net:
                matches.append(Match(ip, entry, fname))
        for entry, fname in ips_map.get(ip, []):
            matches.append(Match(ip, entry, fname))
    return matches


def _log_tree(matches):
    for idx, m in enumerate(matches):
        char = "├─" if idx < len(matches) - 1 else "└─"
        logger.info(f" {char} {m.ip} -> {m.entry} ({os.path.basename(m.source_file)})")


# Vérifie un domaine ou une IP unique ; renvoie {target: [Match, ...]} ou {}
def single_check(target, networks, ips_map, resolver):
    try:
        ipaddress.ip_address(target)
        resolved_ips = [target]
    except ValueError:
        _, resolved_ips = resolve_domain(target, resolver)

    if not resolved_ips:
        logger.info(f"{RED}[-]{RESET} {target} : Aucune IP résolue.")
        return {}

    matches = match_ips(resolved_ips, networks, ips_map)
    if not matches:
        red_list = ", ".join(f"{RED}{ip}{RESET}" for ip in resolved_ips)
        logger.info(f"{RED}[-]{RESET} {target} : Hors scope [{red_list}]")
        return {}

    logger.info(f"{GREEN}[+]{RESET} {target} résout vers:")
    _log_tree(matches)
    return {target: matches}


# Vérifie une liste de domaines en parallèle ; renvoie {domain: [Match, ...]}
def check_domains(targets, networks, ips_map, resolver):
    results = {}
    with ThreadPoolExecutor(max_workers=10) as executor:
        for domain, ips in executor.map(lambda d: resolve_domain(d, resolver), targets):
            if not ips:
                logger.info(f"{RED}[-]{RESET} {domain} : Aucune IP résolue.")
                continue

            matches = match_ips(ips, networks, ips_map)
            matched_ips = {m.ip for m in matches}
            colored_ips = [
                f"{GREEN}{ip}{RESET}" if ip in matched_ips else f"{RED}{ip}{RESET}"
                for ip in ips
            ]
            prefix = f"{GREEN}[+]{RESET}" if matches else f"{RED}[-]{RESET}"
            logger.info(f"{prefix} {domain} : [{', '.join(colored_ips)}]")

            if matches:
                _log_tree(matches)
                results[domain] = matches
    return results


# Écrit les résultats dans un fichier (txt ou csv)
def write_output(filename, data, csv=False):
    with open(filename, 'w', encoding='utf-8') as f:
        if csv:
            f.write("domain,ip,entry,file\n")
            for domain, matches in data.items():
                for m in matches:
                    f.write(f"{domain},{m.ip},{m.entry},{os.path.basename(m.source_file)}\n")
        else:
            for domain in data:
                f.write(domain + "\n")


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


def build_parser():
    parser = argparse.ArgumentParser(description="Izinscope : Check IP/domain vs scope")
    parser.add_argument(
        "-s", "--scope", required=True, action='append',
        help="Fichier ou dossier de scope (CIDR/IP/domaines). Peut être utilisé plusieurs fois"
    )
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("-d", "--domains-to-check", help="Fichier domaines à vérifier")
    group.add_argument("-i", "--single-check", help="Domaine ou IP unique à vérifier")
    parser.add_argument("--debug", action="store_true", help="Mode debug (logs détaillés)")
    parser.add_argument("-oT", "--output-txt", help="Sortie txt (domaines uniquement)")
    parser.add_argument("-oC", "--output-csv", help="Sortie csv (domain,ip,entry,file)")
    parser.add_argument("-V", "--version", action="version", version=f"izinscope {__version__}")
    parser.add_argument("-od", "--only-domain", action='store_true',
                        help="Afficher uniquement les domaines dans la sortie")
    return parser


def main():
    args = build_parser().parse_args()

    configure_logging(debug=args.debug, quiet=args.only_domain)

    scope_files = expand_scope_paths(args.scope)

    resolver = dns.resolver.Resolver()
    resolver.timeout = 3
    resolver.lifetime = 3

    allowed_networks = []
    allowed_ips_map = {}
    for scope_file in scope_files:
        nets, ips = load_scope(scope_file, resolver)
        allowed_networks.extend(nets)
        for ip, entries in ips.items():
            allowed_ips_map.setdefault(ip, []).extend(entries)

    if args.single_check:
        inscope_results = single_check(
            args.single_check, allowed_networks, allowed_ips_map, resolver
        )
    else:
        with open(args.domains_to_check, 'r', encoding='utf-8') as f:
            targets = [l.strip() for l in f if l.strip()]
        inscope_results = check_domains(
            targets, allowed_networks, allowed_ips_map, resolver
        )

    if args.output_csv:
        write_output(args.output_csv, inscope_results, csv=True)
        logger.info(f"Fichier CSV '{args.output_csv}' créé.")

    if args.output_txt:
        write_output(args.output_txt, inscope_results, csv=False)
        logger.info(f"Fichier TXT '{args.output_txt}' créé.")

    if args.only_domain:
        for domain in inscope_results:
            print(domain)


if __name__ == "__main__":
    main()
