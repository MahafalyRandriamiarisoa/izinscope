import argparse
import sys

import dns.resolver

from . import __version__
from .checker import check_domains, single_check
from .output import write_output
from .reporting import configure_logging, logger
from .scope import expand_scope_paths, load_scope


def build_parser():
    parser = argparse.ArgumentParser(description="Izinscope : Check IP/domain vs scope")
    parser.add_argument(
        "-s",
        "--scope",
        required=True,
        action="append",
        help="Fichier ou dossier de scope (CIDR/IP/domaines). Peut être utilisé plusieurs fois",
    )
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("-d", "--domains-to-check", help="Fichier domaines à vérifier")
    group.add_argument("-i", "--single-check", help="Domaine ou IP unique à vérifier")
    parser.add_argument(
        "--debug", action="store_true", help="Mode debug (logs détaillés)"
    )
    parser.add_argument(
        "--timeout", type=float, default=3.0, help="Timeout DNS en secondes (défaut: 3)"
    )
    parser.add_argument("-oT", "--output-txt", help="Sortie txt (domaines uniquement)")
    parser.add_argument("-oC", "--output-csv", help="Sortie csv (domain,ip,entry,file)")
    parser.add_argument(
        "-V", "--version", action="version", version=f"izinscope {__version__}"
    )
    parser.add_argument(
        "-od",
        "--only-domain",
        action="store_true",
        help="Afficher uniquement les domaines dans la sortie",
    )
    return parser


def main():
    args = build_parser().parse_args()

    configure_logging(debug=args.debug, quiet=args.only_domain)

    scope_files = expand_scope_paths(args.scope)

    resolver = dns.resolver.Resolver()
    resolver.timeout = args.timeout
    resolver.lifetime = args.timeout

    allowed_networks = []
    allowed_ips_map = {}
    for scope_file in scope_files:
        try:
            nets, ips = load_scope(scope_file, resolver)
        except FileNotFoundError:
            logger.error(f"Fichier de scope introuvable : {scope_file}")
            sys.exit(2)
        allowed_networks.extend(nets)
        for ip, entries in ips.items():
            allowed_ips_map.setdefault(ip, []).extend(entries)

    if args.single_check:
        inscope_results = single_check(
            args.single_check, allowed_networks, allowed_ips_map, resolver
        )
    else:
        try:
            with open(args.domains_to_check, "r", encoding="utf-8") as f:
                targets = [l.strip() for l in f if l.strip()]
        except FileNotFoundError:
            logger.error(f"Fichier de domaines introuvable : {args.domains_to_check}")
            sys.exit(2)
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
