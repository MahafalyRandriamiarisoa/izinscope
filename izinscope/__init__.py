#!/usr/bin/env python3
import argparse
import ipaddress
import datetime
import os
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



def log(msg, logfile=None):
    if not ONLY_DOMAIN:
        print(msg)
    if logfile:
        logfile.write(msg + "\n")

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

# Charge un fichier de scope et renvoie:
# - liste de tuples (network_obj, entry, filename)
# - dict mapping ip -> list of (entry, filename)
def load_scope(scope_file, resolver):
    # Accept both `str` and `pathlib.Path` inputs.  Convert once to a plain
    # string so that internal data structures always contain the same type
    # (this helps comparisons in tests that expect a `str`).
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
                    log(f"Erreur résolution '{entry}' dans {scope_file_str}")
                for ip in resolved:
                    ips_map.setdefault(ip, []).append((entry, scope_file_str))
    return networks, ips_map

# Vérifie un domaine ou une IP unique
# Affiche détails et fichier source

def single_check(target, networks, ips_map, resolver, logfile=None):
    try:
        ipaddress.ip_address(target)
        resolved_ips = [target]
    except ValueError:
        _, resolved_ips = resolve_domain(target, resolver)

    if not resolved_ips:
        log(f"{RED}[-]{RESET} {target} : Aucune IP résolue.", logfile)
        return {}

    matches = []
    for ip in resolved_ips:
        ip_obj = ipaddress.ip_address(ip)
        for net, entry, fname in networks:
            if ip_obj in net:
                matches.append((ip, entry, fname))
        if ip in ips_map:
            for entry, fname in ips_map[ip]:
                matches.append((ip, entry, fname))

    if not matches:
        red_list = ", ".join(f"{RED}{ip}{RESET}" for ip in resolved_ips)
        log(f"{RED}[-]{RESET} {target} : Hors scope [{red_list}]", logfile)
        return {}

    log(f"{GREEN}[+]{RESET} {target} résout vers:", logfile)
    for idx, (ip, entry, fname) in enumerate(matches):
        char = "├─" if idx < len(matches) - 1 else "└─"
        log(f" {char} {ip} -> {entry} ({os.path.basename(fname)})", logfile)
    return {target: matches}

# Écrit les résultats dans un fichier (txt ou csv)
def write_output(filename, data, csv=False):
    with open(filename, 'w', encoding='utf-8') as f:
        if csv:
            f.write("domain,ip,entry,file\n")
            for domain, matches in data.items():
                for ip, entry, fname in matches:
                    f.write(f"{domain},{ip},{entry},{os.path.basename(fname)}\n")
        else:
            for domain in data:
                f.write(domain + "\n")


def main():
    parser = argparse.ArgumentParser(description="Izinscope : Check IP/domain vs scope")
    parser.add_argument(
        "-s", "--scope", required=True,
        action='append',
        help="Fichier ou dossier de scope (CIDR/IP/domaines). Peut être utilisé plusieurs fois"
    )
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("-d", "--domains-to-check", help="Fichier domaines à vérifier")
    group.add_argument("-i", "--single-check", help="Domaine ou IP unique à vérifier")
    parser.add_argument("--debug", action="store_true", help="Mode debug (logs détaillés)")
    parser.add_argument("-oT", "--output-txt", help="Sortie txt (domaines uniquement)")
    parser.add_argument("-oC", "--output-csv", help="Sortie csv (domain,ip,entry,file)")
    parser.add_argument("-V", "--version", action="version", version=f"izinscope {__version__}")
    # stdout options for only domain --only-domain
    parser.add_argument("-od",'--only-domain', action='store_true', help="Afficher uniquement les domaines dans la sortie")

    

    args = parser.parse_args()
    global ONLY_DOMAIN
    ONLY_DOMAIN = args.only_domain
    # Expansion des scopes: fichiers et dossiers (récursif, fichiers cachés ignorés)
    scope_files = []
    for path in args.scope:
        p = Path(path)
        if p.is_dir():
            for entry in sorted(p.rglob("*")):
                if entry.is_file() and not any(
                    part.startswith(".") for part in entry.relative_to(p).parts
                ):
                    scope_files.append(str(entry))
        else:
            scope_files.append(path)

    resolver = dns.resolver.Resolver()
    resolver.timeout = 3
    resolver.lifetime = 3

    # Charger et cumuler tous les scopes
    allowed_networks = []
    allowed_ips_map = {}
    for scope_file in scope_files:
        nets, ips = load_scope(scope_file, resolver)
        allowed_networks.extend(nets)
        for ip, entries in ips.items():
            allowed_ips_map.setdefault(ip, []).extend(entries)

    logfile = None
    if args.debug:
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        logfile = open(f"log_izinscope_{timestamp}.log", 'w', encoding='utf-8')

    if args.single_check:
        inscope_results = single_check(args.single_check, allowed_networks, allowed_ips_map, resolver, logfile)
    else:
        with open(args.domains_to_check, 'r', encoding='utf-8') as f:
            targets = [l.strip() for l in f if l.strip()]

        inscope_results = {}
        with ThreadPoolExecutor(max_workers=10) as executor:
            for domain, ips in executor.map(lambda d: resolve_domain(d, resolver), targets):
                if not ips:
                    log(f"{RED}[-]{RESET} {domain} : Aucune IP résolue.", logfile)
                    continue

                matches_for_domain = []
                colored_ips = []
                for ip in ips:
                    ip_obj = ipaddress.ip_address(ip)
                    descs = []
                    for net, entry, fname in allowed_networks:
                        if ip_obj in net:
                            descs.append((ip, entry, fname))
                    if ip in allowed_ips_map:
                        for entry, fname in allowed_ips_map[ip]:
                            descs.append((ip, entry, fname))
                    if descs:
                        colored_ips.append(f"{GREEN}{ip}{RESET}")
                        matches_for_domain.extend(descs)
                    else:
                        colored_ips.append(f"{RED}{ip}{RESET}")

                prefix = f"{GREEN}[+]{RESET}" if matches_for_domain else f"{RED}[-]{RESET}"
                log(f"{prefix} {domain} : [{', '.join(colored_ips)}]", logfile)

                if matches_for_domain:
                    for idx, (ip, entry, fname) in enumerate(matches_for_domain):
                        char = "├─" if idx < len(matches_for_domain) - 1 else "└─"
                        log(f" {char} {ip} -> {entry} ({os.path.basename(fname)})")
                    inscope_results[domain] = matches_for_domain

    # Sortie CSV : domaine,ip,entry,file
    if args.output_csv:
        write_output(args.output_csv, inscope_results, csv=True)
        log(f"Fichier CSV '{args.output_csv}' créé.", logfile)

    # Sortie TXT : "domaines/IPs uniques"
    if args.output_txt:
        write_output(args.output_txt, inscope_results, csv=False)
        log(f"Fichier TXT '{args.output_txt}' créé.", logfile)

    if args.only_domain:
        for domain, matches in inscope_results.items():
            print(domain)

    if logfile:
        logfile.close()

if __name__ == "__main__":
    main()
