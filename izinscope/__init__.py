#!/usr/bin/env python3
import argparse
import ipaddress
import socket
import datetime
import sys
from concurrent.futures import ThreadPoolExecutor
import dns.resolver

GREEN = "\033[92m"
RED = "\033[91m"
RESET = "\033[0m"

def log(msg, logfile=None):
    print(msg)
    if logfile:
        logfile.write(msg + "\n")

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

def load_scope(scope_file):
    allowed_networks = []
    allowed_ips = set()
    with open(scope_file, 'r') as f:
        for line in f:
            entry = line.strip()
            if not entry:
                continue
            try:
                network = ipaddress.ip_network(entry, strict=False)
                allowed_networks.append(network)
            except ValueError:
                try:
                    ips = socket.gethostbyname_ex(entry)[2]
                    allowed_ips.update(ips)
                except Exception as e:
                    print(f"Erreur résolution '{entry}': {e}")
    return allowed_networks, allowed_ips

def is_ip_in_scope(ip, networks, ips):
    ip_obj = ipaddress.ip_address(ip)
    return ip in ips or any(ip_obj in net for net in networks)

def single_check(ip, networks, ips):
    try:
        ip_obj = ipaddress.ip_address(ip)
    except ValueError:
        print(f"{RED}[-]{RESET} {ip} : Adresse IP invalide")
        sys.exit(1)

    matching = [str(net) for net in networks if ip_obj in net]
    if ip in ips:
        matching.append(f"{ip}/32")

    if matching:
        print(f"{GREEN}[+]{RESET} {ip} -> {', '.join(matching)}")
    else:
        print(f"{RED}[-]{RESET} {ip} hors scope.")

def write_output(filename, data, csv=False):
    with open(filename, 'w', encoding='utf-8') as f:
        for domain, ips in data.items():
            line = domain + ("," + ",".join(ips) if csv else "")
            f.write(line + "\n")

def main():
    parser = argparse.ArgumentParser(description="Izinscope : Check IP/domain vs scope")
    parser.add_argument("-s", "--scope", required=True, help="Fichier scope (CIDR/IP/domaines)")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("-d", "--domains-to-check", help="Fichier domaines à vérifier")
    group.add_argument("-i", "--single-check", help="IP unique à vérifier")
    parser.add_argument("--debug", action="store_true", help="Mode debug (logs détaillés)")
    parser.add_argument("-oT", "--output-txt", help="Sortie txt (domaines uniquement)")
    parser.add_argument("-oC", "--output-csv", help="Sortie csv (domaine,ip,...)")
    parser.add_argument('--version', action='version', version='Izinscope 1.1')
    args = parser.parse_args()

    allowed_networks, allowed_ips = load_scope(args.scope)

    logfile = None
    if args.debug:
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        logfile = open(f"log_izinscope_{timestamp}.log", 'w', encoding='utf-8')

    resolver = dns.resolver.Resolver()
    resolver.timeout = 3
    resolver.lifetime = 3

    if args.single_check:
        single_check(args.single_check, allowed_networks, allowed_ips)
        return

    with open(args.domains_to_check, 'r', encoding='utf-8') as f:
        domains = [line.strip() for line in f if line.strip()]

    inscope_results = {}
    with ThreadPoolExecutor(max_workers=10) as executor:
        results = executor.map(lambda d: resolve_domain(d, resolver), domains)

        for domain, ips in results:
            if not ips:
                log(f"{RED}[-]{RESET} {domain} : Aucune IP résolue.", logfile)
                continue

            in_scope_ips = [ip for ip in ips if is_ip_in_scope(ip, allowed_networks, allowed_ips)]
            colored_ips = [f"{GREEN if ip in in_scope_ips else RED}{ip}{RESET}" for ip in ips]

            status = f"{GREEN}[+]{RESET}" if in_scope_ips else f"{RED}[-]{RESET}"
            log(f"{status} {domain} : [{', '.join(colored_ips)}]", logfile)

            if in_scope_ips:
                inscope_results[domain] = in_scope_ips

    if args.output_csv:
        write_output(args.output_csv, inscope_results, csv=True)
        log(f"Fichier CSV '{args.output_csv}' créé.", logfile)

    if args.output_txt:
        write_output(args.output_txt, inscope_results, csv=False)
        log(f"Fichier TXT '{args.output_txt}' créé.", logfile)

    if logfile:
        logfile.close()

if __name__ == "__main__":
    main()
