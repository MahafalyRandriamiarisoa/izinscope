import ipaddress
import os
from concurrent.futures import ThreadPoolExecutor

from .models import Match
from .reporting import logger, GREEN, RED, RESET
from .resolver import resolve_domain


def match_ips(ips, networks, ips_map):
    """Retourne les Match des IP données contre le scope (networks + ips_map)."""
    matches = []
    for ip in ips:
        try:
            ip_obj = ipaddress.ip_address(ip)
        except ValueError:
            logger.warning(f"IP invalide ignorée : {ip}")
            continue
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


def single_check(target, networks, ips_map, resolver):
    """Vérifie un domaine ou une IP unique ; renvoie {target: [Match, ...]} ou {}."""
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


def check_domains(targets, networks, ips_map, resolver):
    """Vérifie une liste de domaines en parallèle ; renvoie {domain: [Match, ...]}."""
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
