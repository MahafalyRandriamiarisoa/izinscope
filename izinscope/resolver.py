import dns.exception
import dns.resolver

from .reporting import logger


def resolve_domain(domain, resolver):
    """Résout les enregistrements A et AAAA d'un domaine -> (domain, [ip, ...]).

    Les erreurs DNS (NXDOMAIN, timeout, ...) sont journalisées en debug et ne
    lèvent pas ; les exceptions non-DNS, elles, remontent (pas de catch large).
    """
    ips = set()
    for record in ["A", "AAAA"]:
        try:
            answers = resolver.resolve(domain, record)
            for rdata in answers:
                ips.add(rdata.to_text())
        except dns.resolver.NoAnswer:
            continue
        except dns.resolver.NXDOMAIN:
            logger.debug(f"{domain}: NXDOMAIN")
            break
        except dns.exception.DNSException as exc:
            logger.debug(f"{domain} ({record}): {exc.__class__.__name__}")
    return domain, list(ips)
