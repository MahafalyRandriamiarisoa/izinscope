import dns.resolver


def resolve_domain(domain, resolver):
    """Résout les enregistrements A et AAAA d'un domaine -> (domain, [ip, ...])."""
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
