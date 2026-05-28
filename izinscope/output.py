import os


def write_output(filename, data, csv=False):
    """Écrit {domain: [Match, ...]} en TXT (1 domaine/ligne) ou CSV (4 colonnes)."""
    with open(filename, 'w', encoding='utf-8') as f:
        if csv:
            f.write("domain,ip,entry,file\n")
            for domain, matches in data.items():
                for m in matches:
                    f.write(f"{domain},{m.ip},{m.entry},{os.path.basename(m.source_file)}\n")
        else:
            for domain in data:
                f.write(domain + "\n")
