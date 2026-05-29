import csv as _csv
import os


def write_output(filename, data, csv=False):
    """Écrit {domain: [Match, ...]} en TXT (1 domaine/ligne) ou CSV (4 colonnes).

    Le CSV passe par csv.writer : les champs contenant une virgule (chemins,
    entrées) sont échappés au lieu de décaler les colonnes.
    """
    with open(filename, "w", encoding="utf-8", newline="") as f:
        if csv:
            writer = _csv.writer(f)
            writer.writerow(["domain", "ip", "entry", "file"])
            for domain, matches in data.items():
                for m in matches:
                    writer.writerow(
                        [domain, m.ip, m.entry, os.path.basename(m.source_file)]
                    )
        else:
            for domain in data:
                f.write(domain + "\n")
