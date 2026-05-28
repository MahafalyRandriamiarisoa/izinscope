from dataclasses import dataclass


@dataclass(frozen=True)
class Match:
    """Une IP in-scope avec l'entrée de scope qui la couvre et son fichier."""

    ip: str
    entry: str
    source_file: str
