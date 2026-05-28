import datetime
import logging
import re
import sys

GREEN = "\033[92m"
RED = "\033[91m"
RESET = "\033[0m"

_ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")
logger = logging.getLogger("izinscope")


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
