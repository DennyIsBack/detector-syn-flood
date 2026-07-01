import logging
import os

# Modulo de Registro: centraliza a geracao de logs e alertas em arquivo.
# Eventos normais sao gravados em nivel INFO e alertas de ataque em WARNING.

_LOG_DIR = "logs"
_LOG_FILE = os.path.join(_LOG_DIR, "syn_flood.log")

_logger = None


def get_logger():
    global _logger

    if _logger is not None:
        return _logger

    os.makedirs(_LOG_DIR, exist_ok=True)

    logger = logging.getLogger("syn_flood")
    logger.setLevel(logging.INFO)

    # Evita adicionar handlers duplicados caso a funcao seja chamada mais de uma vez
    if not logger.handlers:
        handler = logging.FileHandler(_LOG_FILE, encoding="utf-8")
        formato = logging.Formatter(
            "%(asctime)s [%(levelname)s] %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S"
        )
        handler.setFormatter(formato)
        logger.addHandler(handler)

    _logger = logger
    return logger
