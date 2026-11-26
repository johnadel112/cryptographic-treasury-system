"""One-line logs to terminal and runtime/logs/<program>.log."""
import logging
import os
import re
from pathlib import Path

from .config import LOG_DIR


def get_logger(program: str) -> logging.Logger:
    if not re.fullmatch(r"[A-Za-z0-9_-]+", program):
        raise ValueError("invalid logging identity")
    log_dir = Path(os.environ.get("TREASURY_LOG_DIR", str(LOG_DIR)))
    log_dir.mkdir(parents=True, exist_ok=True)
    logger = logging.getLogger(f"treasury.{program}")
    logger.setLevel(logging.INFO)
    logger.propagate = False
    if logger.handlers:
        return logger
    fmt = logging.Formatter(f"{program:<8s} %(asctime)s  %(message)s", "%Y-%m-%d %H:%M:%S%z")
    stream = logging.StreamHandler()
    stream.setFormatter(fmt)
    file_handler = logging.FileHandler(log_dir / f"{program}.log", encoding="utf-8")
    file_handler.setFormatter(fmt)
    logger.addHandler(stream)
    logger.addHandler(file_handler)
    return logger
