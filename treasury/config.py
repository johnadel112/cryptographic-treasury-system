"""Shared, non-secret project configuration."""
from pathlib import Path

# TODO: Replace this with the numeric student IDs of the whole group,
# sorted from smallest to largest and joined with hyphens.
GROUP = "5-12-23"

HOST = "127.0.0.1"
SERVER_PORT = 5050
MALLORY_PORT = 6000
MAX_FRAME_BYTES = 4 * 1024 * 1024
SOCKET_TIMEOUT_SECONDS = 10
LOG_DIR = Path("runtime") / "logs"
DATA_DIR = Path("runtime") / "data"

# Project parameters. Keep these configurable; do not hard-code t=3 or n=5
# inside protocol algorithms.
DEFAULT_T = 3
DEFAULT_N = 5
MEMBER_NAMES = tuple(f"M{i}" for i in range(1, DEFAULT_N + 1))

WEAKNESS_NAMES = {
    "unsigned-handshake", "fixed-nonce", "short-challenge", "no-nonce",
    "no-proof", "no-share-check", "unsigned-ballots",
}


def validate_group() -> None:
    if not GROUP or GROUP.startswith("REPLACE-"):
        raise RuntimeError("Set GROUP in treasury/config.py before running the project")
