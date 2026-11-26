"""Shared, non-secret project configuration."""
from pathlib import Path

# Student IDs sorted numerically and joined with hyphens.
GROUP = "16002216-16003727-16004417-16005162"

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
    "no-encryption",
}

CHANNEL_WEAKNESSES = ("unsigned-handshake", "no-encryption")
CERTIFICATE_EXPIRY = "2026-12-31"
# https://www.rfc-editor.org/rfc/rfc3526 section 3, group 14. The assignment uses subgroup generator 4.
P = int("""
FFFFFFFF FFFFFFFF C90FDAA2 2168C234 C4C6628B 80DC1CD1
29024E08 8A67CC74 020BBEA6 3B139B22 514A0879 8E3404DD
EF9519B3 CD3A431B 302B0A6D F25F1437 4FE1356D 6D51C245
E485B576 625E7EC6 F44C42E9 A637ED6B 0BFF5CB6 F406B7ED
EE386BFB 5A899FA5 AE9F2411 7C4B1FE6 49286651 ECE45B3D
C2007CB8 A163BF05 98DA4836 1C55D39A 69163FA8 FD24CF5F
83655D23 DCA3AD96 1C62F356 208552BB 9ED52907 7096966D
670C354E 4ABC9804 F1746C08 CA18217C 32905E46 2E36CE3B
E39E772C 180E8603 9B2783A2 EC07A28F B5C55DF0 6F4C52C9
DE2BCBF6 95581718 3995497C EA956AE5 15D22618 98FA0510
15728E5A 8AACAA68 FFFFFFFF FFFFFFFF
""".replace(" ", "").replace("\n", ""), 16)
Q = (P - 1) // 2
G = 4


def member_names(n: int = DEFAULT_N) -> tuple[str, ...]:
    if type(n) is not int or n < 1:
        raise ValueError("member count must be a positive integer")
    return tuple(f"M{i}" for i in range(1, n + 1))


def valid_group_element(value: int) -> bool:
    return type(value) is int and 1 < value < P and pow(value, Q, P) == 1


def validate_group() -> None:
    if not GROUP or GROUP.startswith("REPLACE-"):
        raise RuntimeError("Set GROUP in treasury/config.py before running the project")
