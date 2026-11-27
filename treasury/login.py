"""Essam's Schnorr login, migrated to the official GROUP-bound encoding."""
import secrets
from pathlib import Path
from .config import P, Q, G
from .encoding import H, hex_int
from .identity import validate_name, write_new


def register_login_secret(name: str, p: int = P, q: int = Q, g: int = G) -> tuple[int, int]:
    validate_name(name)
    x = secrets.randbelow(q - 1) + 1
    return x, pow(g, x, p)


def load_login_secret(name: str, root: Path) -> int:
    validate_name(name)
    path = root / name / "login.secret"
    if not path.exists():
        x, _ = register_login_secret(name)
        try:
            write_new(path, format(x, "x").encode(), private=True)
        except FileExistsError:
            pass
    return hex_int(path.read_text("ascii"), limit=Q, nonzero=True)


def make_commitment() -> tuple[int, int]:
    k = secrets.randbelow(Q - 1) + 1
    return k, pow(G, k, P)


def make_interactive_response(x_M: int, challenge: int, q: int = Q, *, k: int) -> int:
    """Use the SAME k that produced the previously sent R."""
    if not 0 < x_M < q or not 0 < k < q or not 0 <= challenge < (1 << 128):
        raise ValueError("invalid login scalar/challenge")
    return (k + challenge * x_M) % q


def verify_interactive_login(R: int, z: int, e: int, X_M: int,
                             p: int = P, q: int = Q, g: int = G) -> bool:
    return (all(type(v) is int for v in (R, z, e, X_M)) and
            1 < R < p and 1 < X_M < p and pow(R, q, p) == pow(X_M, q, p) == 1 and
            0 <= z < q and 0 <= e < q and pow(g, z, p) == R * pow(X_M, e, p) % p)


def make_noninteractive_response(name: str, x_M: int, nonce: int) -> dict:
    k, R = make_commitment()
    e = H("login", name, pow(G, x_M, P), R, nonce, q=Q)
    return {"R": format(R, "x"), "z": format((k + e*x_M) % Q, "x")}
