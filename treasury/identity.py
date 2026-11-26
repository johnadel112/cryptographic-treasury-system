"""Owner-local identity storage; founder only reads published public keys."""
from dataclasses import dataclass
import json
import os
from pathlib import Path
import re
import secrets

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from .certificates import check_certificate, load_public, public_pem, require_p256
from .config import DATA_DIR

# P-256 order. Explicit secrets randomness also meets the course's RNG rule.
P256_ORDER = int("ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551", 16)


def generate_private_key():
    return ec.derive_private_key(secrets.randbelow(P256_ORDER - 1) + 1, ec.SECP256R1())


def validate_name(name: str) -> str:
    if not isinstance(name, str) or not re.fullmatch(r"founder|server|M[1-9][0-9]*", name):
        raise ValueError("identity must be founder, server or M<positive integer>")
    return name


def write_new(path: Path, data: bytes, *, private: bool = False) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600 if private else 0o644)
    with os.fdopen(fd, "wb") as stream:
        stream.write(data)


def initialize_identity(name: str, root: Path = DATA_DIR):
    """Called only by the identity's own program. Never replaces existing keys."""
    validate_name(name)
    own = root / name
    own.mkdir(parents=True, exist_ok=True, mode=0o700)
    path = own / "identity.key"
    if path.exists():
        key = load_private(name, root)
    else:
        key = generate_private_key()
        write_new(path, key.private_bytes(serialization.Encoding.PEM,
                  serialization.PrivateFormat.PKCS8, serialization.NoEncryption()), private=True)
    published = root / "public" / (name + ".pub")
    data = public_pem(key.public_key()).encode("ascii")
    if published.exists():
        if published.read_bytes() != data:
            raise ValueError("published key differs from owner's key; refusing overwrite")
    else:
        write_new(published, data)
    return key


def load_private(name: str, root: Path = DATA_DIR):
    validate_name(name)
    return require_p256(serialization.load_pem_private_key(
        (root / name / "identity.key").read_bytes(), password=None))


@dataclass
class Identity:
    name: str
    private_key: ec.EllipticCurvePrivateKey
    certificate: dict
    founder_public_key: ec.EllipticCurvePublicKey


def load_identity(name: str, root: Path = DATA_DIR) -> Identity:
    private = load_private(name, root)
    founder = load_public((root / "public" / "founder.pub").read_text("ascii"))
    cert = json.loads((root / "public" / (name + ".cert.json")).read_text("utf-8"))
    certified = check_certificate(cert, founder, name)
    if public_pem(certified) != public_pem(private.public_key()):
        raise ValueError("certificate does not belong to owner's private key")
    return Identity(name, private, cert, founder)
