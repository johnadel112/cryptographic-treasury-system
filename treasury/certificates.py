"""Founder-signed P-256 certificates (Overview, page 4)."""
from dataclasses import dataclass, asdict
from datetime import date, datetime, timezone
import re

from cryptography.exceptions import InvalidSignature, UnsupportedAlgorithm
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

from .config import GROUP
from .encoding import canonical_json
from .framing import ProtocolError


class CertificateError(ProtocolError):
    pass


def require_p256(key):
    if not isinstance(key, (ec.EllipticCurvePrivateKey, ec.EllipticCurvePublicKey)) or not isinstance(key.curve, ec.SECP256R1):
        raise ValueError("key must use P-256")
    return key


def public_pem(key) -> str:
    require_p256(key)
    return key.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode("ascii")


def load_public(pem: str):
    if not isinstance(pem, str):
        raise ValueError("public key must be PEM text")
    return require_p256(serialization.load_pem_public_key(pem.encode("ascii")))


def decode_hex(value: str) -> bytes:
    if not isinstance(value, str) or not re.fullmatch(r"(?:[0-9a-f]{2})+", value):
        raise ValueError("expected nonempty lowercase hexadecimal bytes")
    return bytes.fromhex(value)


def sign(private_key, value) -> str:
    require_p256(private_key)
    return private_key.sign(canonical_json(value), ec.ECDSA(hashes.SHA256())).hex()


def verify_signature(public_key, signature: str, value) -> None:
    require_p256(public_key)
    public_key.verify(decode_hex(signature), canonical_json(value), ec.ECDSA(hashes.SHA256()))


@dataclass
class Certificate:
    group: str
    name: str
    public_key: str
    expires: str
    sig: str = ""

    def unsigned_fields(self) -> dict:
        return {k: v for k, v in asdict(self).items() if k != "sig"}

    def to_dict(self) -> dict:
        return asdict(self)


def create_certificate(founder_private_key, name: str, public_key_pem: str,
                       expires: str) -> Certificate:
    load_public(public_key_pem)
    date.fromisoformat(expires)
    cert = Certificate(GROUP, name, public_key_pem, expires)
    cert.sig = sign(founder_private_key, cert.unsigned_fields())
    return cert


def check_certificate(certificate: dict, founder_public_key, expected_name: str,
                      *, today: date | None = None):
    """Return the certified public key or raise a diagnostic CertificateError."""
    try:
        fields = {"group", "name", "public_key", "expires", "sig"}
        if not isinstance(certificate, dict) or set(certificate) != fields:
            raise ValueError("certificate fields are missing or unexpected")
        if not all(isinstance(v, str) for v in certificate.values()):
            raise ValueError("certificate fields must be strings")
        if certificate["group"] != GROUP:
            raise ValueError("certificate GROUP mismatch")
        if certificate["name"] != expected_name:
            raise ValueError("certificate identity mismatch")
        expiry = date.fromisoformat(certificate["expires"])
        if expiry.isoformat() != certificate["expires"]:
            raise ValueError("certificate expiry must be YYYY-MM-DD")
        if expiry < (today or datetime.now(timezone.utc).date()):
            raise ValueError("certificate expired")
        key = load_public(certificate["public_key"])
        unsigned = {k: certificate[k] for k in fields if k != "sig"}
        try:
            verify_signature(founder_public_key, certificate["sig"], unsigned)
        except InvalidSignature as exc:
            raise ValueError("certificate founder signature invalid") from exc
        return key
    except (ValueError, TypeError, UnicodeError, UnsupportedAlgorithm) as exc:
        raise CertificateError(str(exc)) from exc


def verify_certificate(certificate: dict, founder_public_key, expected_name: str) -> bool:
    try:
        check_certificate(certificate, founder_public_key, expected_name)
        return True
    except CertificateError:
        return False
