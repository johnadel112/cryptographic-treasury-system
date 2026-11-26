"""Milestone 1 certificate structure. Implement signing and verification."""
from dataclasses import dataclass, asdict

from .config import GROUP


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
    """TODO: sign canonical_json(unsigned_fields) with founder's ECDSA key."""
    raise NotImplementedError


def verify_certificate(certificate: dict, founder_public_key, expected_name: str) -> bool:
    """TODO: verify founder signature, GROUP, expected name and expiry date."""
    raise NotImplementedError
