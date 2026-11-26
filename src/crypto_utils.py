"""Cryptographic primitives for P-256 ECDSA/ECDH, HKDF, AES-256-GCM, and Schnorr."""

import hashlib
import json
import secrets
from typing import Any, Dict, Tuple

from cryptography.exceptions import InvalidSignature, InvalidTag
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from .config import Q


def canonical_bytes(obj: Any) -> bytes:
    """Serialize obj deterministically to UTF-8 JSON bytes."""
    return json.dumps(obj, separators=(",", ":"), sort_keys=True).encode("utf-8")


def sha256_bytes(obj: Any) -> bytes:
    """Return SHA-256 digest of canonical JSON bytes."""
    return hashlib.sha256(canonical_bytes(obj)).digest()


def hash_to_zq(*args: Any) -> int:
    """Hash canonical list of arguments to an integer modulo Q."""
    digest = hashlib.sha256(canonical_bytes(list(args))).digest()
    return int.from_bytes(digest, "big") % Q


def generate_p256_keypair() -> Tuple[ec.EllipticCurvePrivateKey, ec.EllipticCurvePublicKey]:
    """Generate a fresh NIST P-256 keypair."""
    priv = ec.generate_private_key(ec.SECP256R1())
    return priv, priv.public_key()


def priv_to_int(priv: ec.EllipticCurvePrivateKey) -> int:
    """Return scalar integer of P-256 private key."""
    return priv.private_numbers().private_value


def int_to_priv(val: int) -> ec.EllipticCurvePrivateKey:
    """Construct P-256 private key from scalar integer."""
    return ec.derive_private_key(val, ec.SECP256R1())


def pub_to_hex(pub: ec.EllipticCurvePublicKey) -> str:
    """Encode P-256 public key as uncompressed point hex."""
    return pub.public_bytes(
        encoding=serialization.Encoding.X962,
        format=serialization.PublicFormat.UncompressedPoint,
    ).hex()


def hex_to_pub(hex_str: str) -> ec.EllipticCurvePublicKey:
    """Decode uncompressed point hex to P-256 public key."""
    return ec.EllipticCurvePublicKey.from_encoded_point(
        ec.SECP256R1(), bytes.fromhex(hex_str)
    )


def sign_data(priv: ec.EllipticCurvePrivateKey, obj: Any) -> str:
    """Sign canonical bytes of obj with P-256 ECDSA, returning hex DER signature."""
    sig = priv.sign(canonical_bytes(obj), ec.ECDSA(hashes.SHA256()))
    return sig.hex()


def verify_sig(pub: ec.EllipticCurvePublicKey, obj: Any, sig_hex: str) -> bool:
    """Verify hex DER ECDSA signature over canonical bytes of obj."""
    try:
        pub.verify(bytes.fromhex(sig_hex), canonical_bytes(obj), ec.ECDSA(hashes.SHA256()))
        return True
    except (InvalidSignature, ValueError):
        return False


def create_certificate(
    founder_priv: ec.EllipticCurvePrivateKey,
    name: str,
    group: str,
    subject_pub: ec.EllipticCurvePublicKey,
) -> Dict[str, str]:
    """Create a founder-signed certificate for a member or server."""
    pub_hex = pub_to_hex(subject_pub)
    sig = sign_data(founder_priv, ["cert", group, name, pub_hex])
    return {"name": name, "group": group, "pubkey": pub_hex, "sig": sig}


def verify_certificate(
    cert: Dict[str, str],
    founder_pub: ec.EllipticCurvePublicKey,
    expected_group: str,
    expected_name: str | None = None,
) -> bool:
    """Verify certificate signature, group, and optional expected subject name."""
    if not isinstance(cert, dict):
        return False
    name = cert.get("name")
    group = cert.get("group")
    pub_hex = cert.get("pubkey")
    sig = cert.get("sig")
    if not all(isinstance(v, str) and v for v in (name, group, pub_hex, sig)):
        return False
    if group != expected_group:
        return False
    if expected_name is not None and name != expected_name:
        return False
    try:
        hex_to_pub(pub_hex)
    except ValueError:
        return False
    return verify_sig(founder_pub, ["cert", group, name, pub_hex], sig)


def derive_channel_keys(
    shared_secret: bytes,
    group: str,
    member_name: str,
    x_hex: str,
    y_hex: str,
) -> Tuple[bytes, bytes]:
    """Derive (member_to_server_key, server_to_member_key) using HKDF-SHA256."""
    hs_hash = sha256_bytes(["hs", group, member_name, x_hex, y_hex])
    info = f"ICS505|{group}|channel|".encode("utf-8") + hs_hash
    okm = HKDF(
        algorithm=hashes.SHA256(),
        length=64,
        salt=None,
        info=info,
    ).derive(shared_secret)
    return okm[:32], okm[32:]


def encrypt_frame(key: bytes, counter: int, plaintext: bytes) -> bytes:
    """Encrypt plaintext with AES-256-GCM using 12-byte big-endian counter nonce."""
    nonce = counter.to_bytes(12, "big")
    ct = AESGCM(key).encrypt(nonce, plaintext, None)
    return nonce + ct


def decrypt_frame(key: bytes, expected_counter: int, frame: bytes) -> bytes:
    """Verify frame counter nonce and decrypt AES-256-GCM frame."""
    if len(frame) < 12 + 16:
        raise ValueError("Encrypted frame too short")
    nonce = frame[:12]
    expected_nonce = expected_counter.to_bytes(12, "big")
    if nonce != expected_nonce:
        raise ValueError(
            f"Nonce counter mismatch: got {int.from_bytes(nonce, 'big')}, expected {expected_counter}"
        )
    try:
        return AESGCM(key).decrypt(nonce, frame[12:], None)
    except InvalidTag as exc:
        raise ValueError("AES-GCM authentication tag verification failed") from exc


def random_zq_scalar() -> int:
    """Return a cryptographically random scalar in [1, Q - 1]."""
    return secrets.randbelow(Q - 1) + 1
