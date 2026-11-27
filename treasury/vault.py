"""Divan's ElGamal/HKDF/AES-GCM vault with founder-authenticated public setup.

Only founder distributes shares. Each running member loads only its own share;
server combines public contributions and never reconstructs s.
"""
import json
import secrets
from pathlib import Path

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from .certificates import decode_hex, sign, verify_signature, load_public
from .config import G, GROUP, P, Q, member_names
from .encoding import canonical_json, group_int, hex_int
from .identity import write_new, load_private, validate_name
from .logging_utils import get_logger
from .opening import combine_decryption_shares
from .sharing import feldman_commitments, make_shares, verification_key

# Default vault content used by founder setup and standalone demos.
VAULT_DEFAULT_CONTENT = b"TREASURY VAULT - Confidential Project Funds Ledger - ICS505"


# ---------------------------------------------------------------------------
# ElGamal key encapsulation over the RFC-3526 group
# ---------------------------------------------------------------------------

def elgamal_encrypt(message_element: int, public_key: int, p: int = P, q: int = Q, g: int = G) -> tuple[int, int]:
    """Encrypt a group element m using ElGamal: (c1, c2) = (g^r, m * h^r) mod p.

    public_key h = g^s mod p  (the vault public key).
    Returns (c1, c2).
    """
    r = secrets.randbelow(q - 1) + 1
    c1 = pow(g, r, p)
    c2 = (message_element * pow(public_key, r, p)) % p
    return c1, c2


def elgamal_decrypt(c1: int, c2: int, secret: int, p: int = P) -> int:
    """Decrypt ElGamal ciphertext: m = c2 * c1^{-s} mod p."""
    shared = pow(c1, secret, p)
    shared_inv = pow(shared, p - 2, p)   # Fermat inverse (p is prime)
    return (c2 * shared_inv) % p


def elgamal_decrypt_from_shares(c1: int, c2: int, combined_d: int, p: int = P) -> int:
    """Recover plaintext using the threshold-combined partial decryption d = c1^s mod p.

    combined_d is returned by opening.combine_decryption_shares.
    m = c2 * d^{-1} mod p
    """
    combined_inv = pow(combined_d, p - 2, p)
    return (c2 * combined_inv) % p


# ---------------------------------------------------------------------------
# HKDF file-encryption key derivation
# ---------------------------------------------------------------------------

def derive_file_key(shared_element: int, salt: bytes | None = None) -> bytes:
    """Derive a 32-byte AES-256 key from a DH shared element using HKDF-SHA-256.

    info encodes the purpose and project group for domain separation.
    salt should be a fresh random 32-byte value; pass None for no salt.
    """
    ikm = shared_element.to_bytes((shared_element.bit_length() + 7) // 8, "big")
    info = ("ICS505|" + GROUP + "|vault-file-key").encode()
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=salt, info=info).derive(ikm)


# ---------------------------------------------------------------------------
# AES-256-GCM vault file encryption / decryption
# ---------------------------------------------------------------------------

def encrypt_vault_file(plaintext: bytes, key: bytes) -> dict:
    """Encrypt vault file content with AES-256-GCM.

    Returns a dict with hex-encoded nonce and ciphertext+tag.
    The nonce is a fresh random 12-byte value (96-bit).
    """
    if len(key) != 32:
        raise ValueError("AES-256 requires a 32-byte key")
    nonce = secrets.token_bytes(12)
    ciphertext = AESGCM(key).encrypt(nonce, plaintext, None)
    return {
        "nonce": nonce.hex(),
        "ciphertext": ciphertext.hex(),   # includes 16-byte GCM tag at end
    }


def decrypt_vault_file(encrypted: dict, key: bytes) -> bytes:
    """Decrypt vault file content.  Raises ValueError on tag failure."""
    if len(key) != 32:
        raise ValueError("AES-256 requires a 32-byte key")
    nonce      = decode_hex(encrypted["nonce"])
    ciphertext = decode_hex(encrypted["ciphertext"])
    try:
        from cryptography.exceptions import InvalidTag
        return AESGCM(key).decrypt(nonce, ciphertext, None)
    except Exception as exc:
        raise ValueError("vault file authentication tag FAILED") from exc



def check_vault_public(record: dict, founder_public_key) -> dict:
    """Authenticate all commitments and ciphertext metadata before using them."""
    try:
        unsigned = {k: v for k, v in record.items() if k != "sig"}
        verify_signature(founder_public_key, record["sig"], ["vault-setup", GROUP, unsigned])
        if set(unsigned) != {"group", "t", "n", "commitments", "vault_key", "elgamal", "encrypted_vault"} or record["group"] != GROUP:
            raise ValueError("invalid vault setup schema/GROUP")
        t, n = record["t"], record["n"]
        if type(t) is not int or type(n) is not int or not 1 <= t <= n < Q:
            raise ValueError("invalid threshold parameters")
        commitments = record["commitments"]
        if not isinstance(commitments, list) or len(commitments) != t:
            raise ValueError("invalid commitment count")
        for c in commitments:
            group_int(c)
        if record["vault_key"] != commitments[0]:
            raise ValueError("vault key differs from C0")
        group_int(record["elgamal"]["c1"])
        group_int(record["elgamal"]["c2"])
        if len(decode_hex(record["elgamal"]["salt"])) != 32 or len(decode_hex(record["encrypted_vault"]["nonce"])) != 12:
            raise ValueError("invalid vault salt/nonce")
        decode_hex(record["encrypted_vault"]["ciphertext"])
        return record
    except Exception as exc:
        raise ValueError("founder commitment/setup verification FAILED") from exc


def trusted_verification_keys(record: dict) -> dict[int, int]:
    commitments = [group_int(c) for c in record["commitments"]]
    return {i: verification_key(i, commitments, P, Q) for i in range(1, record["n"]+1)}


def vault_setup(root: Path, t: int, n: int, vault_plaintext: bytes, log=None) -> dict:
    log = log or get_logger("founder")
    if type(t) is not int or type(n) is not int or not 1 <= t <= n < Q:
        raise ValueError("require 1 <= t <= n < q")
    if len(vault_plaintext) > 1024 * 1024:
        raise ValueError("educational vault file limit is 1 MiB")
    destinations = [root / name / "share.json" for name in member_names(n)]
    destinations += [root / "public" / "vault_public.json"]
    if any(path.exists() for path in destinations):
        raise ValueError("existing vault/share files; use a fresh runtime directory")
    founder = load_private("founder", root)
    # Avoid zero shares/identity commitments, which cannot pass the mandated u>1 rule.
    while True:
        secret = secrets.randbelow(Q - 1) + 1
        coefficients, shares = make_shares(secret, t, n, Q)
        if all(shares):
            break
    commitments = feldman_commitments(coefficients, P, G)
    m = pow(G, secrets.randbelow(Q - 1) + 1, P)
    c1, c2 = elgamal_encrypt(m, commitments[0])
    salt = secrets.token_bytes(32)
    encrypted = encrypt_vault_file(vault_plaintext, derive_file_key(m, salt))
    record = {"group": GROUP, "t": t, "n": n,
              "commitments": [format(c, "x") for c in commitments],
              "vault_key": format(commitments[0], "x"),
              "elgamal": {"c1": format(c1, "x"), "c2": format(c2, "x"), "salt": salt.hex()},
              "encrypted_vault": encrypted}
    record["sig"] = sign(founder, ["vault-setup", GROUP, record])
    check_vault_public(record, founder.public_key())
    created = []
    try:
        for i, share in enumerate(shares, 1):
            path = root / f"M{i}" / "share.json"
            write_new(path, canonical_json({"member": f"M{i}", "index": i, "share": format(share, "x")}), private=True)
            created.append(path)
        path = root / "public" / "vault_public.json"
        write_new(path, canonical_json(record))
        created.append(path)
    except Exception:
        for path in created:
            path.unlink()  # only exact files created by this call, no recursive deletion
        raise
    log.info("signed vault setup ready n=%d t=%d C0=%s; no secret retained", n, t, record["vault_key"][:8])
    return record  # locals containing s/coefficients/m expire; Python cannot guarantee wiping


def load_vault_public(root: Path) -> dict:
    founder = load_public((root / "public" / "founder.pub").read_text("ascii"))
    return check_vault_public(json.loads((root / "public" / "vault_public.json").read_text("utf-8")), founder)


def load_member_share(root: Path, member_name: str) -> dict:
    validate_name(member_name)
    if not member_name.startswith("M"):
        raise ValueError("share owner must be a member")
    record = json.loads((root / member_name / "share.json").read_text("utf-8"))
    if record["member"] != member_name or record["index"] != int(member_name[1:]):
        raise ValueError("share owner mismatch")
    hex_int(record["share"], limit=Q, nonzero=True)
    return record


def open_vault(vault_public: dict, contributions: list[dict], *, founder_public_key,
               weak: str | None = None, log=None) -> bytes | None:
    check_vault_public(vault_public, founder_public_key)
    c1 = group_int(vault_public["elgamal"]["c1"])
    c2 = group_int(vault_public["elgamal"]["c2"])
    combined = combine_decryption_shares(contributions, c1, vault_public["t"],
                verification_keys=trusted_verification_keys(vault_public), weak=weak)
    if combined is None:
        return None
    m = elgamal_decrypt_from_shares(c1, c2, combined)
    try:
        return decrypt_vault_file(vault_public["encrypted_vault"],
                    derive_file_key(m, decode_hex(vault_public["elgamal"]["salt"])))
    except ValueError:
        return None
