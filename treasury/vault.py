"""Milestone 2 – Encrypted Treasury Vault.

Divan (Student 3): vault key generation, ElGamal encryption of vault key
material, HKDF file-encryption key derivation, AES-256-GCM vault file
encryption/decryption, signed open requests, and share distribution.

Design overview:
  1. Founder's secret s is a random scalar in Z_q.
  2. Shamir splits s into n shares, threshold t.
  3. Feldman commitments V_k = g^{a_k} mod p are published.
  4. Vault public key  H_vault = g^s mod p.
  5. Member verification key for member i: V_i = g^{s_i} mod p.
  6. ElGamal encryption of vault key material uses H_vault as the recipient key.
  7. File encryption key K_file derived via HKDF from the ElGamal shared secret.
  8. Vault file encrypted with AES-256-GCM using K_file.
  9. Founder's secret s is zeroed/deleted immediately after setup.
 10. Vault opening: t members each submit a signed request and a decryption
     contribution with Chaum-Pedersen proof; Lagrange combination recovers
     the decryption without reconstructing s.

Security properties:
  - Shamir secret sharing: information-theoretically secure (t-1 shares leak nothing).
  - Feldman VSS: each member can verify their own share against public commitments.
  - Chaum-Pedersen proofs: prevent cheating members (Attack A5).
  - ElGamal + HKDF: forward-secret key encapsulation for the vault.
  - AES-256-GCM: authenticated encryption of vault file content.
  - Founder secret erasure: s not retained after setup.
"""
import json
import os
import secrets
from pathlib import Path

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from .certificates import decode_hex, sign, verify_signature
from .config import G, GROUP, P, Q, member_names
from .encoding import H, canonical_json, sha256
from .identity import write_new
from .logging_utils import get_logger
from .opening import combine_decryption_shares, make_decryption_share, verify_decryption_share
from .sharing import feldman_commitments, lagrange_coefficient, make_shares, verify_share

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


# ---------------------------------------------------------------------------
# Vault setup (called once by the founder)
# ---------------------------------------------------------------------------

def vault_setup(
    root: Path,
    t: int,
    n: int,
    vault_plaintext: bytes,
    log=None,
    *,
    p: int = P,
    q: int = Q,
    g: int = G,
) -> dict:
    """Create the full vault:

    1. Generate founder secret s ∈ Z_q.
    2. Shamir-split s into n shares with threshold t.
    3. Compute Feldman commitments C_k = g^{a_k} mod p.
    4. Compute vault public key H = g^s mod p.
    5. Compute per-member verification keys V_i = g^{s_i} mod p.
    6. ElGamal-encrypt an ephemeral key element e using H.
    7. Derive K_file via HKDF from e.
    8. Encrypt vault_plaintext with AES-256-GCM using K_file.
    9. Distribute each member's share to private per-member file.
    10. Zero s immediately.

    Writes to root/public/vault_public.json  (commitments, encrypted key)
    and root/M{i}/share.json  (each member's private share).
    Returns the vault_public dict.
    """
    if log is None:
        log = get_logger("vault")

    if not (1 <= t <= n):
        raise ValueError("require 1 <= t <= n")

    # Step 1-2: founder secret and Shamir shares
    s = secrets.randbelow(q - 1) + 1
    coefficients, shares = make_shares(s, t, n, q)
    log.info("vault setup: generated Shamir polynomial degree=%d shares=%d", t - 1, n)

    # Step 3: Feldman commitments
    commitments = feldman_commitments(coefficients, p, g)
    log.info("vault setup: Feldman commitments C0=%s...", format(commitments[0], "x")[:8])

    # Step 4-5: vault public key and member verification keys
    H_vault = pow(g, s, p)                            # = commitments[0] = C_0
    V_keys  = [pow(g, si, p) for si in shares]        # V_i = g^{s_i} mod p
    log.info("vault setup: vault public key H=%s...", format(H_vault, "x")[:8])

    # Step 6: ElGamal encrypt an ephemeral group element
    e = secrets.randbelow(q - 1) + 1                  # ephemeral secret element
    e_elem = pow(g, e, p)                             # g^e – the "message" we encrypt
    hkdf_salt = secrets.token_bytes(32)               # random HKDF salt
    c1, c2 = elgamal_encrypt(e_elem, H_vault, p, q, g)
    log.info("vault setup: ElGamal encryption c1=%s...", format(c1, "x")[:8])

    # Step 7: Derive file key from e_elem
    K_file = derive_file_key(e_elem, salt=hkdf_salt)

    # Step 8: Encrypt vault file
    encrypted_vault = encrypt_vault_file(vault_plaintext, K_file)
    log.info("vault setup: AES-256-GCM vault encrypted nonce=%s", encrypted_vault["nonce"][:8])

    # Step 9: Write private per-member shares (never to public/)
    names = member_names(n)
    for idx, (name, si) in enumerate(zip(names, shares)):
        member_dir = root / name
        member_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        share_path = member_dir / "share.json"
        # Verify share against commitments before distributing
        assert verify_share(si, idx + 1, commitments, p, q, g), f"share {idx+1} failed self-verification"
        share_data = canonical_json({
            "member":      name,
            "index":       idx + 1,
            "share":       format(si, "x"),
            "V_i":         format(V_keys[idx], "x"),
        })
        if not share_path.exists():
            write_new(share_path, share_data, private=True)
            log.info("vault setup: wrote private share member=%s V_i=%s...", name, format(V_keys[idx], "x")[:8])
        else:
            log.warning("vault setup: share already exists for %s, skipping", name)

    # Step 10: Zero founder secret (best-effort in CPython)
    del s, coefficients, e, e_elem, K_file
    import gc; gc.collect()

    # Build vault_public record (no secret material)
    vault_public = {
        "group":       GROUP,
        "t":           t,
        "n":           n,
        "commitments": [format(c, "x") for c in commitments],
        "vault_key":   format(H_vault, "x"),
        "V_keys":      [format(v, "x") for v in V_keys],
        "elgamal": {
            "c1":   format(c1, "x"),
            "c2":   format(c2, "x"),
            "salt": hkdf_salt.hex(),
        },
        "encrypted_vault": encrypted_vault,
    }

    public_dir = root / "public"
    public_dir.mkdir(parents=True, exist_ok=True)
    vault_pub_path = public_dir / "vault_public.json"
    if not vault_pub_path.exists():
        write_new(vault_pub_path, canonical_json(vault_public))
        log.info("vault setup: vault_public.json written t=%d n=%d", t, n)
    else:
        log.warning("vault setup: vault_public.json already exists; vault not overwritten")

    return vault_public


# ---------------------------------------------------------------------------
# Signed vault-opening requests
# ---------------------------------------------------------------------------

def open_request_transcript(group: str, member_name: str, seq: int, vault_key_hex: str) -> list:
    """Canonical transcript for a signed vault-opening request."""
    return ["open-vault", group, member_name, seq, vault_key_hex]


def sign_open_request(private_key, member_name: str, seq: int, vault_key: int) -> dict:
    """Create a signed vault-opening request (member side).

    The signature covers the canonical transcript so the server can
    verify intent before collecting decryption contributions.
    """
    transcript = open_request_transcript(GROUP, member_name, seq, format(vault_key, "x"))
    sig = sign(private_key, transcript)
    return {
        "op":        "open-vault",
        "group":     GROUP,
        "member":    member_name,
        "seq":       seq,
        "vault_key": format(vault_key, "x"),
        "sig":       sig,
    }


def verify_open_request(public_key, request: dict, last_seq: int) -> bool:
    """Verify a signed open-vault request (server side).

    Checks group, increasing seq, and ECDSA-SHA-256 signature.
    """
    try:
        if request.get("op") != "open-vault":
            return False
        if request.get("group") != GROUP:
            return False
        seq = request.get("seq")
        if not isinstance(seq, int) or seq <= last_seq:
            return False
        member_name = request["member"]
        vault_key_hex = request["vault_key"]
        transcript = open_request_transcript(GROUP, member_name, seq, vault_key_hex)
        verify_signature(public_key, request["sig"], transcript)
        return True
    except Exception:
        return False


# ---------------------------------------------------------------------------
# Vault opening (server-side orchestration)
# ---------------------------------------------------------------------------

def open_vault(
    vault_public: dict,
    contributions: list[dict],
    *,
    weak: str | None = None,
    p: int = P,
    q: int = Q,
    g: int = G,
    log=None,
) -> bytes | None:
    """Attempt to open the vault from t valid decryption contributions.

    Parameters
    ----------
    vault_public  : the dict from vault_public.json
    contributions : list of dicts from member make_decryption_share calls
    weak          : pass "no-proof" to skip Chaum-Pedersen verification (A5 weak)
    Returns decrypted vault plaintext, or None if threshold not reached.
    """
    if log is None:
        log = get_logger("vault")

    t   = int(vault_public["t"])
    c1  = int(vault_public["elgamal"]["c1"], 16)
    c2  = int(vault_public["elgamal"]["c2"], 16)
    salt = bytes.fromhex(vault_public["elgamal"]["salt"])

    if weak == "no-proof":
        log.warning("WEAK MODE no-proof: Chaum-Pedersen verification DISABLED – A5 demonstration")
    else:
        log.info("vault opening: verifying Chaum-Pedersen proofs for all contributions")

    # Combine decryption shares (internally applies proof verification)
    combined_d = combine_decryption_shares(contributions, c1, t, p, q, g, weak=weak)
    if combined_d is None:
        log.error("vault opening FAILED: fewer than t=%d valid contributions", t)
        return None

    log.info("vault opening: threshold reached combined_d=%s...", format(combined_d, "x")[:8])

    # Recover e_elem = c2 * combined_d^{-1} mod p
    e_elem = elgamal_decrypt_from_shares(c1, c2, combined_d, p)
    log.info("vault opening: ElGamal decryption recovered e_elem=%s...", format(e_elem, "x")[:8])

    # Re-derive file key
    K_file = derive_file_key(e_elem, salt=salt)

    # Decrypt vault file
    try:
        plaintext = decrypt_vault_file(vault_public["encrypted_vault"], K_file)
        log.info("vault opening: AES-256-GCM decryption SUCCESS")
        return plaintext
    except ValueError as exc:
        log.error("vault opening FAILED: %s", exc)
        return None


# ---------------------------------------------------------------------------
# Share loading helper (for member CLIs)
# ---------------------------------------------------------------------------

def load_member_share(root: Path, member_name: str) -> dict:
    """Load a member's private share from their local directory."""
    share_path = root / member_name / "share.json"
    if not share_path.exists():
        raise FileNotFoundError(f"No share found for {member_name}")
    data = json.loads(share_path.read_bytes())
    return data


def load_vault_public(root: Path) -> dict:
    """Load the public vault parameters."""
    path = root / "public" / "vault_public.json"
    if not path.exists():
        raise FileNotFoundError("vault_public.json not found; run founder vault-setup first")
    return json.loads(path.read_bytes())
