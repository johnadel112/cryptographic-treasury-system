import hashlib
import json
import secrets
from dataclasses import dataclass
from typing import Callable, Iterable, Tuple


def canonical_bytes(data: dict) -> bytes:
    return json.dumps(data, sort_keys=True, separators=(",", ":")).encode("utf-8")


def ballot_digest(vote_number: str, voter_id: str, c1: int, c2: int) -> bytes:
    return hashlib.sha256(
        canonical_bytes({
            "vote_number": vote_number,
            "voter_id": voter_id,
            "c1": c1,
            "c2": c2,
        })
    ).digest()


@dataclass(frozen=True)
class EncryptedBallot:
    vote_number: str
    voter_id: str
    c1: int
    c2: int
    signature: bytes


def encrypt_and_sign_ballot(
    vote_number: str,
    voter_id: str,
    vote_yes: bool,
    p: int,
    g: int,
    q: int,
    public_key_h: int,
    sign_ecdsa: Callable[[bytes], bytes],
) -> EncryptedBallot:
    m = 1 if vote_yes else 0
    # Fresh randomness r per ballot prevents ciphertext linkability
    r = secrets.randbelow(q - 1) + 1
    c1 = pow(g, r, p)
    c2 = (pow(g, m, p) * pow(public_key_h, r, p)) % p
    sig = sign_ecdsa(ballot_digest(vote_number, voter_id, c1, c2))
    return EncryptedBallot(
        vote_number=vote_number,
        voter_id=voter_id,
        c1=c1,
        c2=c2,
        signature=sig,
    )


def aggregate_ciphertexts(ballots: Iterable[EncryptedBallot], p: int) -> Tuple[int, int]:
    agg_c1 = 1
    agg_c2 = 1
    for ballot in ballots:
        agg_c1 = (agg_c1 * ballot.c1) % p
        agg_c2 = (agg_c2 * ballot.c2) % p
    return agg_c1, agg_c2


def recover_yes_count(g_pow_y: int, g: int, p: int, max_ballots: int) -> int:
    current = 1
    for count in range(max_ballots + 1):
        if current == g_pow_y:
            return count
        current = (current * g) % p
    raise ValueError("Decrypted group element does not match any valid vote count")