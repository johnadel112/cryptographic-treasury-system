"""Milestone 2 – Verifiable partial decryption shares with Chaum-Pedersen proofs.

Divan (Student 3): implements make_decryption_share, verify_decryption_share,
combine_decryption_shares.

Attack A5 – Cheating Member:
  --weak no-proof  → skip proof verification (insecure mode; invalid contributions accepted)
  secure mode      → reject invalid contributions; continue with remaining valid shares

Chaum–Pedersen proof of discrete-log equality:
  Given public ElGamal ciphertext component c1 (= g^r mod p) and member share s_i,
  prove knowledge of s_i such that:
      d_i = c1^{s_i} mod p   AND   V_i = g^{s_i} mod p  (Feldman commitment)
  without revealing s_i.

Proof (non-interactive via Fiat-Shamir):
  1. Prover picks random u ∈ Z_q
  2. a1 = g^u mod p,  a2 = c1^u mod p
  3. c  = H("cp-proof", g, V_i, c1, d_i, a1, a2) mod q
  4. z  = (u + c*s_i) mod q
  Transcript: (a1, a2, c, z)

Verifier checks:
  g^z  ≡ a1 * V_i^c    (mod p)
  c1^z ≡ a2 * d_i^c    (mod p)
"""
import secrets

from .config import G, P, Q
from .encoding import H
from .sharing import lagrange_coefficient


# ---------------------------------------------------------------------------
# Proof creation
# ---------------------------------------------------------------------------

def make_decryption_share(
    share: int,
    member_index: int,
    c1: int,
    p: int = P,
    q: int = Q,
    g: int = G,
    verification_key: int | None = None,
) -> dict:
    """Compute d_i = c1^{share} mod p and a Chaum-Pedersen equality-of-DL proof.

    Parameters
    ----------
    share          : member i's secret share s_i (from Shamir splitting)
    member_index   : 1-based member index i
    c1             : ElGamal first ciphertext component (= g^r mod p)
    p, q, g        : group parameters (defaults from config)
    verification_key : V_i = g^{s_i} mod p; computed if not supplied.

    Returns
    -------
    dict with keys: member_index, d_i, a1, a2, c, z   (all large ints as hex strings)
    """
    if not (0 < share < q):
        raise ValueError("share must be in (0, q)")

    # Partial decryption share
    d_i = pow(c1, share, p)

    # Verification key (Feldman commitment for this member)
    V_i = verification_key if verification_key is not None else pow(g, share, p)

    # Chaum–Pedersen prover
    u = secrets.randbelow(q - 1) + 1          # random blinding scalar
    a1 = pow(g, u, p)                          # commitment to u in g-subgroup
    a2 = pow(c1, u, p)                         # commitment to u in c1-subgroup

    # Fiat-Shamir challenge (domain-separated)
    c = H("cp-proof", g, V_i, c1, d_i, a1, a2, q=q)
    z = (u + c * share) % q                    # response

    return {
        "member_index": member_index,
        "d_i": format(d_i, "x"),
        "V_i": format(V_i, "x"),
        "a1":  format(a1,  "x"),
        "a2":  format(a2,  "x"),
        "c":   format(c,   "x"),
        "z":   format(z,   "x"),
    }


# ---------------------------------------------------------------------------
# Proof verification
# ---------------------------------------------------------------------------

def verify_decryption_share(
    contribution: dict,
    c1: int,
    p: int = P,
    q: int = Q,
    g: int = G,
    *,
    weak: str | None = None,
) -> bool:
    """Verify a member's decryption contribution before accepting d_i.

    Mandatory A5 comparison:
      --weak no-proof  → always return True (insecure; invalid share passes)
      secure mode      → verify both Chaum-Pedersen equations; reject on failure.

    Returns True iff the contribution is accepted.
    """
    # A5 weak mode: skip all verification
    if weak == "no-proof":
        return True

    try:
        d_i = int(contribution["d_i"], 16)
        V_i = int(contribution["V_i"], 16)
        a1  = int(contribution["a1"],  16)
        a2  = int(contribution["a2"],  16)
        c   = int(contribution["c"],   16)
        z   = int(contribution["z"],   16)
    except (KeyError, ValueError, TypeError):
        return False   # malformed contribution → reject

    # Recompute challenge from the transcript
    c_check = H("cp-proof", g, V_i, c1, d_i, a1, a2, q=q)
    if c != c_check:
        return False

    # Equation 1: g^z ≡ a1 * V_i^c  (mod p)
    if pow(g, z, p) != (a1 * pow(V_i, c, p)) % p:
        return False

    # Equation 2: c1^z ≡ a2 * d_i^c  (mod p)
    if pow(c1, z, p) != (a2 * pow(d_i, c, p)) % p:
        return False

    return True


# ---------------------------------------------------------------------------
# Combination (Lagrange interpolation on decryption shares)
# ---------------------------------------------------------------------------

def combine_decryption_shares(
    contributions: list[dict],
    c1: int,
    t: int,
    p: int = P,
    q: int = Q,
    g: int = G,
    *,
    weak: str | None = None,
) -> int | None:
    """Lagrange-combine t accepted decryption shares to recover g^{secret*r} mod p.

    The combined result equals c1^{f(0)} = g^{r * secret} which can be used to
    decrypt the ElGamal ciphertext without ever reconstructing the raw secret.

    Returns the combined decryption value, or None if fewer than t valid shares.
    """
    # Filter to accepted (verified) contributions only
    valid = [
        contrib for contrib in contributions
        if verify_decryption_share(contrib, c1, p, q, g, weak=weak)
    ]

    if len(valid) < t:
        return None   # threshold not reached with valid contributions

    # Use exactly t valid shares
    selected = valid[:t]
    indices = [int(contrib["member_index"]) for contrib in selected]

    # Multiply d_i^{λ_i} for each selected member
    result = 1
    for contrib in selected:
        i   = int(contrib["member_index"])
        d_i = int(contrib["d_i"], 16)
        lam = lagrange_coefficient(i, indices, q)
        result = (result * pow(d_i, lam, p)) % p

    return result
