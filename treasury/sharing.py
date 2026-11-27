"""Milestone 2 – Shamir Secret Sharing with Feldman VSS commitments.

Divan (Student 3): threshold cryptography and treasury vault.
All arithmetic is in the RFC 3526 group defined in config.py.
Randomness: secrets.randbelow only (never random module).
"""
import secrets


def evaluate_polynomial(coefficients: list[int], x: int, q: int) -> int:
    """Evaluate f(x) = a0 + a1*x + a2*x^2 + ... modulo q using Horner's method.

    coefficients[0] is the constant term (the secret a0).
    """
    result = 0
    for coeff in reversed(coefficients):
        result = (result * x + coeff) % q
    return result


def make_shares(secret: int, t: int, n: int, q: int) -> tuple[list[int], list[int]]:
    """Generate a random degree-(t-1) polynomial and return (coefficients, shares).

    The polynomial f satisfies f(0) = secret.
    coefficients: [a0=secret, a1, ..., a_{t-1}]  (kept private)
    shares:       [f(1), f(2), ..., f(n)]          (member i gets shares[i-1])
    """
    if type(t) is not int or type(n) is not int or not (1 <= t <= n < q):
        raise ValueError("require 1 <= t <= n")
    if not (0 < secret < q):
        raise ValueError("secret must be in (0, q)")

    # Constant term is the secret; remaining t-1 coefficients are random.
    coefficients = [secret] + [secrets.randbelow(q - 1) + 1 for _ in range(t - 1)]
    shares = [evaluate_polynomial(coefficients, i + 1, q) for i in range(n)]
    return coefficients, shares


def feldman_commitments(coefficients: list[int], p: int, g: int) -> list[int]:
    """Compute Feldman VSS public commitments C_k = g^{a_k} mod p.

    Returns a list of len(coefficients) group elements.
    These are published so members can verify their own share.
    """
    return [pow(g, a, p) for a in coefficients]


def verify_share(share: int, member_index: int, commitments: list[int], p: int, q: int, g: int) -> bool:
    """Check that g^share ≡ ∏ C_k^{i^k}  (mod p) for member index i = member_index.

    member_index is 1-based (member M_i gets share f(i)).
    Returns True iff the share is consistent with the public commitments.
    """
    if (type(share) is not int or not 0 <= share < q or
            type(member_index) is not int or not 0 < member_index < q or
            any(type(c) is not int or not 1 < c < p or pow(c, q, p) != 1 for c in commitments)):
        return False
    if not commitments:
        return False
    # LHS: g^{share} mod p
    lhs = pow(g, share, p)
    # RHS: C_0 * C_1^i * C_2^{i^2} * ... mod p
    rhs = 1
    for k, C_k in enumerate(commitments):
        rhs = (rhs * pow(C_k, pow(member_index, k, q), p)) % p
    return lhs == rhs


def lagrange_coefficient(i: int, selected_indices: list[int], q: int) -> int:
    """Compute the Lagrange basis coefficient λ_i(0) for index i over selected_indices.

    Uses modular inverses (Fermat's little theorem: q is prime, so a^{-1} = a^{q-2} mod q).
    i and selected_indices are 1-based member indices matching the polynomial evaluation points.
    """
    if i not in selected_indices or len(set(selected_indices)) != len(selected_indices) or any(type(j) is not int or not 0 < j < q for j in selected_indices):
        raise ValueError("invalid or duplicate interpolation indices")
    numerator = 1
    denominator = 1
    for j in selected_indices:
        if j == i:
            continue
        # λ_i(0) = ∏_{j≠i} (0 - j) / (i - j)
        numerator = (numerator * (-j)) % q
        denominator = (denominator * (i - j)) % q
    return (numerator * pow(denominator, q - 2, q)) % q


def verification_key(index: int, commitments: list[int], p: int, q: int) -> int:
    """Derive h_i only from authenticated Feldman commitments."""
    if type(index) is not int or not 0 < index < q:
        raise ValueError("invalid member index")
    result = 1
    for k, commitment in enumerate(commitments):
        result = result * pow(commitment, pow(index, k, q), p) % p
    return result
