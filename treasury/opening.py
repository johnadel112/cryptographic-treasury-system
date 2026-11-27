"""Divan's partial decryption, corrected to M2's exact member-bound transcript."""
import secrets
from .config import G, P, Q, valid_group_element
from .encoding import H, group_int, hex_int
from .sharing import lagrange_coefficient


def make_decryption_share(share: int, member_index: int, c1: int,
                          p: int = P, q: int = Q, g: int = G,
                          verification_key: int | None = None) -> dict:
    if not 0 < share < q or type(member_index) is not int or member_index < 1 or not valid_group_element(c1):
        raise ValueError("invalid decryption inputs")
    hi = verification_key if verification_key is not None else pow(g, share, p)
    di = pow(c1, share, p)
    w = secrets.randbelow(q - 1) + 1
    T1, T2 = pow(g, w, p), pow(c1, w, p)
    e = H("dec", member_index, c1, hi, di, T1, T2, q=q)
    return {"member_index": member_index, "d_i": format(di, "x"),
            "T1": format(T1, "x"), "T2": format(T2, "x"), "z": format((w + e*share) % q, "x")}


def verify_decryption_share(contribution: dict, c1: int, p: int = P, q: int = Q,
                            g: int = G, *, verification_key: int,
                            member_index: int, weak: str | None = None) -> bool:
    """Caller MUST supply trusted h_i and authenticated index, never peer's V_i."""
    try:
        if type(member_index) is not int or member_index < 1 or contribution["member_index"] != member_index:
            return False
        if type(contribution["member_index"]) is not int or not valid_group_element(c1) or not valid_group_element(verification_key):
            return False
        di = group_int(contribution["d_i"])
        if weak == "no-proof":
            return True
        if set(contribution) != {"member_index", "d_i", "T1", "T2", "z"}:
            return False
        T1, T2 = group_int(contribution["T1"]), group_int(contribution["T2"])
        z = hex_int(contribution["z"], limit=q)
        e = H("dec", member_index, c1, verification_key, di, T1, T2, q=q)
        return (pow(g, z, p) == T1 * pow(verification_key, e, p) % p and
                pow(c1, z, p) == T2 * pow(di, e, p) % p)
    except (KeyError, ValueError, TypeError):
        return False


def combine_decryption_shares(contributions: list[dict], c1: int, t: int,
                              p: int = P, q: int = Q, g: int = G, *,
                              verification_keys: dict[int, int], weak: str | None = None) -> int | None:
    if type(t) is not int or not 1 <= t <= len(verification_keys):
        raise ValueError("invalid threshold")
    valid = {}
    for c in contributions:
        i = c.get("member_index")
        if type(i) is not int or i not in verification_keys or i in valid:
            continue
        if verify_decryption_share(c, c1, p, q, g, verification_key=verification_keys[i], member_index=i, weak=weak):
            valid[i] = c
    if len(valid) < t:
        return None
    indices = list(valid)[:t]
    result = 1
    for i in indices:
        result = result * pow(int(valid[i]["d_i"], 16), lagrange_coefficient(i, indices, q), p) % p
    return result
