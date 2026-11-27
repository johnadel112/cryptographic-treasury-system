"""Yassin's ElGamal multiplication/count recovery, integrated with exact signatures."""
import secrets
from cryptography.exceptions import InvalidSignature
from .config import P, Q, G, GROUP, valid_group_element
from .certificates import sign, verify_signature
from .encoding import group_int


def encrypt_vote(vote: int, public_key: int, p: int = P, q: int = Q, g: int = G) -> tuple[int, int]:
    if type(vote) is not int or vote not in (0, 1) or not valid_group_element(public_key):
        raise ValueError("vote must be 0 or 1 and key a valid subgroup element")
    while True:
        r = secrets.randbelow(q - 1) + 1
        c1, c2 = pow(g, r, p), pow(g, vote, p)*pow(public_key, r, p) % p
        if c2 != 1:
            return c1, c2


def ballot_transcript(group: str, member_name: str, vote_number: int, c1, c2) -> list:
    return ["ballot", group, member_name, vote_number,
            format(c1, "x") if isinstance(c1, int) else c1,
            format(c2, "x") if isinstance(c2, int) else c2]


def make_ballot(key, name: str, vote_number: int, vote: int, public_key: int, *, unsigned=False) -> dict:
    c1, c2 = encrypt_vote(vote, public_key)
    ballot = {"type": "ballot", "vote_number": vote_number, "c1": format(c1, "x"), "c2": format(c2, "x")}
    if not unsigned:
        ballot["sig"] = sign(key, ballot_transcript(GROUP, name, vote_number, c1, c2))
    return ballot


def verify_ballot(public_key, name: str, ballot: dict, *, unsigned=False) -> bool:
    try:
        if type(ballot["vote_number"]) is not int or ballot["vote_number"] < 1:
            return False
        group_int(ballot["c1"]); group_int(ballot["c2"])
        expected = {"type", "vote_number", "c1", "c2"}
        if unsigned:
            if set(ballot) not in (expected, expected | {"sig"}):
                return False
        else:
            if set(ballot) != expected | {"sig"}:
                return False
            verify_signature(public_key, ballot["sig"], ballot_transcript(GROUP, name, ballot["vote_number"], ballot["c1"], ballot["c2"]))
        return True
    except (ValueError, KeyError, TypeError, InvalidSignature):
        return False


def aggregate_ciphertexts(ballots) -> tuple[int, int]:
    c1 = c2 = 1
    for ballot in ballots:
        c1 = c1 * group_int(ballot["c1"]) % P
        c2 = c2 * group_int(ballot["c2"]) % P
    return c1, c2


def recover_yes_count(element: int, max_ballots: int) -> int:
    current = 1
    for count in range(max_ballots + 1):
        if current == element:
            return count
        current = current * G % P
    raise ValueError("aggregate tally outside permitted count range")
