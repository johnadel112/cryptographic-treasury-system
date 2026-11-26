"""Milestone 3 encrypted yes/no ballots."""

def encrypt_vote(vote: int, public_key: int, p: int, q: int, g: int):
    """TODO: ElGamal-style encryption of v in {0,1}: (g^r, g^v*h^r)."""
    raise NotImplementedError


def ballot_transcript(group: str, member_name: str, vote_number: int,
                      c1: int, c2: int) -> list:
    return ["ballot", group, member_name, vote_number, c1, c2]


def verify_ballot(*args, **kwargs) -> bool:
    """TODO: verify member signature and enforce one ballot per member."""
    raise NotImplementedError
