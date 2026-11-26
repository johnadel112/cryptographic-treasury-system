"""Milestone 2 verifiable decryption shares. A5 is mandatory."""

def make_decryption_share(share: int, member_index: int, c1: int, *args, **kwargs):
    """TODO: d_i=c1^s_i and a Chaum-Pedersen equality-of-discrete-logs proof."""
    raise NotImplementedError


def verify_decryption_share(*args, **kwargs) -> bool:
    """TODO: verify both proof equations before accepting d_i.

    Mandatory A5 comparison: --weak no-proof must skip this verification;
    secure mode must reject an invalid/missing proof and continue with valid
    participants if at least t valid shares remain.
    """
    raise NotImplementedError


def combine_decryption_shares(*args, **kwargs):
    """TODO: Lagrange-combine t accepted decryption shares."""
    raise NotImplementedError
