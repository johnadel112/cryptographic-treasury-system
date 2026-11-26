"""Milestone 2 Shamir sharing and public commitments."""

def evaluate_polynomial(coefficients: list[int], x: int, q: int) -> int:
    """TODO: evaluate f(x)=a0+a1*x+... modulo q using Horner's method."""
    raise NotImplementedError


def make_shares(secret: int, t: int, n: int, q: int) -> tuple[list[int], list[int]]:
    """TODO: random degree-(t-1) polynomial; return coefficients and shares."""
    raise NotImplementedError


def verify_share(share: int, member_index: int, commitments: list[int], p: int, q: int, g: int) -> bool:
    """TODO: check g^share equals C0*C1^i*... modulo p."""
    raise NotImplementedError


def lagrange_coefficient(i: int, selected_indices: list[int], q: int) -> int:
    """TODO: coefficient at zero for selected member i; use modular inverses."""
    raise NotImplementedError
