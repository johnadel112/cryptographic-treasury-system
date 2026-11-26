"""Milestone 1 proof-of-knowledge login."""

def register_login_secret(name: str, p: int, q: int, g: int) -> tuple[int, int]:
    """TODO: choose x_M in Z_q and return (secret x_M, public X_M=g^x_M mod p)."""
    raise NotImplementedError


def make_interactive_response(x_M: int, challenge: int, q: int) -> tuple[int, int]:
    """TODO: produce fresh R=g^k and z=k+e*x_M mod q."""
    raise NotImplementedError


def verify_interactive_login(R: int, z: int, e: int, X_M: int, p: int, q: int, g: int) -> bool:
    """TODO: check group element and g^z = R * X_M^e mod p."""
    raise NotImplementedError


def make_noninteractive_response(*args, **kwargs):
    """TODO: implement non_interactive response"""
    raise NotImplementedError
