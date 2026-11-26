"""Milestone 1 signed requests and sequence-number replay protection."""

def request_transcript(group: str, name: str, seq: int, op: str, body: dict) -> list:
    return ["request", group, name, seq, op, body]


def sign_request(private_key, group: str, name: str, seq: int, op: str, body: dict) -> dict:
    """TODO: ECDSA-sign canonical_json(request_transcript(...))."""
    raise NotImplementedError


def verify_request(public_key, request: dict, last_sequence: int) -> bool:
    """TODO: verify signature and require seq > last_sequence."""
    raise NotImplementedError
