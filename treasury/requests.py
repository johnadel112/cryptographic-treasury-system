"""Exact assignment request transcript, signature and sequence validation."""
from cryptography.exceptions import InvalidSignature
from .certificates import sign, verify_signature
from .config import GROUP


def request_transcript(group: str, name: str, seq: int, op: str, body: dict) -> list:
    return ["request", group, name, seq, op, body]


def sign_request(private_key, group: str, name: str, seq: int, op: str, body: dict) -> dict:
    return {"op": op, "seq": seq, "body": body,
            "sig": sign(private_key, request_transcript(group, name, seq, op, body))}


def verify_request(public_key, request: dict, last_sequence: int, *, name: str) -> bool:
    try:
        if set(request) != {"op", "seq", "body", "sig"}:
            return False
        seq, op, body = request["seq"], request["op"], request["body"]
        if type(seq) is not int or not last_sequence < seq < (1 << 63):
            return False
        if not isinstance(op, str) or not isinstance(body, dict):
            return False
        verify_signature(public_key, request["sig"], request_transcript(GROUP, name, seq, op, body))
        return True
    except (InvalidSignature, ValueError, TypeError, KeyError):
        return False
