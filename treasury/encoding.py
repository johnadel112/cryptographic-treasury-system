"""Canonical encoding and shared project hash helper."""
import hashlib
import json
from typing import Any

from .config import GROUP


def canonical_json(value: Any) -> bytes:
    """Canonical JSON bytes required for signed/hashed JSON values."""
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("utf-8")


def H(label: str, *values: Any, q: int) -> int:
    """Project challenge hash: H(label, values...) modulo q.

    Integers are represented as lowercase hexadecimal strings, matching the
    project specification. Strings remain strings.
    """
    encoded_values = [v if isinstance(v, str) else format(v, "x") for v in values]
    payload = json.dumps(["ICS505", GROUP, label, *encoded_values],
                         separators=(",", ":"), allow_nan=False).encode("utf-8")
    return int.from_bytes(hashlib.sha256(payload).digest(), "big") % q


def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def hex_int(value: str, *, limit: int, nonzero: bool = False) -> int:
    """Canonical lowercase hex integer, bounded before expensive arithmetic."""
    import re
    if not isinstance(value, str) or len(value) > len(format(limit, "x")) or not re.fullmatch(r"0|[1-9a-f][0-9a-f]*", value):
        raise ValueError("invalid canonical hexadecimal integer")
    number = int(value, 16)
    if not (int(nonzero) <= number < limit):
        raise ValueError("scalar/integer outside permitted range")
    return number


def group_int(value: str) -> int:
    from .config import P, valid_group_element
    number = hex_int(value, limit=P)
    if not valid_group_element(number):
        raise ValueError("invalid subgroup element")
    return number
