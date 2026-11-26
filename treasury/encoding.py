"""Canonical encoding and shared project hash helper."""
import hashlib
import json
from typing import Any

from .config import GROUP


def canonical_json(value: Any) -> bytes:
    """Canonical JSON bytes required for signed/hashed JSON values."""
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")


def H(label: str, *values: Any, q: int) -> int:
    """Project challenge hash: H(label, values...) modulo q.

    Integers are represented as lowercase hexadecimal strings, matching the
    project specification. Strings remain strings.
    """
    encoded_values = [v if isinstance(v, str) else format(v, "x") for v in values]
    payload = json.dumps(["ICS505", GROUP, label, *encoded_values],
                         separators=(",", ":")).encode("utf-8")
    return int.from_bytes(hashlib.sha256(payload).digest(), "big") % q


def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()
