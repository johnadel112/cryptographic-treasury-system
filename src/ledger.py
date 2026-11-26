"""Member login registry, single-use nonce store, sequence tracker, and request ledger."""

import json
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple


class AuthRegistry:
    """Persistent store for member public login values X_M and last sequence numbers."""

    def __init__(self, path: Path) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._members: Dict[str, str] = {}
        self._last_seq: Dict[str, int] = {}
        self._used_nonces: set[str] = set()
        self._issued_nonces: Dict[str, str] = {}
        self._load()

    def _load(self) -> None:
        if self.path.exists():
            data = json.loads(self.path.read_text(encoding="utf-8"))
            self._members = dict(data.get("members", {}))
            self._last_seq = {k: int(v) for k, v in data.get("last_seq", {}).items()}

    def _save(self) -> None:
        self.path.write_text(
            json.dumps(
                {
                    "members": self._members,
                    "last_seq": self._last_seq,
                },
                indent=2,
            ),
            encoding="utf-8",
        )

    def register_member(self, name: str, x_pub_hex: str) -> Tuple[bool, str]:
        """Register X_M for name; keeps first X_M and rejects replacement."""
        with self._lock:
            if name in self._members:
                if self._members[name] == x_pub_hex:
                    return False, "Already registered; replacement not permitted"
                return False, "Unauthorized registration replacement rejected"
            self._members[name] = x_pub_hex
            self._last_seq.setdefault(name, 0)
            self._save()
            return True, "Registered"

    def get_public_login(self, name: str) -> Optional[int]:
        """Return registered X_M as int, or None if not registered."""
        with self._lock:
            val = self._members.get(name)
            return int(val, 16) if val is not None else None

    def get_public_login_hex(self, name: str) -> Optional[str]:
        """Return registered X_M as hex string, or None if not registered."""
        with self._lock:
            return self._members.get(name)

    def issue_nonce(self, member_name: str, nonce_hex: str) -> None:
        """Record a freshly generated server nonce for non-interactive login."""
        with self._lock:
            self._issued_nonces[nonce_hex] = member_name

    def consume_nonce(self, member_name: str, nonce_hex: str) -> Tuple[bool, str]:
        """Validate and consume a server nonce so each N is accepted only once."""
        with self._lock:
            if nonce_hex in self._used_nonces:
                return False, "Nonce already used (replay rejected)"
            expected_member = self._issued_nonces.get(nonce_hex)
            if expected_member is None:
                return False, "Unknown or unissued server nonce"
            if expected_member != member_name:
                return False, "Nonce was not issued to this member"
            del self._issued_nonces[nonce_hex]
            self._used_nonces.add(nonce_hex)
            return True, "OK"

    def check_and_update_seq(self, name: str, seq: int) -> Tuple[bool, str]:
        """Verify seq > last_seq[name] and update on success."""
        with self._lock:
            last = self._last_seq.get(name, 0)
            if not isinstance(seq, int) or seq <= last:
                return False, f"Invalid sequence number {seq} (last={last})"
            self._last_seq[name] = seq
            self._save()
            return True, "OK"

    def get_last_seq(self, name: str) -> int:
        with self._lock:
            return self._last_seq.get(name, 0)


class RequestLedger:
    """Append-only ledger of accepted ECDSA-signed requests."""

    def __init__(self, path: Path) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()

    def append(self, member: str, seq: int, op: str, body: Any, sig: str) -> Dict[str, Any]:
        """Append an accepted request entry to the ledger file."""
        entry = {
            "ts": datetime.now(timezone.utc).isoformat(),
            "member": member,
            "seq": seq,
            "op": op,
            "body": body,
            "sig": sig,
        }
        with self._lock:
            with self.path.open("a", encoding="utf-8") as fh:
                fh.write(json.dumps(entry, separators=(",", ":"), sort_keys=True) + "\n")
        return entry

    def entries(self) -> List[Dict[str, Any]]:
        """Return all accepted ledger entries."""
        with self._lock:
            if not self.path.exists():
                return []
            lines = self.path.read_text(encoding="utf-8").splitlines()
            return [json.loads(line) for line in lines if line.strip()]
