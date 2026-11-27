"""Essam's registry/ledger consolidated into one atomic application transaction.

One server process owns the store. Its thread lock serializes registration, request
sequence checks, application changes and accepted ledger entries. An atomic rename
commits the whole snapshot, so a failed operation never consumes a sequence number.
"""
import copy
from contextlib import contextmanager
import json
import os
from pathlib import Path
import threading
from .config import GROUP
from .encoding import canonical_json


class StateStore:
    def __init__(self, path: Path, setup_id: str):
        self.path = path
        self.lock = threading.RLock()
        if path.exists():
            self.data = json.loads(path.read_text("utf-8"))
            if self.data["group"] != GROUP or self.data["setup_id"] != setup_id:
                raise ValueError("state belongs to another GROUP/vault setup")
        else:
            self.data = {"group": GROUP, "setup_id": setup_id, "members": {}, "last_seq": {},
                         "ledger": [], "next_vote": 1, "operations": {}, "used_proofs": []}

    @contextmanager
    def transaction(self):
        with self.lock:
            candidate = copy.deepcopy(self.data)
            yield candidate
            self.path.parent.mkdir(parents=True, exist_ok=True)
            temporary = self.path.with_suffix(".tmp")
            with temporary.open("wb") as stream:
                stream.write(canonical_json(candidate))
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, self.path)
            self.data = candidate

    def snapshot(self):
        with self.lock:
            return copy.deepcopy(self.data)
