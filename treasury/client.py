"""Essam's member conversation, migrated onto the single treasury Session API."""
from pathlib import Path
import socket
from .channel import member_handshake
from .config import DATA_DIR, HOST, SERVER_PORT, SOCKET_TIMEOUT_SECONDS, GROUP, P, Q, G
from .identity import load_identity
from .login import load_login_secret, make_commitment, make_interactive_response, make_noninteractive_response
from .requests import sign_request
from .encoding import group_int, hex_int
from .logging_utils import get_logger
from .vault import check_vault_public, load_member_share, trusted_verification_keys
from .sharing import verify_share
from .opening import make_decryption_share
from .voting import make_ballot


class TreasuryMemberClient:
    def __init__(self, member_name: str, *, data_dir: Path = DATA_DIR, port: int = SERVER_PORT,
                 weak=None, unsigned_ballots=False):
        self.name = member_name
        self.root = data_dir
        self.port = port
        self.weak = weak
        self.unsigned_ballots = unsigned_ballots
        self.identity = load_identity(member_name, data_dir)
        self.log = get_logger(member_name)
        self.session = None
        self.seq = 0

    def connect(self):
        sock = socket.create_connection((HOST, self.port), timeout=SOCKET_TIMEOUT_SECONDS)
        self.session = member_handshake(sock, self.identity, self.log, weak=self.weak)
        return self

    def close(self):
        if self.session:
            self.session.close()

    def __enter__(self):
        return self.connect()

    def __exit__(self, *args):
        self.close()

    def exchange(self, message):
        self.session.send(message)
        response = self.session.receive()
        if response is None:
            raise ConnectionError("server disconnected")
        return response

    def info(self):
        result = self.exchange({"type": "info"})
        check_vault_public(result["vault"], self.identity.founder_public_key)
        return result

    def register(self):
        x = load_login_secret(self.name, self.root)
        return self.exchange({"type": "register", "X_M": format(pow(G, x, P), "x")})

    def login(self, method="interactive"):
        info = self.info()
        if not info["registered"]:
            registered = self.register()
            if not registered["ok"]:
                return registered
        x = load_login_secret(self.name, self.root)
        if method == "interactive":
            k, R = make_commitment()
            challenge = self.exchange({"type": "login_interactive_start", "R": format(R, "x")})
            if not challenge["ok"]:
                return challenge
            e = hex_int(challenge["e"], limit=1 << 128)
            result = self.exchange({"type": "login_interactive_finish",
                                   "z": format(make_interactive_response(x, e, k=k), "x")})
        elif method == "noninteractive":
            nonce = self.exchange({"type": "login_noninteractive_nonce"})
            if not nonce["ok"]:
                return nonce
            proof = make_noninteractive_response(self.name, x, hex_int(nonce["N"], limit=1 << 128))
            result = self.exchange({"type": "login_noninteractive", **proof})
        else:
            raise ValueError("unknown login method")
        if result["ok"]:
            self.seq = result["last_seq"]
        self.log.info("%s login result=%s", method, result["ok"])
        return result

    def request(self, op, body, *, seq=None):
        seq = self.seq + 1 if seq is None else seq
        result = self.exchange(sign_request(self.identity.private_key, GROUP, self.name, seq, op, body))
        if result["ok"]:
            self.seq = seq
        return result

    def contribute(self, operation_id: str, *, cheat=False):
        vault = self.info()["vault"]
        status = self.request("status", {"operation": operation_id})
        if not status["ok"]:
            return status
        operation = status["result"]
        if operation["state"] != "collecting":
            return {"ok": False, "error": "operation not collecting contributions"}
        try:
            record = load_member_share(self.root, self.name)
            share = hex_int(record["share"], limit=Q, nonzero=True)
            i = int(self.name[1:])
            commitments = [group_int(c) for c in vault["commitments"]]
            if not verify_share(share, i, commitments, P, Q, G):
                raise ValueError("share verification FAILED")
        except (ValueError, KeyError, OSError) as exc:
            self.request("share-complaint", {"reason": "local share invalid"})
            self.log.warning("share verification FAILED; signed complaint sent; refusing contribution")
            return {"ok": False, "error": str(exc)}
        self.log.info("share verification OK member=%s hi=%s", self.name, format(trusted_verification_keys(vault)[i],"x")[:8])
        proof = make_decryption_share(share, i, group_int(operation["c1"]), verification_key=trusted_verification_keys(vault)[i])
        if cheat:
            if self.name != "M3":
                raise ValueError("A5 controlled cheater must be M3")
            proof["d_i"] = format(int(proof["d_i"], 16) * G % P, "x")
            self.log.warning("A5 controlled M3 contribution: d_i multiplied by g; original proof retained")
        return self.request("contribute", {"operation": operation_id, "proof": proof})

    def ballot(self, vote_number: int, value: int):
        vault = self.info()["vault"]
        ballot = make_ballot(self.identity.private_key, self.name, vote_number, value,
                             group_int(vault["vault_key"]), unsigned=self.unsigned_ballots)
        return self.exchange(ballot)
