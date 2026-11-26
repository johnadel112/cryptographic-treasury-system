"""Member client implementing Milestone 1 auth, signed requests, and M2/M3 helpers."""

import logging
import socket
from pathlib import Path
from typing import Any, Dict, Optional

from .channel import SecureChannel, client_handshake
from .config import DATA_DIR, G, GROUP, LOGS_DIR, P, Q, SERVER_HOST, SERVER_PORT
from .crypto_utils import hash_to_zq, random_zq_scalar, sign_data
from .keys import load_owner_keys


class TreasuryMemberClient:
    """Authenticated member client session."""

    def __init__(
        self,
        member_name: str,
        host: str = SERVER_HOST,
        port: int = SERVER_PORT,
        data_dir: Path = DATA_DIR,
        group: str = GROUP,
        log_file: Optional[Path] = None,
        weak_unsigned_handshake: bool = False,
        weak_no_encryption: bool = False,
    ) -> None:
        self.member_name = member_name
        self.host = host
        self.port = port
        self.data_dir = Path(data_dir)
        self.group = group
        self.weak_unsigned_handshake = weak_unsigned_handshake
        self.weak_no_encryption = weak_no_encryption

        keys = load_owner_keys(member_name, self.data_dir)
        self.ecdsa_priv = keys["ecdsa_priv_obj"]
        self.cert = keys["cert"]
        self.founder_pub = keys["founder_pub_obj"]
        self.x_m = keys["login_secret_x_int"]
        self.big_x_m_hex = keys["login_public_X"]

        self.channel: Optional[SecureChannel] = None
        self.seq = 0
        self.logger = logging.getLogger(f"client:{member_name}")
        self.logger.setLevel(logging.INFO)
        self.logger.handlers.clear()
        fmt = logging.Formatter("%(asctime)s [%(name)s] %(levelname)s %(message)s")
        sh = logging.StreamHandler()
        sh.setFormatter(fmt)
        self.logger.addHandler(sh)
        if log_file is not None:
            log_file.parent.mkdir(parents=True, exist_ok=True)
            fh = logging.FileHandler(log_file, mode="w", encoding="utf-8")
            fh.setFormatter(fmt)
            self.logger.addHandler(fh)
        self.logger.propagate = False

    def connect(self) -> None:
        """Open TCP connection and run authenticated ECDH handshake."""
        sock = socket.create_connection((self.host, self.port), timeout=5.0)
        self.channel = client_handshake(
            sock,
            self.member_name,
            self.ecdsa_priv,
            self.cert,
            self.founder_pub,
            self.group,
            weak_unsigned=self.weak_unsigned_handshake,
            weak_no_encryption=self.weak_no_encryption,
        )
        self.logger.info("Connected & handshake complete with %s:%d", self.host, self.port)

    def close(self) -> None:
        if self.channel is not None:
            self.channel.close()
            self.channel = None
        for h in list(self.logger.handlers):
            h.close()

    def register(self) -> Dict[str, Any]:
        """Send public login value X_M = g^(x_M) mod p to the server."""
        assert self.channel is not None
        self.channel.send_json({"type": "register", "X_M": self.big_x_m_hex})
        resp = self.channel.recv_json()
        self.logger.info("Register response: %s", resp)
        return resp

    def login_interactive(self) -> Dict[str, Any]:
        """Perform interactive Schnorr zero-knowledge login."""
        assert self.channel is not None
        k = random_zq_scalar()
        r_int = pow(G, k, P)
        self.channel.send_json({"type": "login_interactive_start", "R": hex(r_int)})
        resp1 = self.channel.recv_json()
        if not resp1.get("ok"):
            return resp1
        e_int = int(resp1["e"], 16)
        z_int = (k + e_int * self.x_m) % Q
        self.channel.send_json({"type": "login_interactive_finish", "z": hex(z_int)})
        resp2 = self.channel.recv_json()
        self.logger.info("Interactive login response: %s", resp2)
        return resp2

    def login_noninteractive(self, weak_no_nonce: bool = False) -> Dict[str, Any]:
        """Perform non-interactive Schnorr ZK login with fresh server nonce N."""
        assert self.channel is not None
        self.channel.send_json({"type": "login_noninteractive_nonce"})
        resp1 = self.channel.recv_json()
        if not resp1.get("ok"):
            return resp1
        nonce_hex = resp1["N"]
        k = random_zq_scalar()
        r_hex = hex(pow(G, k, P))
        if weak_no_nonce:
            e_int = hash_to_zq("login", self.member_name, self.big_x_m_hex, r_hex)
        else:
            e_int = hash_to_zq(
                "login", self.member_name, self.big_x_m_hex, r_hex, nonce_hex
            )
        z_hex = hex((k + e_int * self.x_m) % Q)
        self.channel.send_json(
            {"type": "login_noninteractive", "N": nonce_hex, "R": r_hex, "z": z_hex}
        )
        resp2 = self.channel.recv_json()
        self.logger.info("Non-interactive login response: %s", resp2)
        return resp2

    def send_request(
        self, op: str, body: Dict[str, Any], seq: Optional[int] = None
    ) -> Dict[str, Any]:
        """Send an ECDSA-signed request {"op", "seq", "body", "sig"}."""
        assert self.channel is not None
        if seq is None:
            self.seq += 1
            seq = self.seq
        payload = ["request", self.group, self.member_name, seq, op, body]
        sig = sign_data(self.ecdsa_priv, payload)
        self.channel.send_json(
            {"type": "request", "op": op, "seq": seq, "body": body, "sig": sig}
        )
        resp = self.channel.recv_json()
        self.logger.info("Request op=%s seq=%d -> %s", op, seq, resp.get("ok"))
        return resp

    # --- Milestone 2 & 3 authenticated session integration helpers ---

    def submit_vault_open_request(self, vault_id: str, reason: str = "") -> Dict[str, Any]:
        """Milestone 2: submit signed vault-opening request over authenticated session."""
        return self.send_request("open_vault", {"vault_id": vault_id, "reason": reason})

    def submit_decryption_contribution(
        self,
        vault_id: str,
        member_index: int,
        d_i: str,
        t_1: str,
        t_2: str,
        z: str,
    ) -> Dict[str, Any]:
        """Milestone 2/3: submit signed decryption contribution over authenticated session."""
        return self.send_request(
            "decrypt_share",
            {
                "vault_id": vault_id,
                "index": member_index,
                "d_i": d_i,
                "T_1": t_1,
                "T_2": t_2,
                "z": z,
            },
        )

    def submit_spending_request(self, amount: int, reason: str) -> Dict[str, Any]:
        """Milestone 3: submit signed spending request over authenticated session."""
        return self.send_request("spend_request", {"amount": amount, "reason": reason})

    def submit_ballot(
        self,
        vote_number: int,
        c_1: str,
        c_2: str,
        unsigned: bool = False,
    ) -> Dict[str, Any]:
        """Milestone 3: submit ECDSA-signed ballot over authenticated session."""
        assert self.channel is not None
        sig = (
            ""
            if unsigned
            else sign_data(
                self.ecdsa_priv,
                ["ballot", self.group, self.member_name, vote_number, c_1, c_2],
            )
        )
        self.channel.send_json(
            {
                "type": "ballot",
                "vote_number": vote_number,
                "c_1": c_1,
                "c_2": c_2,
                "sig": sig,
            }
        )
        resp = self.channel.recv_json()
        self.logger.info("Ballot vote=%d -> %s", vote_number, resp.get("ok"))
        return resp
