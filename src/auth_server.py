"""Threaded TCP server implementing Milestone 1 authentication & M2/M3 dispatch."""

import logging
import secrets
import socket
import threading
from pathlib import Path
from typing import Any, Callable, Dict, Optional

from .channel import ChannelError, SecureChannel, server_handshake
from .config import DATA_DIR, G, GROUP, LOGS_DIR, P, Q, SERVER_HOST, SERVER_PORT
from .crypto_utils import hash_to_zq, hex_to_pub, verify_sig
from .keys import load_owner_keys
from .ledger import AuthRegistry, RequestLedger


def build_logger(name: str, log_file: Optional[Path] = None) -> logging.Logger:
    """Create a logger that writes to both stream and optional file."""
    logger = logging.getLogger(name)
    logger.setLevel(logging.INFO)
    logger.handlers.clear()
    formatter = logging.Formatter("%(asctime)s [%(name)s] %(levelname)s %(message)s")
    sh = logging.StreamHandler()
    sh.setFormatter(formatter)
    logger.addHandler(sh)
    if log_file is not None:
        log_file.parent.mkdir(parents=True, exist_ok=True)
        fh = logging.FileHandler(log_file, mode="w", encoding="utf-8")
        fh.setFormatter(formatter)
        logger.addHandler(fh)
    logger.propagate = False
    return logger


class TreasuryAuthServer:
    """Authentication and signed-request server for the Treasury system."""

    def __init__(
        self,
        host: str = SERVER_HOST,
        port: int = SERVER_PORT,
        data_dir: Path = DATA_DIR,
        group: str = GROUP,
        log_file: Optional[Path] = LOGS_DIR / "server.log",
        weak_unsigned_handshake: bool = False,
        weak_no_encryption: bool = False,
        weak_short_challenge: bool = False,
        weak_no_nonce: bool = False,
        weak_unsigned_ballots: bool = False,
        op_handlers: Optional[Dict[str, Callable[[str, Dict[str, Any]], Dict[str, Any]]]] = None,
    ) -> None:
        self.host = host
        self.port = port
        self.data_dir = Path(data_dir)
        self.group = group
        self.weak_unsigned_handshake = weak_unsigned_handshake
        self.weak_no_encryption = weak_no_encryption
        self.weak_short_challenge = weak_short_challenge
        self.weak_no_nonce = weak_no_nonce
        self.weak_unsigned_ballots = weak_unsigned_ballots
        self.op_handlers = op_handlers or {}

        server_keys = load_owner_keys("server", self.data_dir)
        self.server_priv = server_keys["ecdsa_priv_obj"]
        self.server_cert = server_keys["cert"]
        self.founder_pub = server_keys["founder_pub_obj"]

        self.registry = AuthRegistry(self.data_dir / "registry.json")
        self.ledger = RequestLedger(self.data_dir / "ledger.jsonl")
        self.ballots: Dict[int, Dict[str, Dict[str, Any]]] = {}
        self._ballot_lock = threading.Lock()
        self.logger = build_logger(f"server:{port}", log_file)

        self._sock: Optional[socket.socket] = None
        self._stop_event = threading.Event()
        self._threads: list[threading.Thread] = []

    def start(self) -> None:
        """Bind and start accepting connections in a background thread."""
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind((self.host, self.port))
        self._sock.listen(32)
        self._sock.settimeout(0.2)
        t = threading.Thread(target=self._accept_loop, daemon=True)
        t.start()
        self._threads.append(t)
        self.logger.info(
            "Server listening on %s:%d (group=%s)", self.host, self.port, self.group
        )

    def stop(self) -> None:
        """Stop accepting connections and close listening socket."""
        self._stop_event.set()
        if self._sock is not None:
            try:
                self._sock.close()
            except OSError:
                pass
        for t in self._threads:
            t.join(timeout=1.0)
        for h in list(self.logger.handlers):
            h.close()

    def _accept_loop(self) -> None:
        assert self._sock is not None
        while not self._stop_event.is_set():
            try:
                conn, addr = self._sock.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            t = threading.Thread(target=self._handle_client, args=(conn, addr), daemon=True)
            t.start()
            self._threads.append(t)

    def _handle_client(self, conn: socket.socket, addr: Any) -> None:
        member_name = "<unknown>"
        channel: Optional[SecureChannel] = None
        try:
            channel, member_name, member_cert = server_handshake(
                conn,
                self.server_priv,
                self.server_cert,
                self.founder_pub,
                self.group,
                weak_unsigned=self.weak_unsigned_handshake,
                weak_no_encryption=self.weak_no_encryption,
            )
            self.logger.info("Handshake OK with %s from %s", member_name, addr)
            member_pub = hex_to_pub(member_cert["pubkey"])
            authenticated = False
            pending_interactive: Optional[tuple[int, int]] = None  # (R, e)

            while not self._stop_event.is_set():
                try:
                    msg = channel.recv_json()
                except ChannelError as exc:
                    self.logger.warning("Channel closed for %s: %s", member_name, exc)
                    break

                mtype = msg.get("type")

                if mtype == "register":
                    x_pub_hex = msg.get("X_M", "")
                    if not isinstance(x_pub_hex, str) or not x_pub_hex:
                        channel.send_json({"ok": False, "error": "Invalid X_M"})
                        continue
                    ok, reason = self.registry.register_member(member_name, x_pub_hex)
                    self.logger.info(
                        "Register %s -> %s (%s)", member_name, "OK" if ok else "REJECT", reason
                    )
                    channel.send_json({"ok": ok, "reason": reason})

                elif mtype == "login_interactive_start":
                    x_m = self.registry.get_public_login(member_name)
                    if x_m is None:
                        channel.send_json({"ok": False, "error": "Member not registered"})
                        continue
                    r_int = int(msg["R"], 16)
                    e_int = (
                        secrets.randbits(4)
                        if self.weak_short_challenge
                        else secrets.randbits(128)
                    )
                    pending_interactive = (r_int, e_int)
                    channel.send_json({"ok": True, "e": hex(e_int)})

                elif mtype == "login_interactive_finish":
                    if pending_interactive is None:
                        channel.send_json({"ok": False, "error": "No pending interactive login"})
                        continue
                    r_int, e_int = pending_interactive
                    pending_interactive = None
                    x_m = self.registry.get_public_login(member_name)
                    if x_m is None:
                        channel.send_json({"ok": False, "error": "Member not registered"})
                        continue
                    z_int = int(msg["z"], 16)
                    lhs = pow(G, z_int, P)
                    rhs = (r_int * pow(x_m, e_int, P)) % P
                    if lhs == rhs:
                        authenticated = True
                        self.logger.info("login %s OK (interactive)", member_name)
                        channel.send_json({"ok": True})
                    else:
                        self.logger.warning("login %s FAIL (interactive)", member_name)
                        channel.send_json({"ok": False, "error": "Invalid Schnorr proof"})

                elif mtype == "login_noninteractive_nonce":
                    if self.registry.get_public_login(member_name) is None:
                        channel.send_json({"ok": False, "error": "Member not registered"})
                        continue
                    nonce_hex = hex(secrets.randbits(128))
                    self.registry.issue_nonce(member_name, nonce_hex)
                    channel.send_json({"ok": True, "N": nonce_hex})

                elif mtype == "login_noninteractive":
                    x_m = self.registry.get_public_login(member_name)
                    x_m_hex = self.registry.get_public_login_hex(member_name)
                    if x_m is None or x_m_hex is None:
                        channel.send_json({"ok": False, "error": "Member not registered"})
                        continue
                    nonce_hex = msg.get("N", "")
                    if not self.weak_no_nonce:
                        ok_n, reason_n = self.registry.consume_nonce(member_name, nonce_hex)
                        if not ok_n:
                            self.logger.warning(
                                "login %s FAIL (noninteractive): %s", member_name, reason_n
                            )
                            channel.send_json({"ok": False, "error": reason_n})
                            continue
                    r_hex = msg.get("R", "")
                    z_hex = msg.get("z", "")
                    r_int = int(r_hex, 16)
                    z_int = int(z_hex, 16)
                    if self.weak_no_nonce:
                        e_int = hash_to_zq("login", member_name, x_m_hex, r_hex)
                    else:
                        e_int = hash_to_zq("login", member_name, x_m_hex, r_hex, nonce_hex)
                    lhs = pow(G, z_int, P)
                    rhs = (r_int * pow(x_m, e_int, P)) % P
                    if lhs == rhs:
                        authenticated = True
                        self.logger.info("login %s OK (noninteractive)", member_name)
                        channel.send_json({"ok": True})
                    else:
                        self.logger.warning("login %s FAIL (noninteractive)", member_name)
                        channel.send_json({"ok": False, "error": "Invalid Schnorr proof"})

                elif mtype == "request":
                    if not authenticated:
                        self.logger.warning(
                            "Unauthenticated request rejected from %s", member_name
                        )
                        channel.send_json({"ok": False, "error": "Not authenticated"})
                        continue
                    op = msg.get("op")
                    seq = msg.get("seq")
                    body = msg.get("body")
                    sig = msg.get("sig", "")
                    payload = ["request", self.group, member_name, seq, op, body]
                    if not verify_sig(member_pub, payload, sig):
                        self.logger.warning(
                            "Request signature invalid for %s seq=%s op=%s",
                            member_name,
                            seq,
                            op,
                        )
                        channel.send_json({"ok": False, "error": "Invalid request signature"})
                        continue
                    ok_seq, reason_seq = self.registry.check_and_update_seq(member_name, seq)
                    if not ok_seq:
                        self.logger.warning(
                            "Request replay/seq rejected for %s: %s", member_name, reason_seq
                        )
                        channel.send_json({"ok": False, "error": reason_seq})
                        continue
                    entry = self.ledger.append(member_name, seq, op, body, sig)
                    self.logger.info(
                        "Accepted request member=%s seq=%d op=%s", member_name, seq, op
                    )
                    resp: Dict[str, Any] = {"ok": True, "entry": entry}
                    if op in self.op_handlers:
                        resp["result"] = self.op_handlers[op](member_name, body)
                    channel.send_json(resp)

                elif mtype == "ballot":
                    if not authenticated:
                        channel.send_json({"ok": False, "error": "Not authenticated"})
                        continue
                    vote_number = msg.get("vote_number")
                    c_1 = msg.get("c_1")
                    c_2 = msg.get("c_2")
                    sig = msg.get("sig", "")
                    if not self.weak_unsigned_ballots:
                        payload = ["ballot", self.group, member_name, vote_number, c_1, c_2]
                        if not verify_sig(member_pub, payload, sig):
                            self.logger.warning(
                                "Ballot signature invalid for %s vote=%s",
                                member_name,
                                vote_number,
                            )
                            channel.send_json({"ok": False, "error": "Invalid ballot signature"})
                            continue
                    with self._ballot_lock:
                        vote_map = self.ballots.setdefault(int(vote_number), {})
                        if member_name in vote_map:
                            channel.send_json({"ok": False, "error": "Duplicate ballot rejected"})
                            continue
                        vote_map[member_name] = {
                            "c_1": c_1,
                            "c_2": c_2,
                            "sig": sig,
                        }
                    # Note: server log never logs plaintext vote
                    self.logger.info(
                        "Accepted encrypted ballot member=%s vote=%s", member_name, vote_number
                    )
                    channel.send_json({"ok": True})

                else:
                    channel.send_json({"ok": False, "error": f"Unknown message type: {mtype}"})

        except ChannelError as exc:
            self.logger.warning("Handshake/channel failed for %s: %s", member_name, exc)
        except Exception as exc:
            self.logger.exception("Unexpected server error for %s: %s", member_name, exc)
        finally:
            if channel is not None:
                channel.close()
            else:
                try:
                    conn.close()
                except OSError:
                    pass
