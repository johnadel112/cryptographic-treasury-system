"""Mallory attack implementations: A1 MITM proxy, A3 short-challenge, and frame replay."""

import json
import secrets
import socket
import threading
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from cryptography.hazmat.primitives.asymmetric import ec

from .auth_client import TreasuryMemberClient
from .auth_server import build_logger
from .channel import (
    ChannelError,
    SecureChannel,
    recv_raw_packet,
    send_raw_packet,
)
from .config import DATA_DIR, G, GROUP, LOGS_DIR, P, PROXY_PORT, SERVER_HOST, SERVER_PORT
from .crypto_utils import derive_channel_keys, generate_p256_keypair, hex_to_pub, pub_to_hex, random_zq_scalar
from .keys import load_owner_keys


class MalloryMitmProxy:
    """Attack A1: active MITM proxy on port 6000 forwarding to server on port 5050."""

    def __init__(
        self,
        listen_host: str = SERVER_HOST,
        listen_port: int = PROXY_PORT,
        target_host: str = SERVER_HOST,
        target_port: int = SERVER_PORT,
        group: str = GROUP,
        log_file: Optional[Path] = LOGS_DIR / "mallory_a1.log",
        tamper_first_request: bool = False,
    ) -> None:
        self.listen_host = listen_host
        self.listen_port = listen_port
        self.target_host = target_host
        self.target_port = target_port
        self.group = group
        self.tamper_first_request = tamper_first_request
        self.logger = build_logger("mallory:A1", log_file)
        self.captured_cleartext: List[Dict] = []

        self._sock: Optional[socket.socket] = None
        self._stop_event = threading.Event()
        self._threads: List[threading.Thread] = []

    def start(self) -> None:
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind((self.listen_host, self.listen_port))
        self._sock.listen(8)
        self._sock.settimeout(0.2)
        t = threading.Thread(target=self._accept_loop, daemon=True)
        t.start()
        self._threads.append(t)
        self.logger.info(
            "Mallory MITM proxy listening on %s:%d -> %s:%d",
            self.listen_host,
            self.listen_port,
            self.target_host,
            self.target_port,
        )

    def stop(self) -> None:
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
                c_sock, _ = self._sock.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            t = threading.Thread(target=self._mitm_session, args=(c_sock,), daemon=True)
            t.start()
            self._threads.append(t)

    def _mitm_session(self, c_sock: socket.socket) -> None:
        s_sock: Optional[socket.socket] = None
        try:
            s_sock = socket.create_connection((self.target_host, self.target_port), timeout=5.0)

            # 1. Intercept M1 -> Server: replace X with Mallory's X_mal
            msg1 = json.loads(recv_raw_packet(c_sock).decode("utf-8"))
            member_cert = msg1["cert"]
            member_name = member_cert["name"]
            x_m1_hex = msg1["X"]

            x_mal_priv, x_mal_pub = generate_p256_keypair()
            x_mal_hex = pub_to_hex(x_mal_pub)
            self.logger.info(
                "Intercepted handshake from %s: X_member=%s... replaced with X_mallory=%s...",
                member_name,
                x_m1_hex[:16],
                x_mal_hex[:16],
            )
            send_raw_packet(
                s_sock,
                json.dumps({"cert": member_cert, "X": x_mal_hex}).encode("utf-8"),
            )

            # 2. Intercept Server -> M1: replace Y with Mallory's Y_mal, strip sig
            msg2 = json.loads(recv_raw_packet(s_sock).decode("utf-8"))
            server_cert = msg2["cert"]
            y_srv_hex = msg2["Y"]

            y_mal_priv, y_mal_pub = generate_p256_keypair()
            y_mal_hex = pub_to_hex(y_mal_pub)
            send_raw_packet(
                c_sock,
                json.dumps({"cert": server_cert, "Y": y_mal_hex, "sig": ""}).encode("utf-8"),
            )

            # 3. Receive M1's msg3 (if M1 didn't abort), forward empty sig to server
            msg3_raw = recv_raw_packet(c_sock)
            send_raw_packet(s_sock, msg3_raw)

            # Derive separate session keys with client and server
            ss_c = y_mal_priv.exchange(ec.ECDH(), hex_to_pub(x_m1_hex))
            k_m2s_c, k_s2m_c = derive_channel_keys(
                ss_c, self.group, member_name, x_m1_hex, y_mal_hex
            )
            ch_client = SecureChannel(c_sock, send_key=k_s2m_c, recv_key=k_m2s_c)

            ss_s = x_mal_priv.exchange(ec.ECDH(), hex_to_pub(y_srv_hex))
            k_m2s_s, k_s2m_s = derive_channel_keys(
                ss_s, self.group, member_name, x_mal_hex, y_srv_hex
            )
            ch_server = SecureChannel(s_sock, send_key=k_m2s_s, recv_key=k_s2m_s)

            tampered = False
            while not self._stop_event.is_set():
                c_msg = ch_client.recv_json()
                self.captured_cleartext.append(c_msg)
                self.logger.info("CAPTURED IN CLEAR (%s -> server): %s", member_name, c_msg)

                if (
                    self.tamper_first_request
                    and not tampered
                    and c_msg.get("type") == "request"
                    and isinstance(c_msg.get("body"), dict)
                    and "amount" in c_msg["body"]
                ):
                    tampered = True
                    c_msg = json.loads(json.dumps(c_msg))
                    c_msg["body"]["amount"] = 9999
                    self.logger.info("TAMPERED request body amount -> 9999: %s", c_msg)

                ch_server.send_json(c_msg)
                s_msg = ch_server.recv_json()
                self.logger.info("CAPTURED IN CLEAR (server -> %s): %s", member_name, s_msg)
                ch_client.send_json(s_msg)

        except (ChannelError, OSError, EOFError) as exc:
            self.logger.info("MITM session ended: %s", exc)
        finally:
            for s in (c_sock, s_sock):
                if s is not None:
                    try:
                        s.close()
                    except OSError:
                        pass


def run_attack_a3(
    member_name: str = "M3",
    host: str = SERVER_HOST,
    port: int = SERVER_PORT,
    data_dir: Path = DATA_DIR,
    group: str = GROUP,
    max_attempts: int = 100,
    log_file: Optional[Path] = LOGS_DIR / "mallory_a3.log",
) -> Tuple[bool, int]:
    """Attack A3: guess 4-bit challenge e' and forge R = g^z * X_M^(-e') mod p."""
    logger = build_logger("mallory:A3", log_file)
    keys = load_owner_keys(member_name, data_dir)
    big_x_m = keys["login_public_X_int"]

    try:
        for attempt in range(1, max_attempts + 1):
            client = TreasuryMemberClient(
                member_name, host=host, port=port, data_dir=data_dir, group=group
            )
            client.connect()
            try:
                e_guess = secrets.randbits(4)
                z = random_zq_scalar()
                x_e_inv = pow(pow(big_x_m, e_guess, P), -1, P)
                r_forged = (pow(G, z, P) * x_e_inv) % P

                assert client.channel is not None
                client.channel.send_json(
                    {"type": "login_interactive_start", "R": hex(r_forged)}
                )
                resp1 = client.channel.recv_json()
                if not resp1.get("ok"):
                    logger.warning("Attempt %d aborted: %s", attempt, resp1)
                    return False, attempt

                client.channel.send_json(
                    {"type": "login_interactive_finish", "z": hex(z)}
                )
                resp2 = client.channel.recv_json()
                if resp2.get("ok"):
                    logger.info(
                        "Attack A3 SUCCEEDED on attempt %d (guessed e'=%d)", attempt, e_guess
                    )
                    return True, attempt
                logger.info("Attempt %d failed (guess e'=%d)", attempt, e_guess)
            finally:
                client.close()
        logger.info("Attack A3 did not succeed within %d attempts", max_attempts)
        return False, max_attempts
    finally:
        for h in list(logger.handlers):
            h.close()


class FrameReplayProxy:
    """TCP proxy on port 6000->5050 that forwards traffic and replays one encrypted frame."""

    def __init__(
        self,
        listen_host: str = SERVER_HOST,
        listen_port: int = PROXY_PORT,
        target_host: str = SERVER_HOST,
        target_port: int = SERVER_PORT,
        replay_after_packets: int = 4,
        log_file: Optional[Path] = LOGS_DIR / "mallory_replay.log",
    ) -> None:
        self.listen_host = listen_host
        self.listen_port = listen_port
        self.target_host = target_host
        self.target_port = target_port
        self.replay_after_packets = replay_after_packets
        self.logger = build_logger("mallory:replay", log_file)
        self.replay_triggered = False

        self._sock: Optional[socket.socket] = None
        self._stop_event = threading.Event()
        self._thread: Optional[threading.Thread] = None

    def start(self) -> None:
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind((self.listen_host, self.listen_port))
        self._sock.listen(4)
        self._sock.settimeout(0.2)
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop_event.set()
        if self._sock is not None:
            try:
                self._sock.close()
            except OSError:
                pass
        if self._thread is not None:
            self._thread.join(timeout=1.0)
        for h in list(self.logger.handlers):
            h.close()

    def _run(self) -> None:
        assert self._sock is not None
        while not self._stop_event.is_set():
            try:
                c_sock, _ = self._sock.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            self._handle(c_sock)

    def _handle(self, c_sock: socket.socket) -> None:
        s_sock: Optional[socket.socket] = None
        try:
            s_sock = socket.create_connection((self.target_host, self.target_port), timeout=5.0)
            c_to_s_count = 0

            # Handshake: 2 client->server packets, 1 server->client packet
            # Packet 1: C -> S
            send_raw_packet(s_sock, recv_raw_packet(c_sock))
            c_to_s_count += 1
            # Packet 2: S -> C
            send_raw_packet(c_sock, recv_raw_packet(s_sock))
            # Packet 3: C -> S
            send_raw_packet(s_sock, recv_raw_packet(c_sock))
            c_to_s_count += 1

            while not self._stop_event.is_set():
                pkt = recv_raw_packet(c_sock)
                c_to_s_count += 1
                send_raw_packet(s_sock, pkt)

                if c_to_s_count == self.replay_after_packets:
                    # Wait for server response to the legitimate frame, forward it,
                    # then replay the exact same encrypted frame to trigger nonce rejection.
                    resp = recv_raw_packet(s_sock)
                    send_raw_packet(c_sock, resp)
                    self.logger.info(
                        "Replaying captured encrypted frame #%d (nonce=%s) to server",
                        c_to_s_count,
                        pkt[:12].hex(),
                    )
                    self.replay_triggered = True
                    send_raw_packet(s_sock, pkt)
                    break

                resp = recv_raw_packet(s_sock)
                send_raw_packet(c_sock, resp)
        except (ChannelError, OSError):
            pass
        finally:
            for s in (c_sock, s_sock):
                if s is not None:
                    try:
                        s.close()
                    except OSError:
                        pass
