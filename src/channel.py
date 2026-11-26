"""Authenticated ECDH handshake and AES-256-GCM framed channel."""

import json
import socket
import struct
from typing import Any, Dict, Tuple

from cryptography.hazmat.primitives.asymmetric import ec

from .crypto_utils import (
    decrypt_frame,
    derive_channel_keys,
    encrypt_frame,
    generate_p256_keypair,
    hex_to_pub,
    pub_to_hex,
    sign_data,
    verify_certificate,
    verify_sig,
)


class ChannelError(Exception):
    """Raised on handshake, framing, counter, or decryption failure."""


def send_raw_packet(sock: socket.socket, payload: bytes) -> None:
    """Send a 4-byte length-prefixed packet over TCP."""
    sock.sendall(struct.pack(">I", len(payload)) + payload)


def recv_raw_packet(sock: socket.socket) -> bytes:
    """Receive a 4-byte length-prefixed packet from TCP."""
    hdr = _recv_exact(sock, 4)
    (length,) = struct.unpack(">I", hdr)
    if length > 10 * 1024 * 1024:
        raise ChannelError(f"Packet too large: {length}")
    return _recv_exact(sock, length)


def _recv_exact(sock: socket.socket, n: int) -> bytes:
    buf = bytearray()
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ChannelError("Connection closed by peer")
        buf.extend(chunk)
    return bytes(buf)


class SecureChannel:
    """Bidirectional AES-256-GCM channel with monotonic counter nonces."""

    def __init__(
        self,
        sock: socket.socket,
        send_key: bytes,
        recv_key: bytes,
        plain_mode: bool = False,
    ) -> None:
        self.sock = sock
        self.send_key = send_key
        self.recv_key = recv_key
        self.plain_mode = plain_mode
        self.send_counter = 0
        self.recv_counter = 0

    def send_json(self, obj: Dict[str, Any]) -> bytes:
        """Encode obj as JSON, encrypt (unless plain_mode), send, and return wire frame."""
        raw = json.dumps(obj, separators=(",", ":"), sort_keys=True).encode("utf-8")
        if self.plain_mode:
            frame = raw
        else:
            frame = encrypt_frame(self.send_key, self.send_counter, raw)
            self.send_counter += 1
        send_raw_packet(self.sock, frame)
        return frame

    def send_raw_frame(self, frame: bytes) -> None:
        """Send an exact raw frame (used for frame replay testing)."""
        send_raw_packet(self.sock, frame)

    def recv_json(self) -> Dict[str, Any]:
        """Receive frame, verify counter & decrypt (unless plain_mode), parse JSON."""
        frame = recv_raw_packet(self.sock)
        if self.plain_mode:
            plaintext = frame
        else:
            try:
                plaintext = decrypt_frame(self.recv_key, self.recv_counter, frame)
            except ValueError as exc:
                self.close()
                raise ChannelError(str(exc)) from exc
            self.recv_counter += 1
        return json.loads(plaintext.decode("utf-8"))

    def close(self) -> None:
        """Close underlying TCP socket."""
        try:
            self.sock.close()
        except OSError:
            pass


def client_handshake(
    sock: socket.socket,
    member_name: str,
    member_priv: ec.EllipticCurvePrivateKey,
    member_cert: Dict[str, str],
    founder_pub: ec.EllipticCurvePublicKey,
    group: str,
    weak_unsigned: bool = False,
    weak_no_encryption: bool = False,
) -> SecureChannel:
    """Perform Milestone 1 client-side authenticated ECDH handshake."""
    x_priv, x_pub = generate_p256_keypair()
    x_hex = pub_to_hex(x_pub)
    try:
        # 1. Member -> Server: {"cert": member_cert, "X": X}
        send_raw_packet(
            sock,
            json.dumps({"cert": member_cert, "X": x_hex}).encode("utf-8"),
        )

        # 2. Server -> Member: {"cert": server_cert, "Y": Y, "sig": ...}
        msg2 = json.loads(recv_raw_packet(sock).decode("utf-8"))
        server_cert = msg2.get("cert", {})
        y_hex = msg2.get("Y", "")
        if not verify_certificate(server_cert, founder_pub, group, expected_name="server"):
            raise ChannelError("Server certificate invalid")
        if not weak_unsigned:
            sig = msg2.get("sig", "")
            server_pub = hex_to_pub(server_cert["pubkey"])
            if not verify_sig(
                server_pub, ["hs-server", group, member_name, x_hex, y_hex], sig
            ):
                raise ChannelError("Server handshake signature missing or invalid")

        # 3. Member -> Server: {"sig": ...}
        if weak_unsigned:
            msg3 = {"sig": ""}
        else:
            msg3 = {
                "sig": sign_data(
                    member_priv, ["hs-member", group, member_name, x_hex, y_hex]
                )
            }
        send_raw_packet(sock, json.dumps(msg3).encode("utf-8"))

        y_pub = hex_to_pub(y_hex)
        shared_secret = x_priv.exchange(ec.ECDH(), y_pub)
        k_m2s, k_s2m = derive_channel_keys(shared_secret, group, member_name, x_hex, y_hex)
        return SecureChannel(
            sock, send_key=k_m2s, recv_key=k_s2m, plain_mode=weak_no_encryption
        )
    except Exception:
        sock.close()
        raise
    finally:
        # Erase ephemeral secret x
        del x_priv


def server_handshake(
    sock: socket.socket,
    server_priv: ec.EllipticCurvePrivateKey,
    server_cert: Dict[str, str],
    founder_pub: ec.EllipticCurvePublicKey,
    group: str,
    weak_unsigned: bool = False,
    weak_no_encryption: bool = False,
) -> Tuple[SecureChannel, str, Dict[str, str]]:
    """Perform Milestone 1 server-side authenticated ECDH handshake."""
    y_priv, y_pub = generate_p256_keypair()
    y_hex = pub_to_hex(y_pub)
    try:
        # 1. Receive Member -> Server
        msg1 = json.loads(recv_raw_packet(sock).decode("utf-8"))
        member_cert = msg1.get("cert", {})
        x_hex = msg1.get("X", "")
        if not verify_certificate(member_cert, founder_pub, group):
            raise ChannelError("Member certificate invalid")
        member_name = member_cert["name"]
        if member_name == "server":
            raise ChannelError("Member cannot use server name")

        # 2. Send Server -> Member
        if weak_unsigned:
            sig_s = ""
        else:
            sig_s = sign_data(
                server_priv, ["hs-server", group, member_name, x_hex, y_hex]
            )
        send_raw_packet(
            sock,
            json.dumps({"cert": server_cert, "Y": y_hex, "sig": sig_s}).encode("utf-8"),
        )

        # 3. Receive Member -> Server
        msg3 = json.loads(recv_raw_packet(sock).decode("utf-8"))
        if not weak_unsigned:
            sig_m = msg3.get("sig", "")
            member_pub = hex_to_pub(member_cert["pubkey"])
            if not verify_sig(
                member_pub, ["hs-member", group, member_name, x_hex, y_hex], sig_m
            ):
                raise ChannelError("Member handshake signature missing or invalid")

        x_pub = hex_to_pub(x_hex)
        shared_secret = y_priv.exchange(ec.ECDH(), x_pub)
        k_m2s, k_s2m = derive_channel_keys(shared_secret, group, member_name, x_hex, y_hex)
        channel = SecureChannel(
            sock, send_key=k_s2m, recv_key=k_m2s, plain_mode=weak_no_encryption
        )
        return channel, member_name, member_cert
    except Exception:
        sock.close()
        raise
    finally:
        # Erase ephemeral secret y
        del y_priv
