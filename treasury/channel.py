"""Exact Milestone 1 handshake, key schedule and directional AES-GCM channel."""
import socket

from cryptography.exceptions import InvalidSignature, InvalidTag
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from .certificates import CertificateError, check_certificate, decode_hex, sign, verify_signature
from .config import CHANNEL_WEAKNESSES, GROUP
from .encoding import canonical_json, sha256
from .framing import (ProtocolError, decode_json, recv_frame, recv_json,
                      send_frame, send_json)
from .identity import Identity, generate_private_key


def generate_p256_keypair():
    private = generate_private_key()
    return private, private.public_key()


def point_hex(key) -> str:
    return key.public_bytes(serialization.Encoding.X962,
                            serialization.PublicFormat.UncompressedPoint).hex()


def load_point(value: str):
    raw = decode_hex(value)
    if len(raw) != 65 or raw[0] != 4:
        raise ProtocolError("ephemeral point must be uncompressed P-256")
    try:
        return ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), raw)
    except ValueError as exc:
        raise ProtocolError("invalid P-256 ephemeral point") from exc


def build_handshake_transcript(member_name: str, X_hex: str, Y_hex: str) -> list:
    return ["hs", GROUP, member_name, X_hex, Y_hex]


def derive_directional_keys(shared_secret: bytes, member_name: str,
                             X_hex: str, Y_hex: str) -> tuple[bytes, bytes]:
    info = ("ICS505|" + GROUP + "|channel|").encode() + sha256(
        canonical_json(build_handshake_transcript(member_name, X_hex, Y_hex)))
    material = HKDF(algorithm=hashes.SHA256(), length=64, salt=None,
                    info=info).derive(shared_secret)
    return material[:32], material[32:]


class SecureChannel:
    """A failure permanently poisons this channel. Never reuse keys/counters."""
    def __init__(self, send_key: bytes, receive_key: bytes):
        if len(send_key) != 32 or len(receive_key) != 32:
            raise ValueError("AES-256 requires two 32-byte keys")
        self.send_key = send_key
        self.receive_key = receive_key
        self.send_counter = 0
        self.receive_counter = 0
        self.closed = False

    def close(self) -> None:
        self.closed = True
        self.send_key = self.receive_key = b""

    def encrypt(self, plaintext: bytes) -> bytes:
        if self.closed:
            raise ProtocolError("channel is closed")
        if self.send_counter >= 1 << 96:
            self.close()
            raise ProtocolError("nonce counter exhausted")
        nonce = self.send_counter.to_bytes(12, "big")
        frame = nonce + AESGCM(self.send_key).encrypt(nonce, plaintext, None)
        self.send_counter += 1
        return frame

    def decrypt(self, frame: bytes) -> bytes:
        if self.closed:
            raise ProtocolError("channel is closed")
        try:
            if len(frame) < 28:
                raise ProtocolError("encrypted frame too short")
            nonce = frame[:12]
            counter = int.from_bytes(nonce, "big")
            if counter != self.receive_counter:
                raise ProtocolError(f"nonce validation FAILED: expected {self.receive_counter}, got {counter}")
            plaintext = AESGCM(self.receive_key).decrypt(nonce, frame[12:], None)
            self.receive_counter += 1
            return plaintext
        except (InvalidTag, ProtocolError) as exc:
            self.close()
            if isinstance(exc, InvalidTag):
                raise ProtocolError("AES-GCM authentication tag FAILED") from exc
            raise


class Session:
    """Transport identity is distinct from Essam's future login state.

    One reader and one writer per session; not safe for concurrent writers.
    The handler owns the socket lifetime and should use this context manager.
    """
    def __init__(self, sock, channel, peer_name, peer_public_key, log, *, weak=None):
        self.sock = sock
        self.channel = channel
        self.peer_name = peer_name
        self.peer_public_key = peer_public_key
        self.log = log
        self.weak = weak
        self.authenticated = False  # Only successful login verification may change this.
        self.state: dict = {}  # Essam owns pending challenges/nonces; never log this dict.
        self.closed = False

    def send(self, message: dict) -> None:
        try:
            if self.closed or not isinstance(message, dict):
                raise ProtocolError("send requires an open session and JSON object")
            payload = canonical_json(message)
            if self.weak == "no-encryption":
                send_frame(self.sock, payload)
                self.log.warning("DEMO plaintext send type=%s", message.get("type", message.get("op")))
            else:
                counter = self.channel.send_counter
                send_frame(self.sock, self.channel.encrypt(payload))
                self.log.info("encrypted send peer=%s nonce=%d bytes=%d", self.peer_name, counter, len(payload))
        except (OSError, ValueError, ProtocolError) as exc:
            self.log.error("security rejection on send: %s", exc)
            self.close()
            raise

    def receive(self) -> dict | None:
        try:
            if self.closed:
                raise ProtocolError("session is closed")
            frame = recv_frame(self.sock)
            if frame is None:
                self.close()
                return None
            if self.weak == "no-encryption":
                payload = frame
                self.log.warning("DEMO plaintext receive bytes=%d", len(payload))
            else:
                counter = self.channel.receive_counter
                payload = self.channel.decrypt(frame)
                self.log.info("decrypted receive peer=%s nonce=%d validation OK tag OK", self.peer_name, counter)
            message = decode_json(payload)
            if not isinstance(message, dict):
                raise ProtocolError("application message must be a JSON object")
            return message
        except (OSError, ValueError, ProtocolError) as exc:
            self.log.error("security rejection on receive: %s", exc)
            self.close()
            raise

    def close(self) -> None:
        if not self.closed:
            self.closed = True
            self.channel.close()
            self.authenticated = False
            self.state.clear()
            try:
                self.sock.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            self.sock.close()
            self.log.info("connection closed peer=%s", self.peer_name)

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()


def _message(sock, fields: set[str]) -> dict:
    message = recv_json(sock)
    if not isinstance(message, dict) or set(message) != fields:
        raise ProtocolError("handshake missing or unexpected fields (including required signature)")
    return message


def _mode(sock, weak, log):
    if weak is not None and weak not in CHANNEL_WEAKNESSES:
        raise ProtocolError("unsupported channel weakness")
    if sock.getpeername()[0] != "127.0.0.1" or sock.getsockname()[0] != "127.0.0.1":
        raise ProtocolError("treasury connections are restricted to 127.0.0.1")
    if weak:
        log.warning("EDUCATIONAL WEAK MODE: %s", weak)


def _check_peer(cert, identity, expected, log):
    try:
        key = check_certificate(cert, identity.founder_public_key, expected)
    except CertificateError as exc:
        log.error("certificate verification FAILED expected=%s: %s", expected, exc)
        raise
    log.info("certificate verification OK peer=%s group=%s sig=%s", expected, GROUP, cert["sig"][:8])
    return key


def _verify(key, signature, role, name, X, Y, log):
    try:
        verify_signature(key, signature, [role, GROUP, name, X, Y])
    except (InvalidSignature, ValueError, TypeError) as exc:
        log.error("%s signature verification FAILED X=%s Y=%s", role, X[:8], Y[:8])
        raise ProtocolError(f"{role} signature verification FAILED") from exc
    log.info("%s signature verification OK X=%s Y=%s sig=%s", role, X[:8], Y[:8], signature[:8])


def member_handshake(sock, identity: Identity, log, *, weak=None) -> Session:
    try:
        _mode(sock, weak, log)
        ephemeral, public = generate_p256_keypair()
        X = point_hex(public)
        send_json(sock, {"cert": identity.certificate, "X": X})
        log.info("handshake sent member hello X=%s", X[:8])
        fields = {"cert", "Y"} if weak == "unsigned-handshake" else {"cert", "Y", "sig"}
        reply = _message(sock, fields)
        server_key = _check_peer(reply["cert"], identity, "server", log)
        Y = reply["Y"]
        peer = load_point(Y)
        if weak != "unsigned-handshake":
            _verify(server_key, reply["sig"], "hs-server", identity.name, X, Y, log)
            signature = sign(identity.private_key, ["hs-member", GROUP, identity.name, X, Y])
            send_json(sock, {"sig": signature})
        else:
            send_json(sock, {})
            log.warning("DEMO handshake signatures omitted")
        m2s, s2m = derive_directional_keys(ephemeral.exchange(ec.ECDH(), peer), identity.name, X, Y)
        log.info("channel ready peer=server; login still required")
        return Session(sock, SecureChannel(m2s, s2m), "server", server_key, log, weak=weak)
    except (OSError, ValueError, TypeError, ProtocolError) as exc:
        log.error("handshake security rejection: %s", exc)
        sock.close()
        raise
    # Ephemeral keys and shared-secret bytes are not stored on Session.


def server_handshake(sock, identity: Identity, allowed_members, log, *, weak=None) -> Session:
    try:
        _mode(sock, weak, log)
        hello = _message(sock, {"cert", "X"})
        cert = hello["cert"]
        name = cert.get("name") if isinstance(cert, dict) else None
        if not isinstance(name, str) or name not in allowed_members:
            raise ProtocolError("certificate identity is not a configured member")
        member_key = _check_peer(cert, identity, name, log)
        X = hello["X"]
        peer = load_point(X)
        ephemeral, public = generate_p256_keypair()
        Y = point_hex(public)
        reply = {"cert": identity.certificate, "Y": Y}
        if weak != "unsigned-handshake":
            reply["sig"] = sign(identity.private_key, ["hs-server", GROUP, name, X, Y])
        send_json(sock, reply)
        log.info("handshake sent server hello X=%s Y=%s", X[:8], Y[:8])
        finish = _message(sock, set() if weak == "unsigned-handshake" else {"sig"})
        if weak != "unsigned-handshake":
            _verify(member_key, finish["sig"], "hs-member", name, X, Y, log)
        else:
            log.warning("DEMO handshake signatures omitted")
        m2s, s2m = derive_directional_keys(ephemeral.exchange(ec.ECDH(), peer), name, X, Y)
        log.info("session established peer=%s; login still required", name)
        return Session(sock, SecureChannel(s2m, m2s), name, member_key, log, weak=weak)
    except (OSError, ValueError, TypeError, ProtocolError) as exc:
        log.error("handshake security rejection: %s", exc)
        sock.close()
        raise
