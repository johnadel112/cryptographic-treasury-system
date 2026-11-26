"""Milestone 1 secure channel. The baseline TCP layer is in framing.py/network.py."""

def generate_p256_keypair():
    """TODO: generate an ECDSA/ECDH-capable P-256 private/public key pair."""
    raise NotImplementedError


def build_handshake_transcript(member_name: str, X_hex: str, Y_hex: str) -> list:
    """Return the exact transcript list specified in the project handout."""
    from .config import GROUP
    return ["hs", GROUP, member_name, X_hex, Y_hex]


def derive_directional_keys(shared_secret: bytes, member_name: str,
                             X_hex: str, Y_hex: str) -> tuple[bytes, bytes]:
    """TODO: HKDF-SHA256 to derive 32-byte member->server and server->member keys."""
    raise NotImplementedError


class SecureChannel:
    """TODO: implement AES-256-GCM frames and strict per-direction counters.

    Required frame: 12-byte nonce || ciphertext+tag. Nonce counter is a
    96-bit big-endian integer starting at zero. Reject skipped/replayed frames.
    """
    def __init__(self, send_key: bytes, receive_key: bytes):
        self.send_key = send_key
        self.receive_key = receive_key
        self.send_counter = 0
        self.receive_counter = 0

    def encrypt(self, plaintext: bytes) -> bytes:
        raise NotImplementedError

    def decrypt(self, frame: bytes) -> bytes:
        raise NotImplementedError
