from datetime import date
import hashlib
import hmac
import logging
import socket
import struct
import tempfile
import unittest
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization

from treasury.certificates import (CertificateError, check_certificate, create_certificate,
                                   public_pem, sign, verify_certificate)
from treasury.channel import (SecureChannel, build_handshake_transcript,
                              derive_directional_keys, generate_p256_keypair, load_point, point_hex)
from treasury.config import GROUP, P, Q, G, member_names, valid_group_element
from treasury.encoding import canonical_json
from treasury.founder import issue_certificates
from treasury.framing import ProtocolError, recv_json
from treasury.identity import initialize_identity, load_identity


class CertificateTests(unittest.TestCase):
    def setUp(self):
        self.founder, self.pub = generate_p256_keypair()
        self.member, pub = generate_p256_keypair()
        self.cert = create_certificate(self.founder, "M1", public_pem(pub), "2099-12-31").to_dict()

    def test_exact_format(self):
        self.assertEqual(set(self.cert), {"group", "name", "public_key", "expires", "sig"})
        self.assertEqual(self.cert["group"], GROUP)

    def test_valid_certificate(self):
        self.assertTrue(verify_certificate(self.cert, self.pub, "M1"))

    def test_wrong_founder(self):
        _, wrong = generate_p256_keypair()
        self.assertFalse(verify_certificate(self.cert, wrong, "M1"))

    def test_modified_signature(self):
        self.cert["sig"] = "00" + self.cert["sig"][2:]
        self.assertFalse(verify_certificate(self.cert, self.pub, "M1"))

    def test_wrong_group_even_when_signed(self):
        self.cert["group"] = "other-group"
        self.cert["sig"] = sign(self.founder, {k: v for k, v in self.cert.items() if k != "sig"})
        self.assertFalse(verify_certificate(self.cert, self.pub, "M1"))

    def test_wrong_identity(self):
        self.assertFalse(verify_certificate(self.cert, self.pub, "M2"))

    def test_expired(self):
        with self.assertRaisesRegex(CertificateError, "expired"):
            check_certificate(self.cert, self.pub, "M1", today=date(2100, 1, 1))

    def test_expiry_day_is_valid(self):
        check_certificate(self.cert, self.pub, "M1", today=date(2099, 12, 31))

    def test_missing_and_extra_fields(self):
        for changed in ({k: v for k, v in self.cert.items() if k != "sig"}, dict(self.cert, extra="x")):
            self.assertFalse(verify_certificate(changed, self.pub, "M1"))

    def test_malformed_public_key(self):
        self.cert["public_key"] = "not PEM"
        self.assertFalse(verify_certificate(self.cert, self.pub, "M1"))

    def test_wrong_curve(self):
        other = ec.generate_private_key(ec.SECP384R1()).public_key()
        self.cert["public_key"] = other.public_bytes(serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo).decode()
        self.cert["sig"] = sign(self.founder, {k: v for k, v in self.cert.items() if k != "sig"})
        self.assertFalse(verify_certificate(self.cert, self.pub, "M1"))

    def test_invalid_types_and_dates(self):
        for key, value in [("sig", "XYZ"), ("expires", "not-a-date"), ("name", []), ("sig", None)]:
            with self.subTest(key=key, value=value):
                changed = dict(self.cert, **{key: value})
                self.assertFalse(verify_certificate(changed, self.pub, "M1"))


class ChannelTests(unittest.TestCase):
    def setUp(self):
        self.sender = SecureChannel(b"a" * 32, b"b" * 32)
        self.receiver = SecureChannel(b"b" * 32, b"a" * 32)

    def test_gcm_roundtrip_and_independent_counters(self):
        first = self.sender.encrypt(b"hello")
        self.assertEqual(first[:12], bytes(12))
        self.assertEqual(self.receiver.decrypt(first), b"hello")
        reverse = self.receiver.encrypt(b"response")
        self.assertEqual(reverse[:12], bytes(12))
        self.assertEqual(self.sender.decrypt(reverse), b"response")
        self.assertEqual(self.receiver.decrypt(self.sender.encrypt(b"next")), b"next")

    def test_ciphertext_tamper_closes_channel(self):
        frame = bytearray(self.sender.encrypt(b"hello"))
        frame[12] ^= 1
        with self.assertRaisesRegex(ProtocolError, "tag FAILED"):
            self.receiver.decrypt(bytes(frame))
        self.assertTrue(self.receiver.closed)
        self.assertEqual(self.receiver.receive_key, b"")

    def test_tag_tamper(self):
        frame = self.sender.encrypt(b"hello")
        with self.assertRaisesRegex(ProtocolError, "tag FAILED"):
            self.receiver.decrypt(frame[:-1] + bytes([frame[-1] ^ 1]))

    def test_replay(self):
        frame = self.sender.encrypt(b"hello")
        self.receiver.decrypt(frame)
        with self.assertRaisesRegex(ProtocolError, "expected 1, got 0"):
            self.receiver.decrypt(frame)
        with self.assertRaisesRegex(ProtocolError, "closed"):
            self.receiver.decrypt(self.sender.encrypt(b"next"))

    def test_skipped_counter(self):
        self.sender.send_counter = 1
        with self.assertRaisesRegex(ProtocolError, "expected 0, got 1"):
            self.receiver.decrypt(self.sender.encrypt(b"hello"))

    def test_invalid_counter(self):
        frame = self.sender.encrypt(b"hello")
        with self.assertRaisesRegex(ProtocolError, "nonce validation FAILED"):
            self.receiver.decrypt(b"\xff" * 12 + frame[12:])

    def test_short_frame(self):
        with self.assertRaises(ProtocolError):
            self.receiver.decrypt(b"short")

    def test_counter_exhaustion(self):
        self.sender.send_counter = (1 << 96) - 1
        self.sender.encrypt(b"last")
        with self.assertRaisesRegex(ProtocolError, "exhausted"):
            self.sender.encrypt(b"overflow")

    def test_reversed_direction_fails(self):
        with self.assertRaisesRegex(ProtocolError, "tag FAILED"):
            self.sender.decrypt(self.sender.encrypt(b"hello"))

    def test_aes256_key_lengths(self):
        with self.assertRaises(ValueError):
            SecureChannel(b"a" * 16, b"b" * 32)

    def test_hkdf_matches_independent_rfc5869_calculation(self):
        secret = bytes(range(32))
        X, Y = "04aa", "04bb"
        info = ("ICS505|" + GROUP + "|channel|").encode() + hashlib.sha256(
            canonical_json(["hs", GROUP, "M1", X, Y])).digest()
        prk = hmac.new(bytes(32), secret, hashlib.sha256).digest()
        first = hmac.new(prk, info + b"\x01", hashlib.sha256).digest()
        second = hmac.new(prk, first + info + b"\x02", hashlib.sha256).digest()
        self.assertEqual(derive_directional_keys(secret, "M1", X, Y), (first, second))
        self.assertNotEqual(first, second)

    def test_ecdh_and_fresh_keys(self):
        a, A = generate_p256_keypair()
        b, B = generate_p256_keypair()
        X, Y = point_hex(A), point_hex(B)
        first = derive_directional_keys(a.exchange(ec.ECDH(), B), "M1", X, Y)
        self.assertEqual(first, derive_directional_keys(b.exchange(ec.ECDH(), A), "M1", X, Y))
        c, C = generate_p256_keypair()
        second = derive_directional_keys(c.exchange(ec.ECDH(), B), "M1", point_hex(C), Y)
        self.assertNotEqual(first, second)
        self.assertEqual(build_handshake_transcript("M1", X, Y), ["hs", GROUP, "M1", X, Y])

    def test_kdf_binds_identity_and_transcript(self):
        key = derive_directional_keys(b"s" * 32, "M1", "04aa", "04bb")
        self.assertNotEqual(key, derive_directional_keys(b"s" * 32, "M2", "04aa", "04bb"))
        self.assertNotEqual(key, derive_directional_keys(b"s" * 32, "M1", "04ac", "04bb"))

    def test_frame_from_other_session_rejected(self):
        other = SecureChannel(b"c" * 32, b"d" * 32)
        with self.assertRaisesRegex(ProtocolError, "tag FAILED"):
            self.receiver.decrypt(other.encrypt(b"different session"))

    def test_reject_compressed_and_invalid_points(self):
        for value in ["02" + "00" * 32, "04" + "00" * 64, "XYZ", "04 AA"]:
            with self.subTest(value=value), self.assertRaises((ProtocolError, ValueError)):
                load_point(value)


class FramingRejectionTests(unittest.TestCase):
    def check_bad(self, wire):
        left, right = socket.socketpair()
        try:
            left.sendall(wire)
            left.shutdown(socket.SHUT_WR)
            with self.assertRaises(ProtocolError):
                recv_json(right)
        finally:
            left.close()
            right.close()

    def test_truncated_header(self):
        self.check_bad(b"\0\0")

    def test_truncated_payload(self):
        self.check_bad(struct.pack(">I", 10) + b"{}")

    def test_missing_payload(self):
        self.check_bad(struct.pack(">I", 10))

    def test_zero_length(self):
        self.check_bad(bytes(4))

    def test_oversize(self):
        self.check_bad(struct.pack(">I", 4 * 1024 * 1024 + 1))

    def test_bad_json_utf8_duplicates_and_nan(self):
        for payload in [b"\xff", b"{", b'{"x":1,"x":2}', b'{"x":NaN}']:
            with self.subTest(payload=payload):
                self.check_bad(struct.pack(">I", len(payload)) + payload)

    def test_clean_disconnect(self):
        left, right = socket.socketpair()
        left.close()
        try:
            self.assertIsNone(recv_json(right))
        finally:
            right.close()


class SetupTests(unittest.TestCase):
    def test_parameters(self):
        self.assertEqual(P.bit_length(), 2048)
        self.assertEqual(Q, (P - 1) // 2)
        self.assertEqual(G, 4)
        self.assertTrue(valid_group_element(G))
        for value in [0, 1, P, P - 1, True]:
            self.assertFalse(valid_group_element(value))
        self.assertEqual(member_names(2), ("M1", "M2"))

    def test_configurable_setup_and_independent_owners(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for name in ["server", *member_names(6)]:
                initialize_identity(name, root)
            issue_certificates(root, 6, 4, logging.getLogger("test"))
            identities = [load_identity(name, root) for name in ["server", *member_names(6)]]
            self.assertEqual(len({public_pem(i.private_key.public_key()) for i in identities}), 7)
            self.assertTrue(all(i.certificate["expires"] == "2026-12-31" for i in identities))
            self.assertEqual(len(list((root / "public").glob("*.key"))), 0)
            with self.assertRaisesRegex(ValueError, "already exists"):
                issue_certificates(root, 6, 4, logging.getLogger("test"))

    def test_owner_setup_is_idempotent(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            first = initialize_identity("M1", root)
            second = initialize_identity("M1", root)
            self.assertEqual(first.private_numbers(), second.private_numbers())

    def test_invalid_threshold(self):
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaises(ValueError):
                issue_certificates(Path(directory), 2, 3, logging.getLogger("test"))

    def test_path_traversal_name(self):
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaises(ValueError):
                initialize_identity("../server", Path(directory))
