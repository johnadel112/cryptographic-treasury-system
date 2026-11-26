"""Authentication, signed-request, attack, and M2/M3 integration tests."""

import shutil
import socket
import tempfile
import time
import unittest
from pathlib import Path

from src.auth_client import TreasuryMemberClient
from src.auth_server import TreasuryAuthServer
from src.channel import ChannelError, client_handshake
from src.config import G, GROUP, P, Q
from src.crypto_utils import (
    create_certificate,
    generate_p256_keypair,
    hash_to_zq,
    random_zq_scalar,
    sign_data,
)
from src.keys import load_owner_keys, setup_pki
from src.proxy_mallory import FrameReplayProxy, MalloryMitmProxy, run_attack_a3


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class AuthenticationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp_path = Path(tempfile.mkdtemp(prefix="treasury_auth_test_"))
        setup_pki(self.tmp_path, members=("M1", "M2", "M3", "M4", "M5"), group=GROUP)
        self.port = _free_port()
        self.srv = TreasuryAuthServer(
            port=self.port,
            data_dir=self.tmp_path,
            group=GROUP,
            log_file=self.tmp_path / "server.log",
        )
        self.srv.start()

    def tearDown(self) -> None:
        self.srv.stop()
        shutil.rmtree(self.tmp_path, ignore_errors=True)

    def test_group_parameters(self) -> None:
        self.assertEqual(P, 2 * Q + 1)
        self.assertEqual(pow(G, Q, P), 1)

    def test_registration_and_no_replacement(self) -> None:
        c1 = TreasuryMemberClient("M1", port=self.port, data_dir=self.tmp_path)
        c1.connect()
        try:
            self.assertTrue(c1.register()["ok"])
            self.assertFalse(c1.register()["ok"])
            assert c1.channel is not None
            c1.channel.send_json({"type": "register", "X_M": hex(pow(G, 12345, P))})
            resp = c1.channel.recv_json()
            self.assertFalse(resp["ok"])
            self.assertIn("replacement", resp["reason"].lower())
        finally:
            c1.close()

        m1_keys = load_owner_keys("M1", self.tmp_path)
        self.assertNotEqual(int(m1_keys["ecdsa_priv"], 16), m1_keys["login_secret_x_int"])

    def test_interactive_and_noninteractive_login_and_single_use_nonce(self) -> None:
        c1 = TreasuryMemberClient("M1", port=self.port, data_dir=self.tmp_path)
        c1.connect()
        try:
            self.assertTrue(c1.register()["ok"])
            self.assertTrue(c1.login_interactive()["ok"])
        finally:
            c1.close()

        c1b = TreasuryMemberClient("M1", port=self.port, data_dir=self.tmp_path)
        c1b.connect()
        try:
            self.assertTrue(c1b.login_noninteractive()["ok"])
            assert c1b.channel is not None
            c1b.channel.send_json({"type": "login_noninteractive_nonce"})
            n_resp = c1b.channel.recv_json()
            nonce = n_resp["N"]

            k = random_zq_scalar()
            r_hex = hex(pow(G, k, P))
            e = hash_to_zq("login", "M1", c1b.big_x_m_hex, r_hex, nonce)
            z_hex = hex((k + e * c1b.x_m) % Q)
            c1b.channel.send_json(
                {"type": "login_noninteractive", "N": nonce, "R": r_hex, "z": z_hex}
            )
            self.assertTrue(c1b.channel.recv_json()["ok"])

            c1b.channel.send_json(
                {"type": "login_noninteractive", "N": nonce, "R": r_hex, "z": z_hex}
            )
            replay_resp = c1b.channel.recv_json()
            self.assertFalse(replay_resp["ok"])
            self.assertIn("already used", replay_resp["error"].lower())
        finally:
            c1b.close()

    def test_signed_requests_seq_replay_modification_and_ledger(self) -> None:
        c2 = TreasuryMemberClient("M2", port=self.port, data_dir=self.tmp_path)
        c2.connect()
        try:
            self.assertTrue(c2.register()["ok"])
            self.assertFalse(c2.send_request("spend", {"amount": 10}, seq=1)["ok"])

            self.assertTrue(c2.login_interactive()["ok"])
            r1 = c2.send_request("spend", {"amount": 50, "reason": "pizza"}, seq=1)
            self.assertTrue(r1["ok"])

            r_replay = c2.send_request("spend", {"amount": 50, "reason": "pizza"}, seq=1)
            self.assertFalse(r_replay["ok"])

            bad_sig = sign_data(
                c2.ecdsa_priv, ["request", GROUP, "M2", 2, "spend", {"amount": 50}]
            )
            assert c2.channel is not None
            c2.channel.send_json(
                {
                    "type": "request",
                    "op": "spend",
                    "seq": 2,
                    "body": {"amount": 5000},
                    "sig": bad_sig,
                }
            )
            self.assertFalse(c2.channel.recv_json()["ok"])

            entries = self.srv.ledger.entries()
            self.assertEqual(len(entries), 1)
            self.assertEqual(entries[0]["member"], "M2")
            self.assertEqual(entries[0]["seq"], 1)
        finally:
            c2.close()

    def test_certificate_refusals(self) -> None:
        m1_keys = load_owner_keys("M1", self.tmp_path)

        rogue_priv, _ = generate_p256_keypair()
        rogue_cert = create_certificate(
            rogue_priv, "M1", GROUP, m1_keys["ecdsa_pub_obj"]
        )
        sock = socket.create_connection(("127.0.0.1", self.port), timeout=5.0)
        with self.assertRaises(ChannelError):
            client_handshake(
                sock,
                "M1",
                m1_keys["ecdsa_priv_obj"],
                rogue_cert,
                m1_keys["founder_pub_obj"],
                GROUP,
            )

        founder_keys = load_owner_keys("founder", self.tmp_path)
        wrong_group_cert = create_certificate(
            founder_keys["ecdsa_priv_obj"],
            "M1",
            "OTHER_GROUP",
            m1_keys["ecdsa_pub_obj"],
        )
        sock2 = socket.create_connection(("127.0.0.1", self.port), timeout=5.0)
        with self.assertRaises(ChannelError):
            client_handshake(
                sock2,
                "M1",
                m1_keys["ecdsa_priv_obj"],
                wrong_group_cert,
                m1_keys["founder_pub_obj"],
                GROUP,
            )

    def test_replayed_encrypted_frame_closes_connection(self) -> None:
        proxy_port = _free_port()
        proxy = FrameReplayProxy(
            listen_port=proxy_port,
            target_port=self.port,
            replay_after_packets=6,
            log_file=self.tmp_path / "replay.log",
        )
        proxy.start()
        try:
            c1 = TreasuryMemberClient("M1", port=proxy_port, data_dir=self.tmp_path)
            c1.connect()
            self.assertTrue(c1.register()["ok"])
            self.assertTrue(c1.login_interactive()["ok"])
            self.assertTrue(c1.send_request("ping", {"n": 1})["ok"])
            time.sleep(0.15)
            self.assertTrue(proxy.replay_triggered)
            self.assertIn(
                "Nonce counter mismatch",
                (self.tmp_path / "server.log").read_text(encoding="utf-8"),
            )
            c1.close()
        finally:
            proxy.stop()

    def test_attack_a1_mitm_and_mitigation(self) -> None:
        srv_port = _free_port()
        proxy_port = _free_port()

        srv = TreasuryAuthServer(
            port=srv_port,
            data_dir=self.tmp_path,
            weak_unsigned_handshake=True,
            log_file=self.tmp_path / "srv_a1.log",
        )
        srv.start()
        proxy = MalloryMitmProxy(
            listen_port=proxy_port,
            target_port=srv_port,
            tamper_first_request=True,
            log_file=self.tmp_path / "mal_a1.log",
        )
        proxy.start()
        try:
            c1 = TreasuryMemberClient(
                "M1",
                port=proxy_port,
                data_dir=self.tmp_path,
                weak_unsigned_handshake=True,
            )
            c1.connect()
            self.assertTrue(c1.register()["ok"])
            self.assertTrue(c1.login_interactive()["ok"])
            resp = c1.send_request("spend", {"amount": 50, "reason": "pizza"})
            self.assertFalse(resp["ok"])
            self.assertGreaterEqual(len(proxy.captured_cleartext), 3)
            c1.close()
        finally:
            proxy.stop()
            srv.stop()

        srv2 = TreasuryAuthServer(
            port=srv_port,
            data_dir=self.tmp_path,
            weak_unsigned_handshake=False,
            log_file=self.tmp_path / "srv_a1_sec.log",
        )
        srv2.start()
        proxy2 = MalloryMitmProxy(
            listen_port=proxy_port,
            target_port=srv_port,
            log_file=self.tmp_path / "mal_a1_sec.log",
        )
        proxy2.start()
        try:
            c1_sec = TreasuryMemberClient(
                "M1",
                port=proxy_port,
                data_dir=self.tmp_path,
                weak_unsigned_handshake=False,
            )
            with self.assertRaises(ChannelError):
                c1_sec.connect()
        finally:
            proxy2.stop()
            srv2.stop()

    def test_attack_a3_short_challenge_and_mitigation(self) -> None:
        srv_port = _free_port()
        srv = TreasuryAuthServer(
            port=srv_port,
            data_dir=self.tmp_path,
            weak_short_challenge=True,
            log_file=self.tmp_path / "srv_a3.log",
        )
        srv.start()
        try:
            c3 = TreasuryMemberClient("M3", port=srv_port, data_dir=self.tmp_path)
            c3.connect()
            self.assertTrue(c3.register()["ok"])
            c3.close()

            ok, attempts = run_attack_a3(
                "M3",
                port=srv_port,
                data_dir=self.tmp_path,
                max_attempts=128,
                log_file=self.tmp_path / "mal_a3.log",
            )
            self.assertTrue(ok)
            self.assertGreaterEqual(attempts, 1)
            self.assertLessEqual(attempts, 128)
        finally:
            srv.stop()

    def test_m2_m3_authenticated_session_integration(self) -> None:
        c1 = TreasuryMemberClient("M1", port=self.port, data_dir=self.tmp_path)
        c1.connect()
        try:
            self.assertTrue(c1.register()["ok"])
            self.assertTrue(c1.login_noninteractive()["ok"])

            self.assertTrue(c1.submit_vault_open_request("vault-1", "monthly audit")["ok"])
            self.assertTrue(
                c1.submit_decryption_contribution(
                    "vault-1", 1, hex(111), hex(222), hex(333), hex(444)
                )["ok"]
            )

            self.assertTrue(c1.submit_spending_request(200, "equipment")["ok"])
            self.assertTrue(c1.submit_ballot(1, hex(12345), hex(67890))["ok"])
            self.assertFalse(c1.submit_ballot(1, hex(12345), hex(67890))["ok"])
            self.assertFalse(
                c1.submit_ballot(2, hex(12345), hex(67890), unsigned=True)["ok"]
            )
        finally:
            c1.close()

        ops = [e["op"] for e in self.srv.ledger.entries()]
        self.assertEqual(ops, ["open_vault", "decrypt_share", "spend_request"])
        self.assertIn("M1", self.srv.ballots[1])


if __name__ == "__main__":
    unittest.main()
