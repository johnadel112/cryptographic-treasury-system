"""Authentication, signed-request, attack, and M2/M3 integration tests."""

import socket
import time
from pathlib import Path

import pytest

from src.auth_client import TreasuryMemberClient
from src.auth_server import TreasuryAuthServer
from src.channel import ChannelError, client_handshake
from src.config import G, GROUP, P, Q
from src.crypto_utils import create_certificate, generate_p256_keypair
from src.keys import load_owner_keys, setup_pki
from src.proxy_mallory import FrameReplayProxy, MalloryMitmProxy, run_attack_a3


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@pytest.fixture()
def env(tmp_path: Path):
    setup_pki(tmp_path, members=("M1", "M2", "M3", "M4", "M5"), group=GROUP)
    port = _free_port()
    srv = TreasuryAuthServer(
        port=port, data_dir=tmp_path, group=GROUP, log_file=tmp_path / "server.log"
    )
    srv.start()
    yield tmp_path, port, srv
    srv.stop()


def test_group_parameters():
    assert P == 2 * Q + 1
    assert pow(G, Q, P) == 1


def test_registration_and_no_replacement(env):
    data_dir, port, _ = env
    c1 = TreasuryMemberClient("M1", port=port, data_dir=data_dir)
    c1.connect()
    try:
        assert c1.register()["ok"] is True
        # Re-registering or replacing X_M must be rejected
        assert c1.register()["ok"] is False
        c1.channel.send_json({"type": "register", "X_M": hex(pow(G, 12345, P))})
        resp = c1.channel.recv_json()
        assert resp["ok"] is False
        assert "replacement" in resp["reason"].lower()
    finally:
        c1.close()

    m1_keys = load_owner_keys("M1", data_dir)
    assert int(m1_keys["ecdsa_priv"], 16) != m1_keys["login_secret_x_int"]


def test_interactive_and_noninteractive_login_and_single_use_nonce(env):
    data_dir, port, _ = env
    c1 = TreasuryMemberClient("M1", port=port, data_dir=data_dir)
    c1.connect()
    try:
        assert c1.register()["ok"] is True
        assert c1.login_interactive()["ok"] is True
    finally:
        c1.close()

    # Non-interactive login on a fresh session
    c1b = TreasuryMemberClient("M1", port=port, data_dir=data_dir)
    c1b.connect()
    try:
        assert c1b.login_noninteractive()["ok"] is True
        # Replaying a consumed nonce N must fail
        c1b.channel.send_json({"type": "login_noninteractive_nonce"})
        n_resp = c1b.channel.recv_json()
        nonce = n_resp["N"]
        # Consume it once validly
        from src.crypto_utils import hash_to_zq, random_zq_scalar

        k = random_zq_scalar()
        r_hex = hex(pow(G, k, P))
        e = hash_to_zq("login", "M1", c1b.big_x_m_hex, r_hex, nonce)
        z_hex = hex((k + e * c1b.x_m) % Q)
        c1b.channel.send_json(
            {"type": "login_noninteractive", "N": nonce, "R": r_hex, "z": z_hex}
        )
        assert c1b.channel.recv_json()["ok"] is True

        # Replay the exact same (N, R, z)
        c1b.channel.send_json(
            {"type": "login_noninteractive", "N": nonce, "R": r_hex, "z": z_hex}
        )
        replay_resp = c1b.channel.recv_json()
        assert replay_resp["ok"] is False
        assert "already used" in replay_resp["error"].lower()
    finally:
        c1b.close()


def test_signed_requests_seq_replay_modification_and_ledger(env):
    data_dir, port, srv = env
    c2 = TreasuryMemberClient("M2", port=port, data_dir=data_dir)
    c2.connect()
    try:
        assert c2.register()["ok"] is True
        # Request before login must be rejected
        assert c2.send_request("spend", {"amount": 10}, seq=1)["ok"] is False

        assert c2.login_interactive()["ok"] is True
        r1 = c2.send_request("spend", {"amount": 50, "reason": "pizza"}, seq=1)
        assert r1["ok"] is True

        # Replay same seq=1 must fail
        r_replay = c2.send_request("spend", {"amount": 50, "reason": "pizza"}, seq=1)
        assert r_replay["ok"] is False

        # Modified body with old signature must fail
        from src.crypto_utils import sign_data

        bad_sig = sign_data(
            c2.ecdsa_priv, ["request", GROUP, "M2", 2, "spend", {"amount": 50}]
        )
        c2.channel.send_json(
            {
                "type": "request",
                "op": "spend",
                "seq": 2,
                "body": {"amount": 5000},
                "sig": bad_sig,
            }
        )
        assert c2.channel.recv_json()["ok"] is False

        entries = srv.ledger.entries()
        assert len(entries) == 1
        assert entries[0]["member"] == "M2"
        assert entries[0]["seq"] == 1
    finally:
        c2.close()


def test_certificate_refusals(env):
    data_dir, port, _ = env
    m1_keys = load_owner_keys("M1", data_dir)

    # 1. Cert signed by rogue founder
    rogue_priv, _ = generate_p256_keypair()
    rogue_cert = create_certificate(
        rogue_priv, "M1", GROUP, m1_keys["ecdsa_pub_obj"]
    )
    sock = socket.create_connection(("127.0.0.1", port), timeout=5.0)
    with pytest.raises(ChannelError):
        client_handshake(
            sock, "M1", m1_keys["ecdsa_priv_obj"], rogue_cert, m1_keys["founder_pub_obj"], GROUP
        )

    # 2. Cert from wrong group
    founder_keys = load_owner_keys("founder", data_dir)
    wrong_group_cert = create_certificate(
        founder_keys["ecdsa_priv_obj"], "M1", "OTHER_GROUP", m1_keys["ecdsa_pub_obj"]
    )
    sock2 = socket.create_connection(("127.0.0.1", port), timeout=5.0)
    with pytest.raises(ChannelError):
        client_handshake(
            sock2,
            "M1",
            m1_keys["ecdsa_priv_obj"],
            wrong_group_cert,
            m1_keys["founder_pub_obj"],
            GROUP,
        )


def test_replayed_encrypted_frame_closes_connection(tmp_path: Path):
    setup_pki(tmp_path, members=("M1",), group=GROUP)
    srv_port = _free_port()
    proxy_port = _free_port()
    srv = TreasuryAuthServer(port=srv_port, data_dir=tmp_path, log_file=tmp_path / "srv.log")
    srv.start()
    proxy = FrameReplayProxy(
        listen_port=proxy_port,
        target_port=srv_port,
        replay_after_packets=6,
        log_file=tmp_path / "replay.log",
    )
    proxy.start()
    try:
        c1 = TreasuryMemberClient("M1", port=proxy_port, data_dir=tmp_path)
        c1.connect()
        assert c1.register()["ok"] is True
        assert c1.login_interactive()["ok"] is True
        # This triggers replay_after_packets=5 on the proxy
        assert c1.send_request("ping", {"n": 1})["ok"] is True
        time.sleep(0.15)
        assert proxy.replay_triggered is True
        assert "Nonce counter mismatch" in (tmp_path / "srv.log").read_text(encoding="utf-8")
        c1.close()
    finally:
        proxy.stop()
        srv.stop()


def test_attack_a1_mitm_and_mitigation(tmp_path: Path):
    setup_pki(tmp_path, members=("M1",), group=GROUP)
    srv_port = _free_port()
    proxy_port = _free_port()

    # Vulnerable: unsigned handshake
    srv = TreasuryAuthServer(
        port=srv_port,
        data_dir=tmp_path,
        weak_unsigned_handshake=True,
        log_file=tmp_path / "srv_a1.log",
    )
    srv.start()
    proxy = MalloryMitmProxy(
        listen_port=proxy_port,
        target_port=srv_port,
        tamper_first_request=True,
        log_file=tmp_path / "mal_a1.log",
    )
    proxy.start()
    try:
        c1 = TreasuryMemberClient(
            "M1", port=proxy_port, data_dir=tmp_path, weak_unsigned_handshake=True
        )
        c1.connect()
        assert c1.register()["ok"] is True
        assert c1.login_interactive()["ok"] is True
        # Mallory tampers with amount -> server must reject ECDSA signature
        resp = c1.send_request("spend", {"amount": 50, "reason": "pizza"})
        assert resp["ok"] is False
        assert len(proxy.captured_cleartext) >= 3
        c1.close()
    finally:
        proxy.stop()
        srv.stop()

    # Secure: real handshake stops Mallory
    srv2 = TreasuryAuthServer(
        port=srv_port,
        data_dir=tmp_path,
        weak_unsigned_handshake=False,
        log_file=tmp_path / "srv_a1_sec.log",
    )
    srv2.start()
    proxy2 = MalloryMitmProxy(
        listen_port=proxy_port, target_port=srv_port, log_file=tmp_path / "mal_a1_sec.log"
    )
    proxy2.start()
    try:
        c1_sec = TreasuryMemberClient(
            "M1", port=proxy_port, data_dir=tmp_path, weak_unsigned_handshake=False
        )
        with pytest.raises(ChannelError):
            c1_sec.connect()
    finally:
        proxy2.stop()
        srv2.stop()


def test_attack_a3_short_challenge_and_mitigation(tmp_path: Path):
    setup_pki(tmp_path, members=("M3",), group=GROUP)
    srv_port = _free_port()

    # Vulnerable 4-bit challenge: register M3 first, then Mallory forges login
    srv = TreasuryAuthServer(
        port=srv_port,
        data_dir=tmp_path,
        weak_short_challenge=True,
        log_file=tmp_path / "srv_a3.log",
    )
    srv.start()
    try:
        c3 = TreasuryMemberClient("M3", port=srv_port, data_dir=tmp_path)
        c3.connect()
        assert c3.register()["ok"] is True
        c3.close()

        ok, attempts = run_attack_a3(
            "M3", port=srv_port, data_dir=tmp_path, max_attempts=128, log_file=tmp_path / "mal_a3.log"
        )
        assert ok is True
        assert 1 <= attempts <= 128
    finally:
        srv.stop()


def test_m2_m3_authenticated_session_integration(env):
    data_dir, port, srv = env
    c1 = TreasuryMemberClient("M1", port=port, data_dir=data_dir)
    c1.connect()
    try:
        assert c1.register()["ok"] is True
        assert c1.login_noninteractive()["ok"] is True

        # Milestone 2: vault opening & decryption contribution
        assert c1.submit_vault_open_request("vault-1", "monthly audit")["ok"] is True
        assert (
            c1.submit_decryption_contribution(
                "vault-1", 1, hex(111), hex(222), hex(333), hex(444)
            )["ok"]
            is True
        )

        # Milestone 3: spending request & signed ballot
        assert c1.submit_spending_request(200, "equipment")["ok"] is True
        assert c1.submit_ballot(1, hex(12345), hex(67890))["ok"] is True
        # Duplicate ballot rejected
        assert c1.submit_ballot(1, hex(12345), hex(67890))["ok"] is False
        # Unsigned ballot rejected
        assert c1.submit_ballot(2, hex(12345), hex(67890), unsigned=True)["ok"] is False
    finally:
        c1.close()

    ops = [e["op"] for e in srv.ledger.entries()]
    assert ops == ["open_vault", "decrypt_share", "spend_request"]
    assert "M1" in srv.ballots[1]
