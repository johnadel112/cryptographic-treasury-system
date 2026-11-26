"""Real founder/server/member subprocesses and loopback sockets, no mocked crypto."""
import os
import logging
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import time
import unittest

from treasury.channel import (generate_p256_keypair, member_handshake, point_hex)
from treasury.framing import recv_json, send_json, send_frame
from treasury.identity import load_identity

PROJECT = Path(__file__).resolve().parents[1]


class ProcessTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.workspace = tempfile.TemporaryDirectory()
        cls.root = Path(cls.workspace.name)
        cls.data = cls.root / "data"
        env = dict(os.environ, TREASURY_LOG_DIR=str(cls.root / "setup-logs"))
        commands = [("server", "--init-identity"),
                    ("member", "--name", "M1", "--init-identity"),
                    ("member", "--name", "M2", "--init-identity"),
                    ("founder", "--n", "2", "--t", "2")]
        for module, *args in commands:
            result = subprocess.run([sys.executable, "-m", "treasury." + module, *args,
                                     "--data-dir", str(cls.data)], cwd=PROJECT,
                                    env=env, capture_output=True, text=True, timeout=20)
            if result.returncode:
                raise AssertionError(result.stdout + result.stderr)
        cls.identity = load_identity("M1", cls.data)

    @classmethod
    def tearDownClass(cls):
        cls.workspace.cleanup()

    def setUp(self):
        self.logs = self.root / self._testMethodName
        self.env = dict(os.environ, TREASURY_LOG_DIR=str(self.logs))
        self.processes = []
        self.streams = []

    def tearDown(self):
        for process in self.processes:
            if process.poll() is None:
                process.terminate()
            process.wait(timeout=5)
        for stream in self.streams:
            stream.close()

    def launch(self, module, *args):
        self.logs.mkdir(exist_ok=True)
        stream = (self.logs / (module + ".output")).open("w", encoding="utf-8")
        self.streams.append(stream)
        process = subprocess.Popen([sys.executable, "-m", "treasury." + module, *args],
                                   cwd=PROJECT, env=self.env, stdout=stream, stderr=stream)
        self.processes.append(process)
        return process

    def wait_log(self, name, text):
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            path = self.logs / (name + ".log")
            if path.exists() and text in path.read_text("utf-8"):
                return path.read_text("utf-8")
            time.sleep(0.025)
        self.fail(f"Missing log {name}: {text}; files=" + str({p.name: p.read_text('utf-8') for p in self.logs.glob('*')}))

    def server(self, weak=None):
        args = ["--once", "--data-dir", str(self.data)]
        if weak:
            args += ["--weak", weak]
        process = self.launch("server", *args)
        self.wait_log("server", "listening on")
        return process

    def member(self, weak=None, port=5050, message="probe-public-marker"):
        args = ["--name", "M1", "--data-dir", str(self.data), "--port", str(port), "--message", message]
        if weak:
            args += ["--weak", weak]
        return subprocess.run([sys.executable, "-m", "treasury.member", *args], cwd=PROJECT,
                              env=self.env, capture_output=True, text=True, timeout=20)

    def test_secure_default_real_processes(self):
        server = self.server()
        member = self.member()
        self.assertEqual(member.returncode, 0, member.stderr)
        server.wait(timeout=10)
        logs = self.wait_log("server", "nonce=0 validation OK tag OK")
        self.assertIn("hs-member signature verification OK", logs)
        self.assertIn("mode=secure", logs)
        self.assertIn("authenticated=False", member.stderr)
        self.assertNotIn("probe-public-marker", logs + member.stderr)

    def test_plaintext_demonstration(self):
        server = self.server("no-encryption")
        member = self.member("no-encryption")
        self.assertEqual(member.returncode, 0, member.stderr)
        server.wait(timeout=10)
        self.wait_log("server", "DEMO plaintext receive")
        self.wait_log("server", "hs-member signature verification OK")

    def test_a1_weak_confidentiality_failure(self):
        server = self.server("unsigned-handshake")
        mallory = self.launch("mallory", "--attack", "A1", "--weak", "unsigned-handshake")
        self.wait_log("mallory", "listening on")
        member = self.member("unsigned-handshake", port=6000, message="A1-public-evidence-marker")
        self.assertEqual(member.returncode, 0, member.stderr)
        server.wait(timeout=10)
        mallory.wait(timeout=10)
        logs = self.wait_log("mallory", "A1 PLAINTEXT member->server")
        self.assertIn("A1-public-evidence-marker", logs)
        self.assertIn("two independent channels", logs)

    def test_a1_secure_rejection(self):
        server = self.server()
        mallory = self.launch("mallory", "--attack", "A1")
        self.wait_log("mallory", "listening on")
        member = self.member(port=6000)
        self.assertNotEqual(member.returncode, 0)
        self.assertIn("hs-server signature verification FAILED", member.stderr)
        server.wait(timeout=10)
        mallory.wait(timeout=10)
        logs = self.wait_log("mallory", "A1 BLOCKED")
        self.assertNotIn("A1 PLAINTEXT", logs)

    def test_real_replay_rejection(self):
        server = self.server()
        mallory = self.launch("mallory", "--attack", "replay-frame")
        self.wait_log("mallory", "listening on")
        self.member(port=6000)
        server.wait(timeout=10)
        mallory.wait(timeout=10)
        self.wait_log("server", "nonce validation FAILED: expected 1, got 0")
        self.wait_log("mallory", "resent exact encrypted frame")

    def test_real_tamper_rejection(self):
        server = self.server()
        mallory = self.launch("mallory", "--attack", "tamper-frame")
        self.wait_log("mallory", "listening on")
        member = self.member(port=6000)
        self.assertNotEqual(member.returncode, 0)
        server.wait(timeout=10)
        mallory.wait(timeout=10)
        self.wait_log("server", "AES-GCM authentication tag FAILED")

    def bad_member_signature(self, final):
        server = self.server()
        _, public = generate_p256_keypair()
        with socket.create_connection(("127.0.0.1", 5050), timeout=5) as sock:
            send_json(sock, {"cert": self.identity.certificate, "X": point_hex(public)})
            self.assertIn("sig", recv_json(sock))
            send_json(sock, final)
            self.assertIsNone(recv_json(sock))
        server.wait(timeout=10)

    def test_invalid_member_handshake_signature(self):
        self.bad_member_signature({"sig": "00"})
        self.wait_log("server", "hs-member signature verification FAILED")

    def test_missing_member_handshake_signature(self):
        self.bad_member_signature({})
        self.wait_log("server", "required signature")

    def test_malformed_member_handshake_signature(self):
        self.bad_member_signature({"sig": [1, 2]})
        self.wait_log("server", "hs-member signature verification FAILED")

    def test_weak_member_cannot_downgrade_secure_server(self):
        server = self.server()
        member = self.member("unsigned-handshake")
        self.assertNotEqual(member.returncode, 0)
        server.wait(timeout=10)
        self.assertNotIn("session established", (self.logs / "server.log").read_text())

    def test_secure_member_rejects_unsigned_server(self):
        server = self.server("unsigned-handshake")
        member = self.member()
        self.assertNotEqual(member.returncode, 0)
        self.assertIn("required signature", member.stderr)
        server.wait(timeout=10)

    def bad_cert(self, cert, expected):
        server = self.server()
        _, public = generate_p256_keypair()
        with socket.create_connection(("127.0.0.1", 5050), timeout=5) as sock:
            send_json(sock, {"cert": cert, "X": point_hex(public)})
            self.assertIsNone(recv_json(sock))
        server.wait(timeout=10)
        self.wait_log("server", expected)

    def test_network_wrong_group_certificate(self):
        self.bad_cert(dict(self.identity.certificate, group="other"), "GROUP mismatch")

    def test_network_wrong_identity_certificate(self):
        self.bad_cert(dict(self.identity.certificate, name="M99"), "not a configured member")

    def test_network_invalid_founder_certificate(self):
        self.bad_cert(dict(self.identity.certificate, sig="00"), "founder signature invalid")

    def test_network_expired_certificate(self):
        self.bad_cert(dict(self.identity.certificate, expires="2020-01-01"), "certificate expired")

    def test_network_malformed_frame(self):
        server = self.server()
        with socket.create_connection(("127.0.0.1", 5050), timeout=5) as sock:
            sock.sendall(bytes(4))
            self.assertEqual(sock.recv(1), b"")
        server.wait(timeout=10)
        self.wait_log("server", "Invalid frame length")

    def test_application_operations_fail_closed_until_integration(self):
        server = self.server()
        with socket.create_connection(("127.0.0.1", 5050), timeout=5) as sock:
            with member_handshake(sock, self.identity, logging.getLogger("test-session")) as session:
                self.assertFalse(session.authenticated)
                session.send({"op": "spend", "seq": 1, "body": {"amount": 50}})
                reply = session.receive()
                self.assertFalse(reply["ok"])
                self.assertIn("not implemented", reply["error"])
                self.assertFalse(session.authenticated)
        server.wait(timeout=10)

    def test_encrypted_non_object_rejected(self):
        server = self.server()
        with socket.create_connection(("127.0.0.1", 5050), timeout=5) as sock:
            with member_handshake(sock, self.identity, logging.getLogger("test-session")) as session:
                send_frame(sock, session.channel.encrypt(b"[]"))
                self.assertIsNone(session.receive())
                self.assertTrue(session.closed)
        server.wait(timeout=10)
        self.wait_log("server", "application message must be a JSON object")

    def test_unexpected_disconnect_during_handshake(self):
        server = self.server()
        with socket.create_connection(("127.0.0.1", 5050), timeout=5) as sock:
            sock.sendall(b"\x00\x00")
        server.wait(timeout=10)
        self.wait_log("server", "Connection closed in the middle of a frame")
