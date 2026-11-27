import logging
from pathlib import Path
import socketserver
import threading
import pytest
from treasury.identity import initialize_identity, load_identity
from treasury.founder import issue_certificates
from treasury.vault import vault_setup
from treasury.application import TreasuryApplication
from treasury.server import serve_connection
from treasury.client import TreasuryMemberClient


def setup_test_root(root, n=5, t=3):
    log = logging.getLogger("test-setup")
    for name in ["server", *(f"M{i}" for i in range(1, n+1))]:
        initialize_identity(name, root)
    issue_certificates(root, n, t, log)
    vault_setup(root, t, n, b"integrated treasury treasure", log)
    return root


@pytest.fixture
def setup_root(tmp_path):
    return setup_test_root(tmp_path)


@pytest.fixture
def service_factory():
    services = []
    def create(root, weaknesses=()):
        log = logging.getLogger("test-service")
        identity = load_identity("server", root)
        app = TreasuryApplication(root, identity, log, weaknesses=weaknesses)
        weak = next((w for w in weaknesses if w in ("unsigned-handshake", "no-encryption")), None)
        class Handler(socketserver.BaseRequestHandler):
            def handle(self):
                serve_connection(self.request, identity, app.names, log, weak, app.handle)
        class Server(socketserver.ThreadingTCPServer):
            allow_reuse_address = True
            daemon_threads = True
        server = Server(("127.0.0.1", 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        services.append((server, thread))
        return app, server.server_address[1]
    yield create
    for server, thread in services:
        server.shutdown(); server.server_close(); thread.join(timeout=5)


@pytest.fixture
def env(setup_root, service_factory):
    app, port = service_factory(setup_root)
    return setup_root, port, app


def client(root, port, name="M1", method="interactive", **kwargs):
    connection = TreasuryMemberClient(name, data_dir=root, port=port, **kwargs)
    connection.connect()
    assert connection.login(method)["ok"]
    return connection
