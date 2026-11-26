"""Local secure TCP server; application authentication awaits Essam."""
import argparse
import json
from pathlib import Path
import socket
import threading

from .channel import server_handshake
from .config import (CHANNEL_WEAKNESSES, DATA_DIR, GROUP, HOST, SERVER_PORT,
                     SOCKET_TIMEOUT_SECONDS, member_names, validate_group)
from .framing import ProtocolError
from .identity import initialize_identity, load_identity
from .logging_utils import get_logger


def handle(message: dict) -> dict:
    """Non-sensitive transport probe only. No treasury operation is authorized."""
    if message.get("type") == "channel-probe":
        return {"type": "channel-probe-ack", "group": GROUP,
                "message": message.get("message"), "authenticated": False}
    return {"ok": False, "error": "authentication/application integration not implemented"}


def serve_connection(conn, identity, names, log, weak=None, handler=None):
    """Essam may inject handler(session, message); enforce login in that handler."""
    conn.settimeout(SOCKET_TIMEOUT_SECONDS)
    try:
        with server_handshake(conn, identity, names, log, weak=weak) as session:
            while (message := session.receive()) is not None:
                response = handler(session, message) if handler else handle(message)
                session.send(response)
    except (OSError, ValueError, TypeError, ProtocolError) as exc:
        log.error("connection rejected: %s", exc)
    finally:
        conn.close()


def main() -> None:
    parser = argparse.ArgumentParser(description="Treasury secure TCP server")
    parser.add_argument("--name", choices=["server"], default="server")
    parser.add_argument("--host", choices=[HOST], default=HOST)
    parser.add_argument("--port", type=int, default=SERVER_PORT)
    parser.add_argument("--data-dir", type=Path, default=DATA_DIR)
    parser.add_argument("--weak", choices=CHANNEL_WEAKNESSES)
    parser.add_argument("--init-identity", action="store_true")
    parser.add_argument("--once", action="store_true", help="serve one connection then exit (tests/demos)")
    args = parser.parse_args()
    validate_group()
    log = get_logger("server")
    try:
        if args.init_identity:
            initialize_identity("server", args.data_dir)
            log.info("owner-local server key ready; public key published")
            return
        identity = load_identity("server", args.data_dir)
        setup = json.loads((args.data_dir / "public" / "setup.json").read_text("utf-8"))
        if setup["group"] != GROUP or type(setup["t"]) is not int or not 1 <= setup["t"] <= setup["n"]:
            raise ValueError("invalid public setup parameters")
        names = member_names(setup["n"])
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
            listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            listener.bind((args.host, args.port))
            listener.listen()
            log.info("listening on %s:%d mode=%s n=%d t=%d", args.host, args.port,
                     args.weak or "secure", setup["n"], setup["t"])
            while True:
                conn, address = listener.accept()
                log.info("connection accepted from %s:%d", *address)
                if args.once:
                    serve_connection(conn, identity, names, log, args.weak)
                    break
                threading.Thread(target=serve_connection,
                                 args=(conn, identity, names, log, args.weak), daemon=True).start()
    except KeyboardInterrupt:
        log.info("server stopped")
    except (OSError, ValueError, KeyError, TypeError, ProtocolError) as exc:
        log.error("server startup rejected: %s", exc)
        parser.exit(1)


if __name__ == "__main__":
    main()
