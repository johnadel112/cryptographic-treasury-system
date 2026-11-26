"""Member identity setup and secure-channel probe; login is not implemented here."""
import argparse
from pathlib import Path
import socket

from .channel import member_handshake
from .config import CHANNEL_WEAKNESSES, DATA_DIR, HOST, SERVER_PORT, SOCKET_TIMEOUT_SECONDS, validate_group
from .framing import ProtocolError
from .identity import initialize_identity, load_identity, validate_name
from .logging_utils import get_logger


def main() -> None:
    parser = argparse.ArgumentParser(description="Treasury member secure-channel probe")
    parser.add_argument("--name", default="M1")
    parser.add_argument("--host", choices=[HOST], default=HOST)
    parser.add_argument("--port", type=int, default=SERVER_PORT)
    parser.add_argument("--data-dir", type=Path, default=DATA_DIR)
    parser.add_argument("--init-identity", action="store_true")
    parser.add_argument("--weak", choices=CHANNEL_WEAKNESSES)
    parser.add_argument("--message", default="treasury channel demonstration")
    args = parser.parse_args()
    validate_group()
    try:
        validate_name(args.name)
        if not args.name.startswith("M"):
            raise ValueError("member name must be M<positive integer>")
    except ValueError as exc:
        parser.error(str(exc))
    log = get_logger(args.name)
    try:
        if args.init_identity:
            initialize_identity(args.name, args.data_dir)
            log.info("owner-local member key ready; public key published")
            return
        identity = load_identity(args.name, args.data_dir)
        with socket.create_connection((args.host, args.port), timeout=SOCKET_TIMEOUT_SECONDS) as sock:
            log.info("connected to %s:%d", args.host, args.port)
            with member_handshake(sock, identity, log, weak=args.weak) as session:
                session.send({"type": "channel-probe", "message": args.message})
                reply = session.receive()
                if not reply or reply.get("type") != "channel-probe-ack" or reply.get("message") != args.message:
                    raise ProtocolError("missing or unexpected probe acknowledgement")
                log.info("channel probe acknowledged; authenticated=False; login and signed requests pending Essam")
    except (OSError, ValueError, TypeError, ProtocolError) as exc:
        log.error("member connection rejected: %s", exc)
        parser.exit(1)


if __name__ == "__main__":
    main()
