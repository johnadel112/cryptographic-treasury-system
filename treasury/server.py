"""Runnable cleartext transport smoke-test server (not the secure M1 server)."""
import argparse

from .config import HOST, SERVER_PORT, validate_group
from .logging_utils import get_logger
from .network import serve_forever


def handle(message: dict) -> dict:
    if message.get("type") != "hello":
        return {"ok": False, "error": "unsupported baseline message"}
    name = message.get("name", "unknown")
    return {"ok": True, "type": "hello-ack", "group": message.get("group"),
            "name": name, "message": "TCP/JSON baseline works; protocol security is not implemented"}


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--name", default="server")
    parser.add_argument("--host", default=HOST)
    parser.add_argument("--port", type=int, default=SERVER_PORT)
    parser.add_argument("--weak", choices=sorted(__import__("treasury.config", fromlist=["WEAKNESS_NAMES"]).WEAKNESS_NAMES))
    args = parser.parse_args()
    validate_group()
    logger = get_logger(args.name)
    if args.weak:
        logger.warning("weakness requested: %s (implement the matching deliberate weakness)", args.weak)
    serve_forever(handle, args.host, args.port, logger)


if __name__ == "__main__":
    main()
