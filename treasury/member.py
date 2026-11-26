"""Runnable cleartext transport smoke-test member (not Milestone 1 login)."""
import argparse

from .config import GROUP, HOST, SERVER_PORT, validate_group
from .logging_utils import get_logger
from .network import send_and_receive


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--name", default="M1")
    parser.add_argument("--host", default=HOST)
    parser.add_argument("--port", type=int, default=SERVER_PORT)
    parser.add_argument("--weak", default=None)
    args = parser.parse_args()
    validate_group()
    logger = get_logger(args.name)
    if args.weak:
        logger.warning("weakness requested: %s (implement the matching deliberate weakness)", args.weak)
    message = {"type": "hello", "group": GROUP, "name": args.name}
    logger.info("sending baseline hello to %s:%d", args.host, args.port)
    response = send_and_receive(args.host, args.port, message)
    logger.info("server response: %s", response)


if __name__ == "__main__":
    main()
