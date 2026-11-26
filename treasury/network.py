"""Reusable baseline TCP helpers. Protocol security is implemented separately."""
import socket
from contextlib import closing
from typing import Callable

from .config import HOST, SERVER_PORT, SOCKET_TIMEOUT_SECONDS
from .framing import recv_json, send_json


def send_and_receive(host: str, port: int, message: dict) -> dict:
    with closing(socket.create_connection((host, port), timeout=SOCKET_TIMEOUT_SECONDS)) as sock:
        send_json(sock, message)
        reply = recv_json(sock)
        if not isinstance(reply, dict):
            raise ConnectionError("Server closed without a JSON response")
        return reply


def serve_forever(handler: Callable[[dict], dict], host: str = HOST,
                  port: int = SERVER_PORT, logger=None) -> None:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind((host, port))
        listener.listen()
        if logger:
            logger.info("listening on %s:%d", host, port)
        while True:
            conn, address = listener.accept()
            with conn:
                conn.settimeout(SOCKET_TIMEOUT_SECONDS)
                try:
                    message = recv_json(conn)
                    if message is None:
                        continue
                    if logger:
                        logger.info("received baseline message from %s: %s", address, message)
                    response = handler(message)
                    send_json(conn, response)
                except Exception as exc:
                    if logger:
                        logger.exception("connection from %s failed: %s", address, exc)
