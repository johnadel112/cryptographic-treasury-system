"""Length-prefixed JSON framing: 4-byte big-endian length + JSON bytes."""
import json
import socket
import struct
from typing import Any

from .config import MAX_FRAME_BYTES


class ProtocolError(Exception):
    pass


def recv_exact(sock: socket.socket, count: int) -> bytes:
    chunks = bytearray()
    while len(chunks) < count:
        chunk = sock.recv(count - len(chunks))
        if not chunk:
            if not chunks:
                return b""
            raise ProtocolError("Connection closed in the middle of a frame")
        chunks.extend(chunk)
    return bytes(chunks)


def send_json(sock: socket.socket, value: Any) -> None:
    payload = json.dumps(value, separators=(",", ":")).encode("utf-8")
    if len(payload) > MAX_FRAME_BYTES:
        raise ProtocolError(f"Frame too large: {len(payload)} bytes")
    sock.sendall(struct.pack(">I", len(payload)) + payload)


def recv_json(sock: socket.socket) -> Any:
    header = recv_exact(sock, 4)
    if not header:
        return None
    (length,) = struct.unpack(">I", header)
    if length == 0 or length > MAX_FRAME_BYTES:
        raise ProtocolError(f"Invalid frame length: {length}")
    payload = recv_exact(sock, length)
    if not payload:
        raise ProtocolError("Connection closed before frame payload")
    try:
        return json.loads(payload.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ProtocolError("Frame does not contain valid UTF-8 JSON") from exc
