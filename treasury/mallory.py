"""Assignment-only loopback A1 and encrypted-frame replay/tamper evidence harness.

Reads no identity files. Certificates are forwarded from the real peers.
"""
import argparse
import select
import socket

from cryptography.hazmat.primitives.asymmetric import ec

from .channel import (SecureChannel, derive_directional_keys, generate_p256_keypair,
                      load_point, point_hex)
from .config import G, P, GROUP, HOST, MALLORY_PORT, SERVER_PORT, SOCKET_TIMEOUT_SECONDS
from .encoding import canonical_json
from .framing import ProtocolError, decode_json, recv_frame, recv_json, send_frame, send_json
from .logging_utils import get_logger


def a1_handshake(member, server, log):
    hello = recv_json(member)
    if not isinstance(hello, dict) or set(hello) != {"cert", "X"}:
        raise ProtocolError("expected member hello")
    name = hello["cert"]["name"]
    original_X = hello["X"]
    member_point = load_point(original_X)
    upstream_secret, upstream_public = generate_p256_keypair()
    replaced_X = point_hex(upstream_public)
    send_json(server, {"cert": hello["cert"], "X": replaced_X})
    log.info("A1 replaced member X=%s with X=%s", original_X[:8], replaced_X[:8])
    reply = recv_json(server)
    if not isinstance(reply, dict) or "Y" not in reply:
        raise ProtocolError("server did not return handshake")
    original_Y = reply["Y"]
    server_point = load_point(original_Y)
    downstream_secret, downstream_public = generate_p256_keypair()
    replaced_Y = point_hex(downstream_public)
    forged = dict(reply, Y=replaced_Y)
    # Preserve any real signature: it cannot authenticate these substituted points.
    send_json(member, forged)
    log.info("A1 replaced server Y=%s with Y=%s; cannot forge hs-server signature", original_Y[:8], replaced_Y[:8])
    finish = recv_json(member)
    if finish is None:
        log.info("A1 BLOCKED: member closed during server handshake authentication")
        return None
    send_json(server, finish)
    down_m2s, down_s2m = derive_directional_keys(
        downstream_secret.exchange(ec.ECDH(), member_point),
        name, original_X, replaced_Y)
    up_m2s, up_s2m = derive_directional_keys(
        upstream_secret.exchange(ec.ECDH(), server_point),
        name, replaced_X, original_Y)
    log.warning("A1 two independent channels established; confidentiality lost group=%s", GROUP)
    return SecureChannel(down_s2m, down_m2s), SecureChannel(up_m2s, up_s2m)


def proxy_connection(member, server, attack, log, *, tamper_request=False):
    channels = None
    try:
        if attack in ("A1", "A7"):
            channels = a1_handshake(member, server, log)
            if channels is None:
                return
        else:
            # Transparent authenticated handshake; Mallory learns no session key.
            for source, target in ((member, server), (server, member), (member, server)):
                frame = recv_frame(source)
                if frame is None:
                    raise ProtocolError("peer closed during handshake relay")
                send_frame(target, frame)
        injected = False
        while True:
            ready, _, _ = select.select([member, server], [], [], SOCKET_TIMEOUT_SECONDS)
            if not ready:
                raise ProtocolError("proxy idle timeout")
            for source in ready:
                target = server if source is member else member
                frame = recv_frame(source)
                if frame is None:
                    log.info("peer closed; proxy connection ends")
                    return
                if channels:
                    downstream, upstream = channels
                    reader, writer = (downstream, upstream) if source is member else (upstream, downstream)
                    clear = reader.decrypt(frame)
                    message = decode_json(clear)
                    log.warning("A1 PLAINTEXT %s: %s", "member->server" if source is member else "server->member", canonical_json(message).decode())
                    if source is member and tamper_request and not injected and message.get("op") == "spend":
                        message["body"]["amount"] += 1
                        clear = canonical_json(message)
                        injected = True
                        log.warning("A1 changed signed request amount; original signature preserved")
                    if source is member and attack == "A7" and not injected and message.get("type") == "ballot":
                        message["c2"] = format(int(message["c2"], 16) * G % P, "x")
                        clear = canonical_json(message)
                        injected = True
                        log.warning("A7 changed c2 := c2*g; original signature preserved if present")
                    send_frame(target, writer.encrypt(clear))
                elif source is member and not injected:
                    injected = True
                    if attack == "replay-frame":
                        send_frame(target, frame)
                        send_frame(target, frame)
                        log.warning("resent exact encrypted frame nonce=%d", int.from_bytes(frame[:12], "big"))
                    else:
                        if len(frame) < 28:
                            raise ProtocolError("encrypted frame too short for demo")
                        changed = frame[:-1] + bytes([frame[-1] ^ 1])
                        send_frame(target, changed)
                        log.warning("changed encrypted frame authentication tag nonce=%d", int.from_bytes(frame[:12], "big"))
                else:
                    send_frame(target, frame)
    finally:
        if channels:
            for channel in channels:
                channel.close()
        member.close()
        server.close()


def main() -> None:
    parser = argparse.ArgumentParser(description="Local treasury attack demonstration")
    parser.add_argument("--attack", required=True, choices=["A1", "A7", "replay-frame", "tamper-frame"])
    parser.add_argument("--weak", choices=["unsigned-handshake"],
                        help="labels the weak A1 run; peers must also enable this flag")
    parser.add_argument("--tamper-request", action="store_true", help="A1: change one signed spending request")
    args = parser.parse_args()
    if args.weak and args.attack not in ("A1", "A7"):
        parser.error("--weak unsigned-handshake is for A1 only")
    log = get_logger("mallory")
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
            listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            listener.bind((HOST, MALLORY_PORT))
            listener.listen(1)
            log.info("listening on %s:%d attack=%s mode=%s", HOST, MALLORY_PORT, args.attack, args.weak or "secure comparison")
            member, address = listener.accept()
            member.settimeout(SOCKET_TIMEOUT_SECONDS)
            try:
                with socket.create_connection((HOST, SERVER_PORT), timeout=SOCKET_TIMEOUT_SECONDS) as server:
                    log.info("two local TCP connections: member=%s server=%s:%d", address, HOST, SERVER_PORT)
                    proxy_connection(member, server, args.attack, log, tamper_request=args.tamper_request)
            finally:
                member.close()
    except (OSError, ValueError, KeyError, TypeError, ProtocolError) as exc:
        log.error("demo connection stopped: %s", exc)
        parser.exit(1)


if __name__ == "__main__":
    main()
