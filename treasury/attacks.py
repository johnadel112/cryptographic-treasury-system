"""Preserved Essam A3 math, run inside the owning member process.

This models possession of M3's signing identity but not its independent login
secret. It never calls load_login_secret or reads another owner's files.
"""
import secrets
from .config import P, Q, G


def run_attack_a3(client, max_attempts=128):
    if type(max_attempts) is not int or not 1 <= max_attempts <= 1024:
        raise ValueError("attempt count must be 1..1024")
    for attempt in range(1, max_attempts+1):
        with client:
            public = client.info()["X_M"]
            if public is None:
                raise ValueError("member must register before A3")
            guess, z = secrets.randbits(4), secrets.randbelow(Q-1)+1
            R = pow(G, z, P) * pow(pow(int(public, 16), guess, P), -1, P) % P
            challenge = client.exchange({"type": "login_interactive_start", "R": format(R,"x")})
            result = client.exchange({"type": "login_interactive_finish", "z": format(z,"x")}) if challenge["ok"] else challenge
            client.log.warning("A3 attempt=%d guessed=%d accepted=%s", attempt, guess, result["ok"])
            if result["ok"]:
                return {"ok": True, "attempts": attempt}
    return {"ok": False, "attempts": max_attempts, "error": "challenge guesses rejected"}
