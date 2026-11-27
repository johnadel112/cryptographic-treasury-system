"""Owner-local CLI for registration, both logins, requests, vault and voting."""
import argparse
import json
from pathlib import Path
from .config import DATA_DIR, HOST, SERVER_PORT, APPLICATION_WEAKNESSES
from .identity import initialize_identity, validate_name
from .login import load_login_secret
from .client import TreasuryMemberClient
from .logging_utils import get_logger


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--name", default="M1")
    parser.add_argument("--host", choices=[HOST], default=HOST)
    parser.add_argument("--port", type=int, default=SERVER_PORT)
    parser.add_argument("--data-dir", type=Path, default=DATA_DIR)
    parser.add_argument("--init-identity", action="store_true")
    parser.add_argument("--weak", action="append", default=[], choices=APPLICATION_WEAKNESSES)
    parser.add_argument("--login", choices=["interactive", "noninteractive"], default="interactive")
    parser.add_argument("--command", choices=["probe", "login", "request", "open-vault", "contribute", "spend", "ballot", "status", "ledger", "a3"], default="login")
    parser.add_argument("--message", default="treasury channel demonstration")
    parser.add_argument("--op", default="ping")
    parser.add_argument("--body", default="{}")
    parser.add_argument("--operation")
    parser.add_argument("--amount", type=int, default=50)
    parser.add_argument("--reason", default="club expenses")
    parser.add_argument("--vote-number", type=int)
    parser.add_argument("--vote", type=int, choices=[0, 1])
    parser.add_argument("--cheat", choices=["A5"])
    parser.add_argument("--attempts", type=int, default=128)
    parser.add_argument("--output", type=Path, help="save recovered vault bytes to a file")
    args = parser.parse_args()
    try:
        validate_name(args.name)
        if not args.name.startswith("M"):
            raise ValueError("member name required")
        log = get_logger(args.name)
        if args.init_identity:
            initialize_identity(args.name, args.data_dir)
            load_login_secret(args.name, args.data_dir)
            log.info("owner-local identity and independent login secret ready")
            return
        if "unsigned-handshake" in args.weak and "no-encryption" in args.weak:
            raise ValueError("channel weaknesses cannot be combined")
        weak = next((w for w in args.weak if w in ("unsigned-handshake", "no-encryption")), None)
        client = TreasuryMemberClient(args.name, data_dir=args.data_dir, port=args.port, weak=weak,
                                      unsigned_ballots="unsigned-ballots" in args.weak)
        if args.command == "a3":
            from .attacks import run_attack_a3
            result = run_attack_a3(client, args.attempts)
        else:
            with client:
                if args.command == "probe":
                    result = client.exchange({"type": "channel-probe", "message": args.message})
                    if result.get("type") != "channel-probe-ack" or result.get("message") != args.message:
                        raise ValueError("unexpected probe response")
                    log.info("channel probe acknowledged; authenticated=False")
                    result["ok"] = True
                else:
                    result = client.login(args.login)
                    if result["ok"]:
                        if args.command == "request":
                            result = client.request(args.op, json.loads(args.body))
                        elif args.command == "open-vault":
                            result = client.request("open-vault", {})
                        elif args.command == "spend":
                            result = client.request("spend", {"amount": args.amount, "reason": args.reason})
                        elif args.command == "contribute":
                            result = client.contribute(args.operation, cheat=args.cheat == "A5")
                        elif args.command == "ballot":
                            result = client.ballot(args.vote_number, args.vote)
                        elif args.command in ("status", "ledger"):
                            result = client.request(args.command, {"operation": args.operation} if args.command == "status" else {})
        if args.output and result.get("result", {}).get("state") == "opened":
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_bytes(bytes.fromhex(result["result"]["content_hex"]))
        # CLI returns actual public operation results; never prints individual votes/keys/shares.
        display = json.loads(json.dumps(result))
        if isinstance(display.get("result"), dict):
            display["result"].pop("content_hex", None)
        print(json.dumps(display, sort_keys=True))
        if not result.get("ok"):
            parser.exit(1)
    except Exception as exc:
        get_logger(args.name if args.name.startswith("M") and args.name[1:].isdigit() else "member").error("member rejected: %s", exc)
        parser.exit(1)


if __name__ == "__main__":
    main()
