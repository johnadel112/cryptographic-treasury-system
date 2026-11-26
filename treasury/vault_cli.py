"""Milestone 2 – Vault CLI: founder vault setup and 3-of-5 threshold demonstration.

Divan (Student 3) – entry points:
  python -m treasury.vault_cli --setup            (founder creates vault)
  python -m treasury.vault_cli --demo             (interactive 3-of-5 demo)
  python -m treasury.vault_cli --demo --weak no-proof  (Attack A5: cheating member)

This script exercises the full Milestone 2 stack:
  sharing.py  →  vault.py  →  opening.py
without requiring a live TCP server (stand-alone demonstration).
"""
import argparse
import json
import secrets
from pathlib import Path

from .config import DATA_DIR, DEFAULT_N, DEFAULT_T, G, P, Q, member_names, validate_group
from .identity import load_private
from .logging_utils import get_logger
from .opening import make_decryption_share, verify_decryption_share
from .sharing import verify_share
from .vault import (
    load_member_share,
    load_vault_public,
    open_vault,
    sign_open_request,
    vault_setup,
)


VAULT_DEFAULT_CONTENT = b"TREASURY VAULT - Confidential Project Funds Ledger - ICS505"


def cmd_setup(args, log) -> int:
    """Run full founder vault setup."""
    root = args.data_dir
    t, n = args.t, args.n
    content = args.content.encode() if args.content else VAULT_DEFAULT_CONTENT
    log.info("vault-setup: starting t=%d n=%d content_len=%d", t, n, len(content))
    try:
        pub = vault_setup(root, t, n, content, log)
        log.info("vault-setup complete vault_key=%s...", pub["vault_key"][:8])
        log.info("vault-setup: Feldman commitments: %s",
                 " ".join(c[:8] for c in pub["commitments"]))
    except (ValueError, FileExistsError, OSError) as exc:
        log.error("vault-setup failed: %s", exc)
        return 1
    return 0


def cmd_demo(args, log) -> int:
    """3-of-5 threshold demonstration (or A5 cheating-member attack)."""
    root = args.data_dir
    weak = args.weak
    t, n = args.t, args.n

    # ----------------------------------------------------------------
    # Load public vault parameters
    # ----------------------------------------------------------------
    try:
        vault_public = load_vault_public(root)
    except FileNotFoundError as exc:
        log.error("demo failed: %s – run --setup first", exc)
        return 1

    t_pub = int(vault_public["t"])
    n_pub = int(vault_public["n"])
    if t != t_pub or n != n_pub:
        log.warning("demo: CLI t/n (%d/%d) differ from vault t/n (%d/%d); using vault values",
                    t, n, t_pub, n_pub)
        t, n = t_pub, n_pub

    c1 = int(vault_public["elgamal"]["c1"], 16)
    names = member_names(n)

    log.info("=" * 60)
    if weak == "no-proof":
        log.info("ATTACK A5 DEMONSTRATION – WEAK MODE: proof verification DISABLED")
    else:
        log.info("SECURE MODE demonstration: proof verification ENABLED")
    log.info("threshold=%d  members=%d", t, n)
    log.info("=" * 60)

    # ----------------------------------------------------------------
    # Each member loads their share and produces a decryption contribution
    # ----------------------------------------------------------------
    contributions = []
    cheating_member_idx = None   # will be set for A5 demo

    for idx, name in enumerate(names):
        member_index = idx + 1  # 1-based
        try:
            share_data = load_member_share(root, name)
        except FileNotFoundError:
            log.warning("demo: share not found for %s, skipping", name)
            continue

        si  = int(share_data["share"], 16)
        V_i = int(share_data["V_i"],   16)

        # In A5 weak mode: inject a cheating member (member 2) with a corrupted share
        if weak == "no-proof" and member_index == 2:
            log.warning("A5: member %s is CHEATING – submitting corrupted decryption share", name)
            cheating_member_idx = member_index
            # corrupt the share by adding 1 to produce an invalid d_i
            bad_si = (si + 1) % Q
            contrib = make_decryption_share(bad_si, member_index, c1, P, Q, G, V_i)
        else:
            contrib = make_decryption_share(si, member_index, c1, P, Q, G, V_i)

        # Log contribution (public values only)
        log.info("member %s: d_i=%s... proof_a1=%s...", name,
                 contrib["d_i"][:8], contrib["a1"][:8])

        # Verify contribution immediately (shows accept/reject in logs)
        accepted = verify_decryption_share(contrib, c1, P, Q, G, weak=weak)
        if accepted:
            log.info("member %s: contribution ACCEPTED", name)
            contributions.append(contrib)
        else:
            log.warning("member %s: contribution REJECTED (invalid Chaum-Pedersen proof)", name)
            if weak != "no-proof":
                log.info("member %s: another valid member can substitute", name)

        # For A5 demo in weak mode: also keep the cheating contribution so it
        # reaches combine_decryption_shares and we show the vault fails to open
        if weak == "no-proof" and member_index == 2:
            contributions.append(contrib)   # already appended above via accepted=True

    # ----------------------------------------------------------------
    # Attempt vault opening
    # ----------------------------------------------------------------
    log.info("-" * 60)
    valid_count = sum(
        1 for c in contributions
        if verify_decryption_share(c, c1, P, Q, G, weak=None)  # always check in secure mode
    )
    log.info("contributions collected=%d  valid(secure-check)=%d  threshold=%d",
             len(contributions), valid_count, t)

    plaintext = open_vault(vault_public, contributions, weak=weak, log=log)

    if plaintext is not None:
        log.info("=" * 60)
        log.info("VAULT OPENED: %s", plaintext.decode(errors="replace"))
        log.info("=" * 60)
        if weak == "no-proof":
            log.warning("A5 RESULT: vault opened despite cheating member because proofs were disabled")
            log.warning("A5 SECURE FIX: enable proof verification to reject invalid contributions")
    else:
        log.info("=" * 60)
        log.error("VAULT OPENING FAILED: threshold not met with valid contributions")
        log.info("=" * 60)
        if weak == "no-proof":
            log.warning("A5 RESULT: vault opening FAILED because cheating member corrupted the result")
            log.info("A5 NOTE: in secure mode, the cheating member would be REJECTED "
                     "and remaining valid members could still open the vault")

    return 0


def cmd_verify_shares(args, log) -> int:
    """Verify all member shares against public Feldman commitments."""
    root = args.data_dir
    try:
        vault_public = load_vault_public(root)
    except FileNotFoundError as exc:
        log.error("%s", exc)
        return 1

    commitments = [int(c, 16) for c in vault_public["commitments"]]
    n = int(vault_public["n"])
    names = member_names(n)
    all_ok = True

    for idx, name in enumerate(names):
        member_index = idx + 1
        try:
            share_data = load_member_share(root, name)
            si = int(share_data["share"], 16)
            ok = verify_share(si, member_index, commitments, P, Q, G)
            if ok:
                log.info("share verification OK member=%s V_i=%s...", name, share_data["V_i"][:8])
            else:
                log.error("share verification FAILED member=%s", name)
                all_ok = False
        except FileNotFoundError:
            log.warning("share not found member=%s", name)

    return 0 if all_ok else 1


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Treasury Vault CLI (Divan – Milestone 2)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python -m treasury.vault_cli --setup
  python -m treasury.vault_cli --demo
  python -m treasury.vault_cli --demo --weak no-proof    # Attack A5
  python -m treasury.vault_cli --verify-shares
        """,
    )
    parser.add_argument("--setup",         action="store_true", help="run founder vault setup")
    parser.add_argument("--demo",          action="store_true", help="run 3-of-5 threshold demo")
    parser.add_argument("--verify-shares", action="store_true", help="verify member shares vs commitments")
    parser.add_argument("--t",             type=int, default=DEFAULT_T, help="threshold (default %(default)s)")
    parser.add_argument("--n",             type=int, default=DEFAULT_N, help="member count (default %(default)s)")
    parser.add_argument("--data-dir",      type=Path, default=DATA_DIR)
    parser.add_argument("--content",       type=str, default=None, help="vault plaintext content")
    parser.add_argument("--weak",          choices=["no-proof", "no-share-check"], default=None,
                        help="educational weakness flag (A5: no-proof)")
    args = parser.parse_args()
    validate_group()

    log = get_logger("vault")

    if args.setup:
        raise SystemExit(cmd_setup(args, log))
    elif args.demo:
        raise SystemExit(cmd_demo(args, log))
    elif args.verify_shares:
        raise SystemExit(cmd_verify_shares(args, log))
    else:
        parser.print_help()
        raise SystemExit(1)


if __name__ == "__main__":
    main()
