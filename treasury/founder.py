"""Founder setup entry point. Implement key/certificate/share/vault setup."""
import argparse
from .config import validate_group
from .logging_utils import get_logger


def main():
    parser = argparse.ArgumentParser(description="Treasury founder setup")
    parser.add_argument("--t", type=int, default=3)
    parser.add_argument("--n", type=int, default=5)
    args = parser.parse_args()
    validate_group()
    log = get_logger("founder")
    if not (1 <= args.t <= args.n):
        parser.error("require 1 <= t <= n")
    log.info("setup requested for threshold t=%d, n=%d", args.t, args.n)
    log.info("TODO: create founder key, certificates, member shares, commitments and encrypted vault")


if __name__ == "__main__":
    main()
