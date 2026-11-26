"""Attack harness entry point. Mandatory: implement A1 and A5 demonstrations."""
import argparse
from .config import validate_group, WEAKNESS_NAMES
from .logging_utils import get_logger


def main():
    parser = argparse.ArgumentParser(description="Treasury attack harness")
    parser.add_argument("--attack", required=True,
                        choices=["A1", "A2", "A3", "A4", "A5", "A6", "A7"])
    parser.add_argument("--weak", required=True, choices=sorted(WEAKNESS_NAMES))
    args = parser.parse_args()
    validate_group()
    log = get_logger("mallory")
    log.info("selected %s using weakness %s", args.attack, args.weak)
    log.info("TODO: implement the attack described in the corresponding milestone document")


if __name__ == "__main__":
    main()
