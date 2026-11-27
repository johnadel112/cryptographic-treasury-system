"""Deprecated offline vault CLI. Use owner-isolated network commands."""
import sys

def main():
    print("Use python -m treasury.founder for setup; python -m treasury.member "
          "--command open-vault / contribute for network opening. "
          "The former bulk-share offline demo was removed.", file=sys.stderr)
    raise SystemExit(2)

if __name__ == "__main__":
    main()
