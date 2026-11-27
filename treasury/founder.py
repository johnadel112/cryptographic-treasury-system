"""Create the founder identity and issue certificates for published program keys."""
import argparse
from pathlib import Path

from .certificates import create_certificate
from .config import (CERTIFICATE_EXPIRY, DATA_DIR, DEFAULT_N, DEFAULT_T,
                     GROUP, member_names, validate_group)
from .encoding import canonical_json
from .identity import initialize_identity, write_new
from .logging_utils import get_logger
from .vault import vault_setup, VAULT_DEFAULT_CONTENT


def issue_certificates(root: Path, n: int, t: int, log) -> None:
    if not 1 <= t <= n:
        raise ValueError("require 1 <= t <= n")
    key = initialize_identity("founder", root)
    names = ("server", *member_names(n))
    # Preflight all public inputs before writing any certificate.
    certs = {name: create_certificate(key, name,
             (root / "public" / (name + ".pub")).read_text("ascii"), CERTIFICATE_EXPIRY)
             for name in names}
    destinations = [root / "public" / (name + ".cert.json") for name in names]
    destinations.append(root / "public" / "setup.json")
    if any(path.exists() for path in destinations):
        raise ValueError("setup already exists; use a fresh --data-dir for new setup")
    for name, cert in certs.items():
        write_new(root / "public" / (name + ".cert.json"), canonical_json(cert.to_dict()))
        log.info("issued certificate name=%s group=%s expires=%s sig=%s", name, GROUP,
                 CERTIFICATE_EXPIRY, cert.sig[:8])
    write_new(root / "public" / "setup.json", canonical_json({"group": GROUP, "n": n, "t": t}))
    log.info("certificate setup complete n=%d t=%d", n, t)
    # Divan vault setup is performed by vault_cli.py --setup (not here).


def main() -> None:
    parser = argparse.ArgumentParser(description="Treasury founder certificate setup")
    parser.add_argument("--t", type=int, default=DEFAULT_T)
    parser.add_argument("--n", type=int, default=DEFAULT_N)
    parser.add_argument("--data-dir", type=Path, default=DATA_DIR)
    parser.add_argument("--vault-file", type=Path, help="file to encrypt; defaults to the course demonstration text")
    args = parser.parse_args()
    validate_group()
    log = get_logger("founder")
    try:
        # Preflight all output paths before changing any setup artifact.
        names = ("server", *member_names(args.n))
        outputs = [args.data_dir / "public" / (name + ".cert.json") for name in names]
        outputs += [args.data_dir / "public" / "setup.json", args.data_dir / "public" / "vault_public.json"]
        outputs += [args.data_dir / name / "share.json" for name in member_names(args.n)]
        if any(path.exists() for path in outputs):
            raise ValueError("existing setup files; use a fresh --data-dir")
        content = args.vault_file.read_bytes() if args.vault_file else VAULT_DEFAULT_CONTENT
        try:
            issue_certificates(args.data_dir, args.n, args.t, log)
            vault_setup(args.data_dir, args.t, args.n, content, log)
        except Exception:
            for path in outputs:
                if path.exists():
                    path.unlink()  # exact preflighted outputs only; preserve all owner keys
            raise
    except (ValueError, OSError) as exc:
        log.error("setup rejected: %s", exc)
        parser.exit(1, "Create server/member --init-identity public keys first.\n")


if __name__ == "__main__":
    main()
