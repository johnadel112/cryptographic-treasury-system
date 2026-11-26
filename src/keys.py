"""Key generation, certificate issuance, and per-owner secret storage."""

import json
from pathlib import Path
from typing import Dict, Iterable

from .config import DATA_DIR, G, GROUP, P
from .crypto_utils import (
    create_certificate,
    generate_p256_keypair,
    hex_to_pub,
    int_to_priv,
    priv_to_int,
    pub_to_hex,
    random_zq_scalar,
)


def setup_pki(
    data_dir: Path = DATA_DIR,
    members: Iterable[str] = ("M1", "M2", "M3", "M4", "M5"),
    group: str = GROUP,
) -> Path:
    """Generate founder, server, and member ECDSA keys, certs, and login secrets."""
    keys_dir = Path(data_dir) / "keys"
    keys_dir.mkdir(parents=True, exist_ok=True)

    founder_priv, founder_pub = generate_p256_keypair()
    founder_pub_hex = pub_to_hex(founder_pub)

    (keys_dir / "founder.json").write_text(
        json.dumps(
            {
                "name": "founder",
                "group": group,
                "ecdsa_priv": hex(priv_to_int(founder_priv)),
                "ecdsa_pub": founder_pub_hex,
            },
            indent=2,
        ),
        encoding="utf-8",
    )

    server_priv, server_pub = generate_p256_keypair()
    server_cert = create_certificate(founder_priv, "server", group, server_pub)
    (keys_dir / "server.json").write_text(
        json.dumps(
            {
                "name": "server",
                "group": group,
                "ecdsa_priv": hex(priv_to_int(server_priv)),
                "ecdsa_pub": pub_to_hex(server_pub),
                "cert": server_cert,
                "founder_pub": founder_pub_hex,
            },
            indent=2,
        ),
        encoding="utf-8",
    )

    for member in members:
        m_priv, m_pub = generate_p256_keypair()
        m_cert = create_certificate(founder_priv, member, group, m_pub)
        # Separate Schnorr login secret x_M in Z_q, independent of ECDSA key
        x_m = random_zq_scalar()
        big_x_m = pow(G, x_m, P)
        (keys_dir / f"{member}.json").write_text(
            json.dumps(
                {
                    "name": member,
                    "group": group,
                    "ecdsa_priv": hex(priv_to_int(m_priv)),
                    "ecdsa_pub": pub_to_hex(m_pub),
                    "cert": m_cert,
                    "founder_pub": founder_pub_hex,
                    "login_secret_x": hex(x_m),
                    "login_public_X": hex(big_x_m),
                },
                indent=2,
            ),
            encoding="utf-8",
        )

    return keys_dir


def load_owner_keys(name: str, data_dir: Path = DATA_DIR) -> Dict:
    """Load an owner's key file and hydrate key objects."""
    path = Path(data_dir) / "keys" / f"{name}.json"
    raw = json.loads(path.read_text(encoding="utf-8"))
    raw["ecdsa_priv_obj"] = int_to_priv(int(raw["ecdsa_priv"], 16))
    raw["ecdsa_pub_obj"] = hex_to_pub(raw["ecdsa_pub"])
    if "founder_pub" in raw:
        raw["founder_pub_obj"] = hex_to_pub(raw["founder_pub"])
    if "login_secret_x" in raw:
        raw["login_secret_x_int"] = int(raw["login_secret_x"], 16)
    if "login_public_X" in raw:
        raw["login_public_X_int"] = int(raw["login_public_X"], 16)
    return raw
