"""Launch a localhost-only Streamlit process for exactly one member."""
import argparse
import os
from pathlib import Path
import subprocess
import sys
from treasury.config import DATA_DIR, SERVER_PORT
from dashboard.service import OwnerConfig


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--name", default="M1")
    parser.add_argument("--data-dir", type=Path, default=DATA_DIR)
    parser.add_argument("--port", type=int, default=8501, help="local browser port")
    parser.add_argument("--treasury-port", type=int, default=SERVER_PORT)
    args = parser.parse_args()
    try:
        owner = OwnerConfig(args.name, args.data_dir.resolve(), args.treasury_port)
        if not 1 <= args.port <= 65535:
            raise ValueError("invalid browser port")
    except ValueError as exc:
        parser.error(str(exc))
    env = dict(os.environ, TREASURY_DASHBOARD_MEMBER=owner.name,
               TREASURY_DASHBOARD_DATA=str(owner.root), TREASURY_DASHBOARD_PORT=str(owner.port))
    base = Path(__file__).resolve().parents[1]
    print(f"{owner.name} dashboard: http://127.0.0.1:{args.port} (treasury 127.0.0.1:{owner.port})", flush=True)
    try:
        result = subprocess.run([sys.executable, "-m", "streamlit", "run", str(base / "dashboard" / "app.py"),
            "--server.address", "127.0.0.1", "--server.port", str(args.port),
            "--server.headless", "true", "--browser.gatherUsageStats", "false"], cwd=base, env=env)
        raise SystemExit(result.returncode)
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
