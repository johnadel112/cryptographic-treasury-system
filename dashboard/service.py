"""Fresh authenticated owner connections; no key caching or cross-owner switching."""
from dataclasses import dataclass
from datetime import datetime, timezone
import os
from pathlib import Path
from treasury.client import TreasuryMemberClient
from treasury.config import DATA_DIR, SERVER_PORT
from treasury.identity import validate_name
from treasury.framing import ProtocolError


class DashboardError(Exception):
    pass


@dataclass(frozen=True)
class OwnerConfig:
    name: str
    root: Path
    port: int = SERVER_PORT

    def __post_init__(self):
        validate_name(self.name)
        if not self.name.startswith("M"):
            raise ValueError("dashboard requires a member identity")
        if not 1 <= self.port <= 65535:
            raise ValueError("invalid treasury port")

    @classmethod
    def from_environment(cls):
        return cls(os.environ.get("TREASURY_DASHBOARD_MEMBER", "M1"),
                   Path(os.environ.get("TREASURY_DASHBOARD_DATA", str(DATA_DIR))).resolve(),
                   int(os.environ.get("TREASURY_DASHBOARD_PORT", str(SERVER_PORT))))


class MemberDashboard:
    def __init__(self, owner, method="interactive"):
        self.owner = owner
        if method not in ("interactive", "noninteractive"):
            raise ValueError("invalid login method")
        self.method = method

    def execute(self, action, **values):
        if action not in {"overview", "open-vault", "spend", "ballot", "contribute", "status"}:
            raise DashboardError("Unsupported dashboard action")
        try:
            with TreasuryMemberClient(self.owner.name, data_dir=self.owner.root, port=self.owner.port) as client:
                login = client.login(self.method)
                if not login.get("ok"):
                    raise DashboardError(login.get("error", "Login rejected"))
                if action == "ballot":
                    response = client.ballot(values["vote_number"], values["vote"])
                elif action == "contribute":
                    response = client.contribute(values["operation"])
                else:
                    body = {}
                    if action == "spend":
                        body = {"amount": values["amount"], "reason": values["reason"]}
                    elif action == "status":
                        body = {"operation": values["operation"]}
                    response = client.request(action, body)
                if not response.get("ok"):
                    raise DashboardError(response.get("error", "Operation rejected"))
                return response["result"]
        except DashboardError:
            raise
        except FileNotFoundError as exc:
            raise DashboardError("Owner setup is missing. Initialize this member and run founder setup first.") from exc
        except OSError as exc:
            raise DashboardError("Treasury connection unavailable or interrupted. Check the server, then refresh before retrying an action: it may already have been accepted.") from exc
        except (ValueError, KeyError, TypeError, ProtocolError) as exc:
            raise DashboardError("Identity, certificate or protocol validation failed. Check the owner and server logs, then refresh before retrying: an interrupted action may already have been accepted.") from exc


def event(action, accepted, detail):
    # Deliberate allowlist: never include ballot choice, keys, proof or recovered file.
    return {"time": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "action": action, "accepted": bool(accepted), "detail": detail}
